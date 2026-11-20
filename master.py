from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, send_from_directory, send_file, flash)
import os, sys, json, time, zipfile, shutil, hashlib, subprocess, signal
import threading, atexit, re, tempfile
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename

try:
    import bcrypt
except ImportError:
    bcrypt = None

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "master_hosting_gold_2024_change_me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
    MAX_CONTENT_LENGTH=200 * 1024 * 1024,  # 200 MB
)

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "servers")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

USERS_FILE = os.path.join(UPLOAD_FOLDER, "_users.json")
PORT_FILE  = os.path.join(UPLOAD_FOLDER, "_ports.json")

processes = {}          # (username, server) -> Popen
proc_lock = threading.Lock()

if HAS_LIMITER:
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"])

# ---------------- Extensions / supported files ----------------
EDITABLE_EXTS = {
    '.py', '.html', '.htm', '.css', '.js', '.mjs', '.ts', '.jsx', '.tsx',
    '.json', '.txt', '.md', '.yml', '.yaml', '.env', '.sh', '.bash',
    '.php', '.xml', '.csv', '.ini', '.conf', '.cfg', '.sql', '.log',
    '.toml', '.dockerfile', '.gitignore', '.htaccess', '.rb', '.go',
    '.rs', '.java', '.c', '.cpp', '.h', '.lua', '.pl', '.r', '.swift',
}
ALLOWED_UPLOAD_EXTS = EDITABLE_EXTS | {
    '.zip', '.tar', '.gz', '.tgz', '.whl', '.png', '.jpg', '.jpeg',
    '.gif', '.svg', '.ico', '.pdf', '.woff', '.woff2', '.ttf', '.eot',
    '.mp3', '.mp4', '.wav', '.webp', '.wasm',
}
MAX_UPLOAD_MB = 100

# ---------------- Helpers: users ----------------
def _hash(pw: str) -> str:
    if bcrypt:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    return "sha256$" + hashlib.sha256(pw.encode()).hexdigest()

def _verify(pw: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("sha256$"):
        return stored == "sha256$" + hashlib.sha256(pw.encode()).hexdigest()
    if bcrypt:
        try:
            return bcrypt.checkpw(pw.encode(), stored.encode())
        except Exception:
            return False
    return False

def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        admin_pw = os.environ.get("ADMIN_PASSWORD", "4841")
        users = {"master": {
            "password": _hash(admin_pw),
            "is_admin": True,
            "created_at": str(datetime.now()),
            "server_limit": -1,
            "active": True,
        }}
        save_users(users)
        return users
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users: dict):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def _user_dir(username: str) -> str:
    d = os.path.join(UPLOAD_FOLDER, secure_filename(username) or username)
    os.makedirs(d, exist_ok=True)
    return d

# ---------------- Helpers: paths & files ----------------
def safe_join(base: str, *paths) -> str:
    final = os.path.abspath(os.path.join(base, *paths))
    base_abs = os.path.abspath(base)
    if not (final == base_abs or final.startswith(base_abs + os.sep)):
        raise ValueError("Path outside base")
    return final

def safe_zip_extract(zip_path: str, extract_to: str):
    """Zip-slip safe extraction."""
    os.makedirs(extract_to, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        for member in z.infolist():
            name = member.filename.replace('\\', '/')
            if name.startswith('/') or '..' in name.split('/'):
                continue
            target = os.path.abspath(os.path.join(extract_to, name))
            if not target.startswith(os.path.abspath(extract_to) + os.sep):
                continue
            if member.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(member) as src, open(target, 'wb') as dst:
                    shutil.copyfileobj(src, dst)

def force_delete_directory(path, max_retries=5, delay=0.5):
    for _ in range(max_retries):
        try:
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
                return True
        except Exception:
            time.sleep(delay)
    return False

def install_requirements(path: str):
    req = os.path.join(path, "requirements.txt")
    if not os.path.exists(req):
        return
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "-r", req],
            capture_output=True, text=True, timeout=600,
        )
    except Exception as e:
        print(f"[install_requirements] {e}")

def find_main_file(path: str):
    for f in ["main.py", "app.py", "bot.py", "server.py", "index.py",
              "start.py", "run.py", "wsgi.py", "manage.py"]:
        if os.path.exists(os.path.join(path, f)):
            return f
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith('.py') and not file.startswith('_'):
                fp = os.path.join(root, file)
                try:
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                        if '__main__' in fh.read():
                            return os.path.relpath(fp, path)
                except Exception:
                    continue
    return None

# ---------------- Config / ports ----------------
def _load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return default

def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def save_server_config(username, server_name, cfg):
    p = os.path.join(_user_dir(username), server_name, "config.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    _save_json(p, cfg)

def load_server_config(username, server_name):
    p = os.path.join(_user_dir(username), server_name, "config.json")
    return _load_json(p, {
        "status": "stopped", "type": "web", "port": 8080,
        "created_at": str(datetime.now())
    })

def alloc_port() -> int:
    used = _load_json(PORT_FILE, {})
    used_set = set(used.values())
    for p in range(8100, 65000):
        if p not in used_set:
            return p
    return 8100

def assign_port(username, server_name, port) -> int:
    used = _load_json(PORT_FILE, {})
    used[f"{username}/{server_name}"] = port
    _save_json(PORT_FILE, used)
    return port

def release_port(username, server_name):
    used = _load_json(PORT_FILE, {})
    used.pop(f"{username}/{server_name}", None)
    _save_json(PORT_FILE, used)

# ---------------- Auth decorators ----------------
def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*a, **kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if 'username' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash("Admin access required", "error")
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return w

# ---------------- Process management ----------------
def _server_dir(username, server_name):
    return os.path.join(_user_dir(username), server_name)

def _working_dir(server_dir):
    ext = os.path.join(server_dir, "extracted")
    return ext if os.path.isdir(ext) and os.listdir(ext) else server_dir

def start_server(username, server_name) -> tuple[bool, str]:
    key = (username, server_name)
    with proc_lock:
        if key in processes and processes[key].poll() is None:
            return False, "Already running"
    sdir = _server_dir(username, server_name)
    if not os.path.isdir(sdir):
        return False, "Server not found"

    cfg = load_server_config(username, server_name)
    log_path = os.path.join(sdir, "logs.txt")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    zip_path = os.path.join(sdir, "server.zip")
    extract_dir = os.path.join(sdir, "extracted")

    with open(log_path, 'a', encoding='utf-8') as log:
        log.write(f"\n{'='*70}\n[{datetime.now()}] START {server_name}\n")
        log.write(f"{'='*70}\n")

    if os.path.exists(zip_path) and not (os.path.isdir(extract_dir) and os.listdir(extract_dir)):
        try:
            if os.path.exists(extract_dir):
                force_delete_directory(extract_dir)
            safe_zip_extract(zip_path, extract_dir)
            install_requirements(extract_dir)
            with open(log_path, 'a', encoding='utf-8') as log:
                log.write(f"[system] ZIP extracted successfully\n")
        except Exception as e:
            with open(log_path, 'a', encoding='utf-8') as log:
                log.write(f"[system ERROR] Extract failed: {e}\n")
            return False, f"Extract failed: {e}"

    working = _working_dir(sdir)
    if not os.path.exists(os.path.join(working, "requirements.txt")):
        pass
    else:
        install_requirements(working)

    main_file = find_main_file(working)
    if not main_file:
        demo = os.path.join(working, "test_server.py")
        if not os.path.exists(demo):
            port = cfg.get("port", 8080)
            with open(demo, 'w', encoding='utf-8') as f:
                f.write(
                    "from flask import Flask\nimport time\n"
                    "app = Flask(__name__)\n"
                    "@app.route('/')\n"
                    "def home():\n"
                    f"    return '<h1>MASTER HOSTING</h1><p>' + time.ctime() + '</p>'\n"
                    f"if __name__ == '__main__':\n"
                    f"    app.run(host='0.0.0.0', port={port})\n"
                )
        main_file = "test_server.py"

    python_cmd = sys.executable or ("python3" if shutil.which("python3") else "python")
    cmd = [python_cmd, "-u", main_file]
    env = os.environ.copy()
    env["PORT"] = str(cfg.get("port", 8080))
    env["SERVER_NAME"] = server_name
    env["PYTHONUNBUFFERED"] = "1"

    log_file = open(log_path, 'a', encoding='utf-8')
    try:
        p = subprocess.Popen(
            cmd, cwd=working, stdout=log_file, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, env=env,
            start_new_session=(os.name != 'nt'),
        )
    except Exception as e:
        log_file.write(f"[system ERROR] Spawn failed: {e}\n")
        log_file.close()
        return False, str(e)

    with proc_lock:
        processes[key] = p
    cfg['status'] = 'running'
    cfg['pid'] = p.pid
    cfg['started_at'] = str(datetime.now())
    save_server_config(username, server_name, cfg)

    def monitor(proc, k, u, s):
        try:
            proc.wait()
        except Exception:
            pass
        with proc_lock:
            processes.pop(k, None)
        try:
            log_file.close()
        except Exception:
            pass
        c = load_server_config(u, s)
        c['status'] = 'stopped'
        c.pop('pid', None)
        save_server_config(u, s, c)
        try:
            with open(os.path.join(_server_dir(u, s), "logs.txt"), 'a') as lg:
                lg.write(f"\n[{datetime.now()}] [system] Process exited (code={proc.returncode})\n")
        except Exception:
            pass

    threading.Thread(target=monitor, args=(p, key, username, server_name),
                     daemon=True).start()
    return True, f"'{server_name}' started (pid={p.pid})"

def stop_server(username, server_name) -> tuple[bool, str]:
    key = (username, server_name)
    with proc_lock:
        p = processes.get(key)
    if not p:
        cfg = load_server_config(username, server_name)
        cfg['status'] = 'stopped'
        cfg.pop('pid', None)
        save_server_config(username, server_name, cfg)
        return True, "Already stopped"
    try:
        if os.name != 'nt':
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                p.terminate()
        else:
            p.terminate()
        for _ in range(20):
            if p.poll() is not None:
                break
            time.sleep(0.1)
        if p.poll() is None:
            try:
                if os.name != 'nt':
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                else:
                    p.kill()
            except Exception:
                pass
        with proc_lock:
            processes.pop(key, None)
        cfg = load_server_config(username, server_name)
        cfg['status'] = 'stopped'
        cfg.pop('pid', None)
        save_server_config(username, server_name, cfg)
        return True, "Stopped"
    except Exception as e:
        return False, str(e)

@atexit.register
def _cleanup():
    with proc_lock:
        items = list(processes.items())
    for _, p in items:
        try:
            if p.poll() is None:
                p.terminate()
                time.sleep(0.3)
                if p.poll() is None:
                    p.kill()
        except Exception:
            pass

# ---------------- Routes: auth ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        users = load_users()
        entry = users.get(u)
        if not entry:
            return render_template("login.html", error="Username ya password galat")
        if not entry.get("active", True):
            return render_template("login.html", error="Account blocked. Admin se baat karo.")
        if not _verify(pw, entry.get("password", "")):
            return render_template("login.html", error="Username ya password galat")
        session['username'] = u
        session['is_admin'] = entry.get("is_admin", False)
        return redirect(url_for('admin_panel' if session['is_admin'] else 'dashboard'))
    return render_template("login.html")

@app.route("/logout")
def logout():
    uname = session.get('username')
    if uname:
        with proc_lock:
            keys = [(u, s) for (u, s) in processes if u == uname]
        for (u, s) in keys:
            stop_server(u, s)
    session.clear()
    return redirect(url_for('login'))

# ---------------- Routes: dashboard ----------------
@app.route("/", methods=["GET", "POST"])
@login_required
def dashboard():
    username = session['username']
    user_dir = _user_dir(username)
    users = load_users()
    limit = users.get(username, {}).get("server_limit", 5)

    if request.method == "POST":
        action = request.form.get("action")
        if action == "create_server":
            name = request.form.get("server_name", "").strip()
            stype = request.form.get("server_type", "web")
            port_in = request.form.get("port", "").strip()
            if not name:
                flash("Server name required", "error")
                return redirect(url_for('dashboard'))
            sname = secure_filename(name).replace("-", "_") or f"server_{int(time.time())}"
            if not sname:
                sname = f"server_{int(time.time())}"

            existing = [f for f in os.listdir(user_dir)
                        if os.path.isdir(os.path.join(user_dir, f))]
            if limit != -1 and len(existing) >= limit:
                flash(f"Server limit reached ({limit}). Admin se limit badhwao.", "error")
                return redirect(url_for('dashboard'))

            sdir = os.path.join(user_dir, sname)
            if os.path.exists(sdir):
                flash("Server with this name already exists", "error")
                return redirect(url_for('dashboard'))

            os.makedirs(sdir, exist_ok=True)
            port = int(port_in) if port_in.isdigit() and 1024 <= int(port_in) <= 65535 else alloc_port()
            assign_port(username, sname, port)
            cfg = {
                "name": name, "display_name": name, "safe_name": sname,
                "type": stype, "port": port, "status": "stopped",
                "created_at": str(datetime.now()),
            }
            save_server_config(username, sname, cfg)

            f = request.files.get("server_files")
            if f and f.filename:
                fname = secure_filename(f.filename)
                ext = os.path.splitext(fname)[1].lower()
                if ext not in ALLOWED_UPLOAD_EXTS:
                    flash(f"File type {ext} not allowed", "error")
                else:
                    f.save(os.path.join(sdir, "server.zip" if ext == ".zip" else fname))
                    flash("Uploaded", "success")
            flash(f"Server '{sname}' created", "success")
            return redirect(url_for('dashboard'))

    servers = []
    for folder in sorted(os.listdir(user_dir)):
        sdir = os.path.join(user_dir, folder)
        if not os.path.isdir(sdir):
            continue
        cfg = load_server_config(username, folder)
        with proc_lock:
            running = (username, folder) in processes and processes[(username, folder)].poll() is None
        servers.append({
            "name": folder,
            "display_name": cfg.get("display_name", folder),
            "running": running,
            "config": cfg,
            "created_at": cfg.get("created_at", ""),
        })
    servers.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return render_template("dashboard.html", servers=servers,
                           user_limit=limit,
                           user_count=len(servers),
                           is_admin=session.get('is_admin', False))

# ---------------- Routes: server control ----------------
@app.route("/api/server/<action>/<name>", methods=["POST"])
@login_required
def server_action(action, name):
    uname = session['username']
    if action == "start":
        ok, msg = start_server(uname, name)
        return (jsonify({"success": True, "message": msg}) if ok
                else (jsonify({"error": msg}), 400))
    if action == "stop":
        ok, msg = stop_server(uname, name)
        return (jsonify({"success": True, "message": msg}) if ok
                else (jsonify({"error": msg}), 400))
    if action == "restart":
        stop_server(uname, name)
        time.sleep(1)
        ok, msg = start_server(uname, name)
        return (jsonify({"success": True, "message": msg}) if ok
                else (jsonify({"error": msg}), 400))
    if action == "delete":
        stop_server(uname, name)
        time.sleep(0.5)
        sdir = _server_dir(uname, name)
        if os.path.exists(sdir) and force_delete_directory(sdir):
            release_port(uname, name)
            return jsonify({"success": True, "message": "Deleted"})
        return jsonify({"error": "Delete failed"}), 400
    return jsonify({"error": "Invalid action"}), 400

# ---------------- Routes: LIVE LOGS (fixed) ----------------
@app.route("/api/logs/<name>")
@login_required
def get_logs(name):
    uname = session['username']
    log_path = os.path.join(_server_dir(uname, name), "logs.txt")
    if not os.path.exists(log_path):
        return jsonify({"lines": [], "size": 0, "running": False})
    try:
        with open(log_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            read_n = min(size, 200_000)
            f.seek(size - read_n)
            raw = f.read()
        text = raw.decode('utf-8', errors='replace')
        lines = text.splitlines()
        with proc_lock:
            running = (uname, name) in processes and processes[(uname, name)].poll() is None
        return jsonify({
            "lines": lines[-2000:],
            "size": size,
            "running": running,
            "timestamp": str(datetime.now()),
        })
    except Exception as e:
        return jsonify({"lines": [f"[error reading logs] {e}"], "size": 0, "running": False})

@app.route("/api/logs/<name>/download")
@login_required
def download_logs(name):
    uname = session['username']
    log_path = os.path.join(_server_dir(uname, name), "logs.txt")
    if not os.path.exists(log_path):
        return "No logs", 404
    return send_file(log_path, as_attachment=True,
                     download_name=f"{name}_logs_{int(time.time())}.txt")

@app.route("/api/logs/<name>/clear", methods=["POST"])
@login_required
def clear_logs(name):
    uname = session['username']
    log_path = os.path.join(_server_dir(uname, name), "logs.txt")
    if os.path.exists(log_path):
        open(log_path, 'w').close()
    return jsonify({"success": True})

# ---------------- Routes: file manager ----------------
@app.route("/files/<server_name>")
@login_required
def file_manager(server_name):
    uname = session['username']
    sdir = _server_dir(uname, server_name)
    if not os.path.isdir(sdir):
        flash("Server not found", "error")
        return redirect(url_for('dashboard'))
    root = _working_dir(sdir)
    entries = []
    def walk(base, prefix=""):
        try:
            items = sorted(os.listdir(base))
        except Exception:
            return
        for item in items:
            full = os.path.join(base, item)
            rel = os.path.join(prefix, item).replace("\\", "/")
            if os.path.isdir(full):
                entries.append({"name": item, "rel": rel, "is_dir": True,
                                "size": 0, "editable": False})
                walk(full, rel)
            else:
                try:
                    size = os.path.getsize(full)
                except Exception:
                    size = 0
                ext = os.path.splitext(item)[1].lower()
                entries.append({"name": item, "rel": rel, "is_dir": False,
                                "size": size, "editable": ext in EDITABLE_EXTS,
                                "ext": ext})
    walk(root)
    return render_template("files.html", server_name=server_name, files=entries)

def _resolve(server_name, filepath):
    uname = session['username']
    sdir = _server_dir(uname, server_name)
    root = _working_dir(sdir)
    return safe_join(root, filepath), root

@app.route("/api/file/read/<server_name>/<path:filepath>")
@login_required
def read_file(server_name, filepath):
    try:
        full, _ = _resolve(server_name, filepath)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.isfile(full):
        return jsonify({"error": "Not a file"}), 404
    if os.path.splitext(full)[1].lower() not in EDITABLE_EXTS:
        return jsonify({"error": "File type not editable"}), 400
    if os.path.getsize(full) > 3 * 1024 * 1024:
        return jsonify({"error": "File too large (>3MB)"}), 400
    try:
        with open(full, 'r', encoding='utf-8', errors='replace') as f:
            return jsonify({"content": f.read(), "path": filepath})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/file/save/<server_name>/<path:filepath>", methods=["POST"])
@login_required
def save_file(server_name, filepath):
    try:
        full, _ = _resolve(server_name, filepath)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if os.path.splitext(full)[1].lower() not in EDITABLE_EXTS:
        return jsonify({"error": "File type not editable"}), 400
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w', encoding='utf-8') as f:
        f.write(content)
    return jsonify({"success": True})

@app.route("/api/file/delete/<server_name>/<path:filepath>", methods=["POST"])
@login_required
def delete_file(server_name, filepath):
    try:
        full, _ = _resolve(server_name, filepath)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if os.path.isdir(full):
        force_delete_directory(full)
    elif os.path.isfile(full):
        os.remove(full)
    return jsonify({"success": True})

@app.route("/api/file/new/<server_name>", methods=["POST"])
@login_required
def new_entry(server_name):
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    is_dir = bool(data.get("is_dir"))
    if not name or "/" in name or ".." in name:
        return jsonify({"error": "Invalid name"}), 400
    try:
        full, _ = _resolve(server_name, name)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if os.path.exists(full):
        return jsonify({"error": "Already exists"}), 400
    if is_dir:
        os.makedirs(full, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, 'w').close()
    return jsonify({"success": True})

@app.route("/api/file/upload/<server_name>", methods=["POST"])
@login_required
def upload_file(server_name):
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file"}), 400
    fname = secure_filename(f.filename)
    ext = os.path.splitext(fname)[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTS:
        return jsonify({"error": f"File type {ext} not allowed"}), 400
    folder = request.form.get("folder", "").strip().strip("/")
    try:
        full_dir, _ = _resolve(server_name, folder) if folder else (None, None)
    except ValueError:
        return jsonify({"error": "Invalid folder"}), 400
    if not folder:
        try:
            full_dir, _ = _resolve(server_name, "")
        except ValueError:
            return jsonify({"error": "Invalid"}), 400
    os.makedirs(full_dir, exist_ok=True)
    target = os.path.join(full_dir, fname)
    f.save(target)
    if ext == ".zip":
        try:
            safe_zip_extract(target, full_dir)
            os.remove(target)
            return jsonify({"success": True, "message": "ZIP extracted"})
        except Exception as e:
            return jsonify({"error": f"ZIP extract failed: {e}"}), 400
    return jsonify({"success": True})

@app.route("/api/file/download/<server_name>/<path:filepath>")
@login_required
def download_file(server_name, filepath):
    try:
        full, _ = _resolve(server_name, filepath)
    except ValueError:
        return "Invalid path", 400
    if not os.path.isfile(full):
        return "Not found", 404
    return send_file(full, as_attachment=True)

@app.route("/api/file/download-zip/<server_name>")
@login_required
def download_zip(server_name):
    uname = session['username']
    sdir = _server_dir(uname, server_name)
    if not os.path.isdir(sdir):
        return "Not found", 404
    root = _working_dir(sdir)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()
    with zipfile.ZipFile(tmp.name, 'w', zipfile.ZIP_DEFLATED) as z:
        for base, _, files in os.walk(root):
            for fn in files:
                fp = os.path.join(base, fn)
                arc = os.path.relpath(fp, root)
                z.write(fp, arc)
    return send_file(tmp.name, as_attachment=True,
                     download_name=f"{server_name}.zip")

# ---------------- Routes: stats / health ----------------
@app.route("/api/stats")
@login_required
def get_stats():
    uname = session['username']
    udir = _user_dir(uname)
    total = running = 0
    for folder in os.listdir(udir):
        if os.path.isdir(os.path.join(udir, folder)):
            total += 1
            with proc_lock:
                if (uname, folder) in processes and processes[(uname, folder)].poll() is None:
                    running += 1
    return jsonify({"total_servers": total, "running_servers": running})

@app.route("/api/servers")
@login_required
def api_servers():
    uname = session['username']
    udir = _user_dir(uname)
    out = []
    for folder in os.listdir(udir):
        if os.path.isdir(os.path.join(udir, folder)):
            cfg = load_server_config(uname, folder)
            with proc_lock:
                running = (uname, folder) in processes and processes[(uname, folder)].poll() is None
            out.append({"name": folder, "running": running, "config": cfg})
    return jsonify(out)

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "ts": str(datetime.now()),
                    "procs": len(processes)})

# ---------------- Routes: ADMIN PANEL ----------------
@app.route("/admin")
@admin_required
def admin_panel():
    users = load_users()
    all_servers = []
    for uname in users:
        udir = os.path.join(UPLOAD_FOLDER, secure_filename(uname) or uname)
        if os.path.isdir(udir):
            for s in os.listdir(udir):
                sd = os.path.join(udir, s)
                if os.path.isdir(sd) and not s.startswith("_"):
                    with proc_lock:
                        running = (uname, s) in processes and processes[(uname, s)].poll() is None
                    all_servers.append({"user": uname, "server": s, "running": running})
    with proc_lock:
        procs = sum(1 for k, p in processes.items() if p.poll() is None)
    return render_template("admin.html", users=users,
                           total_users=len(users),
                           total_servers=len(all_servers),
                           total_running=procs,
                           all_servers=all_servers)

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    uname = request.form.get("username", "").strip()
    pwd = request.form.get("password", "")
    limit_s = request.form.get("server_limit", "5")
    try:
        limit = int(limit_s)
    except ValueError:
        limit = 5
    if len(uname) < 3 or len(pwd) < 4:
        flash("Username 3+ aur password 4+ chars ka ho", "error")
        return redirect(url_for('admin_panel'))
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", uname):
        flash("Sirf letters, numbers, _, - allowed", "error")
        return redirect(url_for('admin_panel'))
    users = load_users()
    if uname in users:
        flash("User already exists", "error")
        return redirect(url_for('admin_panel'))
    users[uname] = {
        "password": _hash(pwd),
        "is_admin": False,
        "created_at": str(datetime.now()),
        "server_limit": limit,
        "active": True,
    }
    save_users(users)
    _user_dir(uname)
    flash(f"User '{uname}' created (limit={limit})", "success")
    return redirect(url_for('admin_panel'))

@app.route("/admin/toggle_user/<uname>", methods=["POST"])
@admin_required
def admin_toggle_user(uname):
    if uname == "admin":
        return jsonify({"error": "Cannot modify admin"}), 400
    users = load_users()
    if uname not in users:
        return jsonify({"error": "User not found"}), 404
    users[uname]["active"] = not users[uname].get("active", True)
    save_users(users)
    return jsonify({"success": True, "active": users[uname]["active"]})

@app.route("/admin/reset_password/<uname>", methods=["POST"])
@admin_required
def admin_reset_password(uname):
    newp = (request.get_json(silent=True) or {}).get("password") or request.form.get("password", "")
    if len(newp) < 4:
        return jsonify({"error": "Password 4+ chars"}), 400
    users = load_users()
    if uname not in users:
        return jsonify({"error": "User not found"}), 404
    users[uname]["password"] = _hash(newp)
    save_users(users)
    return jsonify({"success": True})

@app.route("/admin/set_limit/<uname>", methods=["POST"])
@admin_required
def admin_set_limit(uname):
    try:
        lim = int((request.get_json(silent=True) or {}).get("limit", 5))
    except Exception:
        return jsonify({"error": "Invalid limit"}), 400
    users = load_users()
    if uname not in users:
        return jsonify({"error": "Not found"}), 404
    users[uname]["server_limit"] = lim
    save_users(users)
    return jsonify({"success": True})

@app.route("/admin/delete_user/<uname>", methods=["POST"])
@admin_required
def admin_delete_user(uname):
    if uname == "admin":
        return jsonify({"error": "Cannot delete admin"}), 400
    users = load_users()
    if uname not in users:
        return jsonify({"error": "Not found"}), 404
    with proc_lock:
        keys = [(u, s) for (u, s) in processes if u == uname]
    for (u, s) in keys:
        stop_server(u, s)
    del users[uname]
    save_users(users)
    force_delete_directory(_user_dir(uname))
    return jsonify({"success": True})

@app.route("/admin/user_servers/<uname>")
@admin_required
def admin_user_servers(uname):
    udir = _user_dir(uname)
    out = []
    if os.path.isdir(udir):
        for s in os.listdir(udir):
            sd = os.path.join(udir, s)
            if os.path.isdir(sd) and not s.startswith("_"):
                cfg = load_server_config(uname, s)
                with proc_lock:
                    running = (uname, s) in processes and processes[(uname, s)].poll() is None
                out.append({"server": s, "config": cfg, "running": running})
    return jsonify(out)

@app.route("/admin/stop_server/<uname>/<sname>", methods=["POST"])
@admin_required
def admin_stop_server(uname, sname):
    ok, msg = stop_server(uname, sname)
    return jsonify({"success": ok, "message": msg})

@app.route("/admin/start_server/<uname>/<sname>", methods=["POST"])
@admin_required
def admin_start_server(uname, sname):
    ok, msg = start_server(uname, sname)
    return jsonify({"success": ok, "message": msg})

@app.route("/admin/delete_server/<uname>/<sname>", methods=["POST"])
@admin_required
def admin_delete_server(uname, sname):
    stop_server(uname, sname)
    time.sleep(0.5)
    sdir = _server_dir(uname, sname)
    if force_delete_directory(sdir):
        release_port(uname, sname)
        return jsonify({"success": True})
    return jsonify({"error": "Delete failed"}), 400

# ---------------- Bootstrap ----------------
if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    load_users()
    port = int(os.environ.get("PORT", 8030))
    print(f"""
    ╔══════════════════════════════════════════╗
    ║      MASTER HOSTING — GOLD EDITION       ║
    ║      Admin Panel · Unlimited Servers     ║
    ╠══════════════════════════════════════════╣
    ║  URL:  http://0.0.0.0:{port}
    ║  Admin user: admin
    ║  Admin pass: ADMIN_PASSWORD env (default: admin123)
    ╚══════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)