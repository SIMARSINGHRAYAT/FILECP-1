#!/usr/bin/env python3
"""
filecp — Instant, Private, and Seamless File Sharing
A single-file, production-ready web application for secure session-based
file sharing across devices.
"""

import asyncio
import base64
import io
import json
import mimetypes
import os
import secrets
import shutil
import string
import tempfile
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

import qrcode
import uvicorn
from cryptography.fernet import Fernet
from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    Response,
    StreamingResponse,
)

# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────
APP_NAME = "filecp"
APP_VERSION = "1.0.0"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8000))
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL", "")
MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 500 MB total per session
MAX_SINGLE_FILE = 200 * 1024 * 1024  # 200 MB per file
UPLOAD_DIR = Path(tempfile.gettempdir()) / "filecp_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ENCRYPTION_KEY = Fernet.generate_key()
CIPHER = Fernet(ENCRYPTION_KEY)
CLEANUP_INTERVAL = 30  # seconds between cleanup sweeps
SESSION_ID_LENGTH = 6
SESSION_META_FILE = "session.json"

# ──────────────────────────────────────────────────────────────────────
# In-memory session store
# ──────────────────────────────────────────────────────────────────────
sessions: dict = {}


# ──────────────────────────────────────────────────────────────────────
# App initialization
# ──────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def _lifespan(app: FastAPI):
    _load_persisted_sessions()
    task = asyncio.create_task(_cleanup_expired_sessions())
    yield
    task.cancel()


app = FastAPI(title=APP_NAME, version=APP_VERSION, docs_url=None, redoc_url=None, lifespan=_lifespan)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────
def _generate_session_id() -> str:
    alphabet = string.ascii_uppercase + string.digits
    while True:
        sid = "".join(secrets.choice(alphabet) for _ in range(SESSION_ID_LENGTH))
        if sid not in sessions:
            return sid


def _session_dir(session_id: str) -> Path:
    return UPLOAD_DIR / session_id


def _session_meta_path(session_id: str) -> Path:
    return _session_dir(session_id) / SESSION_META_FILE


def _delete_session(session_id: str) -> None:
    shutil.rmtree(_session_dir(session_id), ignore_errors=True)
    sessions.pop(session_id, None)


def _persist_session(session_id: str) -> None:
    session = sessions.get(session_id)
    if not session:
        return
    meta_path = _session_meta_path(session_id)
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(session, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_persisted_sessions() -> None:
    if not UPLOAD_DIR.exists():
        return

    now = time.time()
    for meta_path in UPLOAD_DIR.glob(f"*/{SESSION_META_FILE}"):
        try:
            session = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            shutil.rmtree(meta_path.parent, ignore_errors=True)
            continue

        session_id = str(session.get("id", "")).upper().strip()
        expires_at = float(session.get("expires_at", 0))
        if not session_id or now > expires_at:
            shutil.rmtree(meta_path.parent, ignore_errors=True)
            continue

        session["id"] = session_id
        sessions[session_id] = session


def _public_session_url(request: Request, session_id: str) -> str:
    base = RENDER_EXTERNAL_URL or str(request.base_url).rstrip("/")
    return f"{base}/session/{session_id}"


def _public_send_to_url(request: Request, session_id: str) -> str:
    base = RENDER_EXTERNAL_URL or str(request.base_url).rstrip("/")
    return f"{base}/send-to/{session_id}"


def _format_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def _get_file_icon(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    icons = {
        ".pdf": "picture_as_pdf",
        ".doc": "description", ".docx": "description",
        ".xls": "table_chart", ".xlsx": "table_chart",
        ".ppt": "slideshow", ".pptx": "slideshow",
        ".txt": "article", ".md": "article", ".csv": "article",
        ".zip": "folder_zip", ".rar": "folder_zip", ".7z": "folder_zip",
        ".tar": "folder_zip", ".gz": "folder_zip",
        ".mp4": "movie", ".avi": "movie", ".mkv": "movie", ".mov": "movie",
        ".mp3": "audio_file", ".wav": "audio_file", ".flac": "audio_file",
        ".ogg": "audio_file",
        ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
        ".svg": "image", ".webp": "image", ".bmp": "image",
        ".py": "code", ".js": "code", ".html": "code", ".css": "code",
        ".java": "code", ".cpp": "code", ".c": "code",
        ".json": "data_object", ".xml": "data_object",
        ".exe": "terminal", ".msi": "terminal",
    }
    return icons.get(ext, "insert_drive_file")


def _is_previewable_image(filename: str) -> bool:
    return Path(filename).suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg")


async def _cleanup_expired_sessions():
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL)
        now = time.time()
        expired = [sid for sid, s in sessions.items() if now > s["expires_at"]]
        for sid in expired:
            _delete_session(sid)


# ──────────────────────────────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────────────────────────────
@app.post("/api/upload")
async def api_upload(
    request: Request,
    files: list[UploadFile] = File(...),
    note: str = Form(""),
    duration: int = Form(10),
    session_id: str = Form(""),
):
    # Clamp duration between 1 and 1440 minutes (24 hours)
    duration = max(1, min(1440, duration))

    existing = False
    if session_id:
        sid = session_id.upper().strip()
        if sid not in sessions:
            raise HTTPException(404, "Session not found or expired.")
        if time.time() > sessions[sid]["expires_at"]:
            raise HTTPException(410, "Session has expired.")
        session_dir = _session_dir(sid)
        session_dir.mkdir(parents=True, exist_ok=True)
        existing = True
    else:
        sid = _generate_session_id()
        session_dir = _session_dir(sid)
        session_dir.mkdir(parents=True, exist_ok=True)

    file_list = []
    total_size = 0

    for upload in files:
        if not upload.filename:
            continue
        safe_name = Path(upload.filename).name
        if not safe_name:
            safe_name = "unnamed_file"
        content = await upload.read()
        file_size = len(content)

        if file_size > MAX_SINGLE_FILE:
            shutil.rmtree(session_dir, ignore_errors=True)
            raise HTTPException(400, f"File '{safe_name}' exceeds 200 MB limit.")

        total_size += file_size
        if total_size > MAX_UPLOAD_SIZE:
            shutil.rmtree(session_dir, ignore_errors=True)
            raise HTTPException(400, "Total upload size exceeds 500 MB limit.")

        encrypted = CIPHER.encrypt(content)
        file_path = session_dir / safe_name
        counter = 1
        while file_path.exists():
            stem = Path(safe_name).stem
            suffix = Path(safe_name).suffix
            file_path = session_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        file_path.write_bytes(encrypted)

        file_list.append({
            "name": file_path.name,
            "original_name": safe_name,
            "size": file_size,
            "size_formatted": _format_size(file_size),
            "icon": _get_file_icon(safe_name),
            "is_image": _is_previewable_image(safe_name),
            "is_pdf": safe_name.lower().endswith(".pdf"),
            "mime": mimetypes.guess_type(safe_name)[0] or "application/octet-stream",
        })

    if not file_list:
        if not existing:
            shutil.rmtree(session_dir, ignore_errors=True)
        raise HTTPException(400, "No files were uploaded.")

    now = time.time()
    if existing:
        sessions[sid].update({
            "files": file_list,
            "note": note.strip()[:1000] if note else sessions[sid].get("note", ""),
            "expires_at": now + duration * 60,
            "duration_minutes": duration,
            "total_size": total_size,
            "total_size_formatted": _format_size(total_size),
            "waiting": False,
        })
    else:
        sessions[sid] = {
            "id": sid,
            "files": file_list,
            "note": note.strip()[:1000] if note else "",
            "created_at": now,
            "expires_at": now + duration * 60,
            "duration_minutes": duration,
            "total_size": total_size,
            "total_size_formatted": _format_size(total_size),
            "download_count": 0,
        }

        _persist_session(sid)
    return JSONResponse({
        "session_id": sid,
        "expires_at": sessions[sid]["expires_at"],
        "file_count": len(file_list),
          "share_url": _public_session_url(request, sid),
    })


@app.get("/api/session/{session_id}")
async def api_session_info(session_id: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if time.time() > s["expires_at"]:
        raise HTTPException(410, "Session has expired.")
    remaining = max(0, s["expires_at"] - time.time())
    return JSONResponse({
        "id": s["id"],
        "files": s["files"],
        "note": s["note"],
        "created_at": s["created_at"],
        "expires_at": s["expires_at"],
        "remaining_seconds": remaining,
        "duration_minutes": s["duration_minutes"],
        "total_size_formatted": s["total_size_formatted"],
        "download_count": s["download_count"],
    })


    @app.get("/healthz")
    async def healthz():
      return JSONResponse({"ok": True, "service": APP_NAME, "version": APP_VERSION})


@app.get("/api/download/{session_id}/{filename}")
async def api_download_file(session_id: str, filename: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if time.time() > s["expires_at"]:
        raise HTTPException(410, "Session has expired.")

    valid_names = {f["name"] for f in s["files"]}
    if filename not in valid_names:
        raise HTTPException(404, "File not found in session.")

    file_path = UPLOAD_DIR / sid / filename
    if not file_path.exists():
        raise HTTPException(404, "File data not found.")

    try:
        file_path.resolve().relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied.")

    encrypted = file_path.read_bytes()
    decrypted = CIPHER.decrypt(encrypted)

    s["download_count"] += 1
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    # Find original name for proper download filename
    original_name = filename
    for f in s["files"]:
        if f["name"] == filename:
            original_name = f["original_name"]
            break
    return Response(
        content=decrypted,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{original_name}"',
            "Content-Length": str(len(decrypted)),
        },
    )


@app.get("/api/preview/{session_id}/{filename}")
async def api_preview_file(session_id: str, filename: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if time.time() > s["expires_at"]:
        raise HTTPException(410, "Session has expired.")

    valid_names = {f["name"] for f in s["files"]}
    if filename not in valid_names:
        raise HTTPException(404, "File not found in session.")

    file_path = UPLOAD_DIR / sid / filename
    if not file_path.exists():
        raise HTTPException(404, "File data not found.")

    try:
        file_path.resolve().relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied.")

    encrypted = file_path.read_bytes()
    decrypted = CIPHER.decrypt(encrypted)
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return Response(content=decrypted, media_type=mime)


@app.get("/api/download-all/{session_id}")
async def api_download_all(session_id: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if time.time() > s["expires_at"]:
        raise HTTPException(410, "Session has expired.")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in s["files"]:
            file_path = UPLOAD_DIR / sid / f["name"]
            if file_path.exists():
                encrypted = file_path.read_bytes()
                decrypted = CIPHER.decrypt(encrypted)
                zf.writestr(f["original_name"], decrypted)

    buf.seek(0)
    s["download_count"] += 1
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="filecp_{sid}.zip"'},
    )


@app.get("/api/qr/{session_id}")
async def api_qr_code(request: Request, session_id: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    url = _public_session_url(request, sid)
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#9b7bff", back_color="#f6f2ff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.post("/api/receive-session")
async def api_create_receive_session():
    sid = _generate_session_id()
    session_dir = _session_dir(sid)
    session_dir.mkdir(parents=True, exist_ok=True)
    now = time.time()
    sessions[sid] = {
        "id": sid,
        "files": [],
        "note": "",
        "created_at": now,
        "expires_at": now + 10 * 60,
        "duration_minutes": 10,
        "total_size": 0,
        "total_size_formatted": _format_size(0),
        "download_count": 0,
        "waiting": True,
    }
    _persist_session(sid)
    return JSONResponse({"session_id": sid})


@app.get("/api/receive-qr/{session_id}")
async def api_receive_qr(request: Request, session_id: str):
  sid = session_id.upper().strip()
  if sid not in sessions:
    raise HTTPException(404, "Session not found.")
  url = _public_send_to_url(request, sid)
  qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
  qr.add_data(url)
  qr.make(fit=True)
  img = qr.make_image(fill_color="#9b7bff", back_color="#f6f2ff")
  buf = io.BytesIO()
  img.save(buf, format="PNG")
  buf.seek(0)
  return StreamingResponse(buf, media_type="image/png")


# ──────────────────────────────────────────────────────────────────────
# Frontend Templates
# ──────────────────────────────────────────────────────────────────────

_SHARED_STYLES = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Fraunces:opsz,wght@9..144,600;9..144,700&display=swap');
  @import url('https://fonts.googleapis.com/icon?family=Material+Icons+Round');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg-primary: #05040b;
    --bg-secondary: rgba(21, 15, 34, 0.82);
    --bg-surface: rgba(18, 12, 31, 0.74);
    --bg-surface-hover: rgba(31, 20, 51, 0.84);
    --bg-elevated: rgba(8, 6, 14, 0.96);
    --border-color: rgba(224, 232, 255, 0.12);
    --border-light: rgba(255, 255, 255, 0.22);
    --text-primary: #f6f2ea;
    --text-secondary: #d8dfef;
    --text-muted: #9aa6be;
    --text-bright: #ffffff;
    --accent: #9b7bff;
    --accent-hover: #c3b2ff;
    --accent-subtle: rgba(155, 123, 255, 0.14);
    --accent-warm: #ff78d2;
    --accent-warm-subtle: rgba(255, 120, 210, 0.12);
    --success: #8df0c4;
    --success-subtle: rgba(141, 240, 196, 0.12);
    --warning: #ffd479;
    --warning-subtle: rgba(255, 212, 121, 0.12);
    --error: #ff8e8e;
    --error-subtle: rgba(255, 142, 142, 0.12);
    --radius-sm: 10px;
    --radius-md: 16px;
    --radius-lg: 24px;
    --shadow-sm: 0 10px 24px rgba(0, 0, 0, 0.16);
    --shadow-md: 0 18px 44px rgba(0, 0, 0, 0.24);
    --shadow-lg: 0 30px 70px rgba(0, 0, 0, 0.34);
    --transition: 0.22s cubic-bezier(0.4, 0, 0.2, 1);
    --font: 'Manrope', sans-serif;
    --display-font: 'Fraunces', serif;
  }

  html { scroll-behavior: smooth; }
  body {
    font-family: var(--font);
    background:
      radial-gradient(circle at top left, rgba(155, 123, 255, 0.22), transparent 28%),
      radial-gradient(circle at top right, rgba(255, 120, 210, 0.14), transparent 24%),
      radial-gradient(circle at bottom, rgba(72, 48, 146, 0.18), transparent 30%),
      linear-gradient(180deg, #020205 0%, #07050d 48%, #0b0713 100%);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
    overflow-x: hidden;
    position: relative;
  }
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    pointer-events: none;
    background-image:
      linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
    background-size: 34px 34px;
    mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.82), transparent 85%);
    opacity: 0.32;
    z-index: -2;
  }
  body::after {
    content: '';
    position: fixed;
    right: -12vw;
    top: 9vh;
    width: 30vw;
    height: 30vw;
    min-width: 280px;
    min-height: 280px;
    background: radial-gradient(circle, rgba(155, 123, 255, 0.22), transparent 70%);
    filter: blur(10px);
    pointer-events: none;
    z-index: -2;
  }

  a { color: var(--text-primary); text-decoration: none; transition: color var(--transition), opacity var(--transition); }
  a:hover { color: var(--text-bright); }

  .material-icons-round { font-family: 'Material Icons Round'; vertical-align: middle; }

  .container { max-width: 1120px; margin: 0 auto; padding: 0 24px; }
  .text-center { text-align: center; }

  .nav {
    position: sticky; top: 0; z-index: 100;
    background: rgba(7, 10, 19, 0.66);
    backdrop-filter: blur(22px) saturate(160%);
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    padding: 14px 0;
  }
  .nav-inner {
    display: flex; align-items: center; justify-content: center;
    max-width: 1120px; margin: 0 auto; padding: 0 24px;
  }
  .nav-brand {
    display: inline-flex; align-items: center; gap: 10px;
    font-family: var(--display-font); font-size: 1rem; font-weight: 700;
    color: var(--text-primary); letter-spacing: 0.18em; text-transform: uppercase;
  }
  .nav-brand::before {
    content: '';
    width: 10px; height: 10px; border-radius: 50%;
    background: linear-gradient(135deg, var(--accent), var(--accent-warm));
    box-shadow: 0 0 18px rgba(155, 123, 255, 0.55);
  }

  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 12px 22px; border-radius: 999px;
    font-family: var(--font); font-size: 0.9rem; font-weight: 700;
    cursor: pointer; border: 1px solid transparent; transition: all var(--transition);
    text-decoration: none; white-space: nowrap; letter-spacing: 0.02em;
    box-shadow: none;
  }
  .btn-primary {
    color: #06101a;
    background: linear-gradient(135deg, #f3ecff 0%, #bda9ff 45%, #ff8bd6 100%);
    box-shadow: 0 18px 40px rgba(155, 123, 255, 0.24);
  }
  .btn-primary:hover {
    transform: translateY(-1px);
    filter: brightness(1.03);
    box-shadow: 0 22px 50px rgba(155, 123, 255, 0.28);
  }
  .btn-outline {
    background: rgba(255, 255, 255, 0.02); color: var(--text-primary);
    border-color: rgba(255, 255, 255, 0.15);
    backdrop-filter: blur(10px);
  }
  .btn-outline:hover {
    border-color: rgba(155, 123, 255, 0.36); color: var(--text-bright);
    background: rgba(155, 123, 255, 0.08);
  }
  .btn-ghost {
    background: rgba(255, 255, 255, 0.03); color: var(--text-primary);
    border-color: rgba(255, 255, 255, 0.08);
  }
  .btn-ghost:hover { background: rgba(255, 255, 255, 0.06); border-color: rgba(255, 255, 255, 0.14); }
  .btn-sm { padding: 8px 14px; font-size: 0.78rem; }
  .btn-lg { padding: 16px 34px; font-size: 0.95rem; letter-spacing: 0.04em; }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none !important; box-shadow: none; }
  .btn .material-icons-round { font-size: 18px; }

  .card {
    background: linear-gradient(180deg, rgba(19, 25, 43, 0.82), rgba(11, 16, 32, 0.78));
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: 24px;
    box-shadow: var(--shadow-md);
    backdrop-filter: blur(18px) saturate(140%);
    transition: transform var(--transition), border-color var(--transition), background var(--transition);
  }
  .card-hover:hover {
    border-color: rgba(255, 255, 255, 0.18);
    transform: translateY(-2px);
  }

  .chip {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 6px 12px; border-radius: 999px;
    font-size: 0.72rem; font-weight: 700;
    background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.08);
    color: var(--text-secondary);
  }
  .chip .material-icons-round { font-size: 13px; }

  .input-group { display: flex; flex-direction: column; gap: 6px; }
  .input-group label {
    font-size: 0.7rem; font-weight: 700; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 1.4px;
  }
  .input-field {
    padding: 12px 16px; border-radius: var(--radius-sm);
    background: rgba(10, 14, 27, 0.7); border: 1px solid rgba(255, 255, 255, 0.1);
    color: var(--text-primary); font-family: var(--font); font-size: 0.92rem;
    transition: all var(--transition); outline: none;
  }
  .input-field:focus {
    border-color: rgba(155, 123, 255, 0.35);
    box-shadow: 0 0 0 4px rgba(155, 123, 255, 0.08);
  }
  .input-field::placeholder { color: var(--text-muted); }

  .progress-bar {
    width: 100%; height: 4px; border-radius: 999px;
    background: rgba(255, 255, 255, 0.08); overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%; border-radius: 999px;
    background: linear-gradient(90deg, var(--accent), var(--accent-warm));
    transition: width 0.3s ease;
  }

  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(16px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
  @keyframes spin { to { transform: rotate(360deg); } }
  .animate-in { animation: fadeInUp 0.55s ease forwards; }
  .stagger-1 { animation-delay: 0.05s; opacity: 0; }
  .stagger-2 { animation-delay: 0.1s; opacity: 0; }
  .stagger-3 { animation-delay: 0.15s; opacity: 0; }
  .stagger-4 { animation-delay: 0.2s; opacity: 0; }

  .spinner {
    width: 24px; height: 24px; border: 2px solid rgba(255, 255, 255, 0.12);
    border-top-color: var(--accent); border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  .spinner-lg { width: 36px; height: 36px; }

  .toast-container {
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    display: flex; flex-direction: column; gap: 8px;
  }
  .toast {
    display: flex; align-items: center; gap: 10px;
    padding: 13px 16px; border-radius: 16px;
    background: rgba(10, 13, 23, 0.92); border: 1px solid rgba(255, 255, 255, 0.12);
    box-shadow: var(--shadow-lg); color: var(--text-primary);
    font-size: 0.82rem; font-weight: 600;
    animation: fadeInUp 0.3s ease forwards;
    max-width: 340px;
  }
  .toast .material-icons-round { font-size: 18px; color: var(--accent); }

  .hero-title, .receive-card h2, .page-header h1, .session-header h1, .success-card h2 {
    font-family: var(--display-font);
    letter-spacing: 0.02em;
  }

  @media (max-width: 640px) {
    .container { padding: 0 16px; }
    .card { padding: 18px; }
    .btn-lg { padding: 14px 24px; font-size: 0.9rem; }
    .toast-container { left: 16px; right: 16px; bottom: 16px; }
    .toast { max-width: none; }
  }
</style>
"""

_NAV_INNER = """
<nav class="nav">
  <div class="nav-inner">
    <a href="/" class="nav-brand">filecp</a>
  </div>
</nav>
"""

_TOAST_JS = """
<div class="toast-container" id="toastContainer"></div>
<script>
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const icons = { success: 'check_circle', error: 'error', info: 'info' };
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = '<span class="material-icons-round">' + (icons[type] || 'info') + '</span>' + message;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateY(10px)'; toast.style.transition = '0.3s ease'; setTimeout(() => toast.remove(), 300); }, 3500);
}
</script>
"""


# ── Welcome Page (clean, no nav, no badge, only Get Started) ─────────
_WELCOME_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>filecp</title>
  """ + _SHARED_STYLES + """
  <style>
    .hero {
      min-height: 100vh;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      text-align: center; padding: 40px 24px;
    }
    .hero-title {
      font-size: clamp(3.5rem, 10vw, 6rem);
      font-weight: 900; letter-spacing: 6px;
      text-transform: uppercase;
      line-height: 1; margin-bottom: 20px;
      color: var(--text-primary);
    }
    .hero-subtitle {
      font-size: clamp(0.85rem, 2vw, 1rem);
      color: var(--text-muted); font-weight: 400;
      max-width: 420px; line-height: 1.8; margin-bottom: 48px;
      letter-spacing: 0.5px;
    }
    .features {
      display: grid; grid-template-columns: repeat(3, 1fr);
      gap: 14px; margin-top: 56px; width: 100%; max-width: 780px;
    }
    @media (max-width: 640px) { .features { grid-template-columns: 1fr; } }
    .feature-card {
      display: flex; align-items: flex-start; gap: 12px;
      padding: 16px; border-radius: var(--radius-md);
      background: var(--bg-surface); border: 1px solid var(--border-color);
      text-align: left; transition: all var(--transition);
    }
    .feature-card:hover { border-color: var(--border-light); }
    .feature-icon {
      width: 32px; height: 32px; border-radius: 6px;
      background: var(--accent-subtle); color: var(--text-muted);
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }
    .feature-icon .material-icons-round { font-size: 16px; }
    .feature-card h3 { font-size: 0.78rem; font-weight: 700; color: var(--text-primary); margin-bottom: 2px; }
    .feature-card p { font-size: 0.68rem; color: var(--text-muted); line-height: 1.5; }

    .footer {
      text-align: center; padding: 24px;
      color: var(--text-muted); font-size: 0.65rem;
      letter-spacing: 1px;
    }
  </style>
</head>
<body>
  <main class="hero">
    <h1 class="hero-title animate-in stagger-1">filecp</h1>
    <p class="hero-subtitle animate-in stagger-2">
      Instant, Private, and Seamless File Sharing.<br>
      No accounts. No tracking. Just transfer.
    </p>
    <a href="/dashboard" class="btn btn-primary btn-lg animate-in stagger-3">
      Get Started
    </a>
    <div class="features animate-in stagger-4">
      <div class="feature-card">
        <div class="feature-icon"><span class="material-icons-round">qr_code_2</span></div>
        <div><h3>QR Pairing</h3><p>Scan to instantly access files on any device</p></div>
      </div>
      <div class="feature-card">
        <div class="feature-icon"><span class="material-icons-round">lock</span></div>
        <div><h3>Secure Transfer</h3><p>End-to-end encrypted — your files stay private</p></div>
      </div>
      <div class="feature-card">
        <div class="feature-icon"><span class="material-icons-round">timer</span></div>
        <div><h3>Auto-Expiry</h3><p>Sessions self-destruct after your chosen duration</p></div>
      </div>
      <div class="feature-card">
        <div class="feature-icon"><span class="material-icons-round">devices</span></div>
        <div><h3>Cross-Platform</h3><p>Works on any device with a browser — no app needed</p></div>
      </div>
      <div class="feature-card">
        <div class="feature-icon"><span class="material-icons-round">file_copy</span></div>
        <div><h3>Multi-Format</h3><p>Images, documents, videos, archives — anything</p></div>
      </div>
      <div class="feature-card">
        <div class="feature-icon"><span class="material-icons-round">person_off</span></div>
        <div><h3>No Login</h3><p>Zero accounts. Start sharing immediately</p></div>
      </div>
    </div>
  </main>
  <footer class="footer">FILECP</footer>
</body>
</html>"""


# ── Dashboard (Send / Receive choice) ───────────────────────────────
_DASHBOARD_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard — filecp</title>
  """ + _SHARED_STYLES + """
  <style>
    .page {
      min-height: calc(100vh - 56px);
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      padding: 40px 24px;
    }
    .page-title {
      font-size: 1rem; font-weight: 600; color: var(--text-muted);
      letter-spacing: 2px; text-transform: uppercase; margin-bottom: 40px;
    }
    .action-grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
      max-width: 520px; width: 100%;
    }
    @media (max-width: 500px) { .action-grid { grid-template-columns: 1fr; } }
    .action-card {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      gap: 16px; padding: 40px 24px;
      background: var(--bg-surface); border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      cursor: pointer; transition: all var(--transition);
      text-decoration: none; color: var(--text-primary);
    }
    .action-card:hover {
      border-color: var(--border-light);
      background: var(--bg-surface-hover);
      transform: translateY(-3px);
    }
    .action-icon {
      width: 56px; height: 56px; border-radius: 50%;
      background: var(--accent-subtle);
      display: flex; align-items: center; justify-content: center;
    }
    .action-icon .material-icons-round { font-size: 26px; color: var(--text-secondary); }
    .action-card h2 { font-size: 0.95rem; font-weight: 700; letter-spacing: 1px; }
    .action-card p { font-size: 0.7rem; color: var(--text-muted); text-align: center; line-height: 1.5; }
  </style>
</head>
<body>
  """ + _NAV_INNER + """
  <main class="page">
    <div class="page-title animate-in">What would you like to do?</div>
    <div class="action-grid">
      <a href="/send" class="action-card animate-in stagger-1">
        <div class="action-icon"><span class="material-icons-round">cloud_upload</span></div>
        <h2>Send</h2>
        <p>Upload files and generate a QR code to share</p>
      </a>
      <a href="/receive" class="action-card animate-in stagger-2">
        <div class="action-icon"><span class="material-icons-round">cloud_download</span></div>
        <h2>Receive</h2>
        <p>Generate a QR code to receive files instantly</p>
      </a>
    </div>
  </main>
</body>
</html>"""


# ── Send Page (custom time input, QR-only result) ───────────────────
_SEND_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Send — filecp</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { padding: 32px 0 64px; }
    .page-header { margin-bottom: 28px; }
    .page-header h1 { font-size: 1.4rem; font-weight: 800; letter-spacing: 1px; }
    .page-header p { color: var(--text-muted); font-size: 0.8rem; margin-top: 4px; }

    .drop-zone {
      border: 1px dashed var(--border-light);
      border-radius: var(--radius-lg);
      padding: 44px 24px; text-align: center;
      cursor: pointer; transition: all var(--transition);
    }
    .drop-zone:hover, .drop-zone.drag-over {
      border-color: var(--text-muted); background: var(--accent-subtle);
    }
    .drop-zone-icon { font-size: 40px; color: var(--text-muted); margin-bottom: 10px; }
    .drop-zone h3 { font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px; }
    .drop-zone p { font-size: 0.7rem; color: var(--text-muted); }
    .drop-zone input { display: none; }

    .file-list { display: flex; flex-direction: column; gap: 6px; margin-top: 14px; }
    .file-item {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 14px; border-radius: var(--radius-sm);
      background: var(--bg-secondary); border: 1px solid var(--border-color);
      animation: fadeInUp 0.3s ease forwards;
    }
    .file-item-icon {
      width: 32px; height: 32px; border-radius: 6px;
      background: var(--accent-subtle); color: var(--text-muted);
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }
    .file-item-icon .material-icons-round { font-size: 16px; }
    .file-item-info { flex: 1; min-width: 0; }
    .file-item-name { font-size: 0.8rem; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .file-item-size { font-size: 0.65rem; color: var(--text-muted); }
    .file-item-remove {
      width: 24px; height: 24px; border-radius: 50%;
      background: none; border: none; color: var(--text-muted);
      cursor: pointer; display: flex; align-items: center; justify-content: center;
      transition: all var(--transition); flex-shrink: 0;
    }
    .file-item-remove:hover { color: var(--text-primary); }

    .options-row {
      display: grid; grid-template-columns: 1fr 1fr; gap: 14px;
      margin-top: 18px;
    }
    @media (max-width: 640px) { .options-row { grid-template-columns: 1fr; } }

    .duration-input-row {
      display: flex; align-items: center; gap: 8px;
    }
    .duration-input {
      width: 80px; padding: 12px 14px; border-radius: var(--radius-sm);
      background: var(--bg-secondary); border: 1px solid var(--border-color);
      color: var(--text-primary); font-family: var(--font); font-size: 0.95rem;
      text-align: center; outline: none; transition: all var(--transition);
    }
    .duration-input:focus { border-color: var(--text-muted); }
    .duration-label { font-size: 0.8rem; color: var(--text-muted); }

    .upload-actions { margin-top: 22px; display: flex; gap: 12px; align-items: center; }
    .upload-actions .file-count { font-size: 0.75rem; color: var(--text-muted); margin-left: auto; }

    .upload-progress {
      margin-top: 22px; padding: 18px;
      border-radius: var(--radius-md);
      background: var(--bg-surface); border: 1px solid var(--border-color);
      display: none;
    }
    .upload-progress.active { display: block; }
    .upload-progress-text { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 8px; }

    /* QR-only result */
    .result-section { margin-top: 32px; display: none; }
    .result-section.active { display: block; animation: fadeInUp 0.5s ease forwards; }
    .result-card {
      background: var(--bg-surface); border: 1px solid var(--border-color);
      border-radius: var(--radius-lg); padding: 40px;
      display: flex; flex-direction: column; align-items: center; gap: 20px;
      text-align: center;
    }
    .result-card h2 { font-size: 0.9rem; font-weight: 700; color: var(--text-secondary); letter-spacing: 1px; }
    .result-qr-img {
      width: 220px; height: 220px; border-radius: var(--radius-md);
      border: 1px solid var(--border-color);
    }
    .result-hint { font-size: 0.7rem; color: var(--text-muted); }
    .countdown-text { font-size: 0.75rem; color: var(--text-muted); font-weight: 600; }
  </style>
</head>
<body>
  """ + _NAV_INNER + """
  <main class="container page">
    <div class="page-header animate-in">
      <h1>Send Files</h1>
      <p>Upload files and share via QR code</p>
    </div>

    <form id="uploadForm" class="animate-in stagger-1">
      <div class="drop-zone" id="dropZone">
        <span class="material-icons-round drop-zone-icon">cloud_upload</span>
        <h3>Drop files here or click to browse</h3>
        <p>Any file type &middot; Up to 200 MB per file &middot; 500 MB total</p>
        <input type="file" id="fileInput" multiple>
      </div>

      <div class="file-list" id="fileList"></div>

      <div class="options-row">
        <div class="input-group">
          <label>Session Duration</label>
          <div class="duration-input-row">
            <input type="number" class="duration-input" id="durationInput" value="10" min="1" max="1440">
            <span class="duration-label">minutes</span>
          </div>
        </div>
        <div class="input-group">
          <label>Note (optional)</label>
          <input type="text" class="input-field" id="noteInput" placeholder="Add a message..." maxlength="1000">
        </div>
      </div>

      <div class="upload-actions">
        <button type="submit" class="btn btn-primary" id="uploadBtn" disabled>
          <span class="material-icons-round">send</span>
          Upload &amp; Share
        </button>
        <button type="button" class="btn btn-ghost btn-sm" id="clearBtn" style="display:none">Clear All</button>
        <span class="file-count" id="fileCount"></span>
      </div>
    </form>

    <div class="upload-progress" id="uploadProgress">
      <div class="upload-progress-text" id="progressText">Uploading...</div>
      <div class="progress-bar"><div class="progress-bar-fill" id="progressFill" style="width:0%"></div></div>
    </div>

    <div class="result-section" id="resultSection">
      <div class="result-card">
        <h2>Scan to Receive</h2>
        <img id="qrImage" class="result-qr-img" alt="QR Code" src="">
        <div class="countdown-text" id="countdownText"></div>
        <p class="result-hint">Scan this QR code with any phone camera to download</p>
      </div>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileList = document.getElementById('fileList');
    const uploadBtn = document.getElementById('uploadBtn');
    const clearBtn = document.getElementById('clearBtn');
    const fileCountEl = document.getElementById('fileCount');
    let selectedFiles = [];

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
      e.preventDefault(); dropZone.classList.remove('drag-over');
      addFiles(Array.from(e.dataTransfer.files));
    });
    fileInput.addEventListener('change', () => { addFiles(Array.from(fileInput.files)); fileInput.value = ''; });

    function addFiles(newFiles) {
      for (const f of newFiles) {
        if (!selectedFiles.some(sf => sf.name === f.name && sf.size === f.size)) {
          selectedFiles.push(f);
        }
      }
      renderFileList();
    }

    function removeFile(index) {
      selectedFiles.splice(index, 1);
      renderFileList();
    }

    function formatSize(bytes) {
      const units = ['B', 'KB', 'MB', 'GB'];
      let i = 0;
      while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
      return bytes.toFixed(1) + ' ' + units[i];
    }

    function getFileIcon(name) {
      const ext = name.split('.').pop().toLowerCase();
      const map = {
        pdf:'picture_as_pdf',doc:'description',docx:'description',
        xls:'table_chart',xlsx:'table_chart',ppt:'slideshow',pptx:'slideshow',
        txt:'article',md:'article',csv:'article',
        zip:'folder_zip',rar:'folder_zip','7z':'folder_zip',
        mp4:'movie',avi:'movie',mkv:'movie',mov:'movie',
        mp3:'audio_file',wav:'audio_file',
        png:'image',jpg:'image',jpeg:'image',gif:'image',svg:'image',webp:'image',
        py:'code',js:'code',html:'code',css:'code',java:'code',
        json:'data_object',xml:'data_object',
      };
      return map[ext] || 'insert_drive_file';
    }

    function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

    function renderFileList() {
      const total = selectedFiles.reduce((s, f) => s + f.size, 0);
      fileList.innerHTML = selectedFiles.map((f, i) => `
        <div class="file-item">
          <div class="file-item-icon"><span class="material-icons-round">${getFileIcon(f.name)}</span></div>
          <div class="file-item-info">
            <div class="file-item-name">${escapeHtml(f.name)}</div>
            <div class="file-item-size">${formatSize(f.size)}</div>
          </div>
          <button type="button" class="file-item-remove" onclick="removeFile(${i})">
            <span class="material-icons-round" style="font-size:16px">close</span>
          </button>
        </div>`).join('');
      uploadBtn.disabled = selectedFiles.length === 0;
      clearBtn.style.display = selectedFiles.length ? 'inline-flex' : 'none';
      fileCountEl.textContent = selectedFiles.length ? selectedFiles.length + ' file' + (selectedFiles.length > 1 ? 's' : '') + ' \\u00b7 ' + formatSize(total) : '';
    }

    clearBtn.addEventListener('click', () => { selectedFiles = []; renderFileList(); });

    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!selectedFiles.length) return;

      let dur = parseInt(document.getElementById('durationInput').value) || 10;
      dur = Math.max(1, Math.min(1440, dur));

      const form = new FormData();
      for (const f of selectedFiles) form.append('files', f);
      form.append('note', document.getElementById('noteInput').value);
      form.append('duration', dur);

      const progressEl = document.getElementById('uploadProgress');
      const progressFill = document.getElementById('progressFill');
      const progressText = document.getElementById('progressText');
      progressEl.classList.add('active');
      uploadBtn.disabled = true;

      try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');
        xhr.upload.addEventListener('progress', (ev) => {
          if (ev.lengthComputable) {
            const pct = Math.round((ev.loaded / ev.total) * 100);
            progressFill.style.width = pct + '%';
            progressText.textContent = 'Uploading... ' + pct + '%';
          }
        });
        const result = await new Promise((resolve, reject) => {
          xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText));
            else reject(new Error(JSON.parse(xhr.responseText).detail || 'Upload failed'));
          };
          xhr.onerror = () => reject(new Error('Network error'));
          xhr.send(form);
        });
        progressFill.style.width = '100%';
        progressText.textContent = 'Done';
        showResult(result);
        showToast('Files ready to share', 'success');
      } catch (err) {
        progressText.textContent = 'Upload failed';
        showToast(err.message, 'error');
        uploadBtn.disabled = false;
      }
    });

    function showResult(data) {
      document.getElementById('resultSection').classList.add('active');
      document.getElementById('qrImage').src = '/api/qr/' + data.session_id;
      startCountdown(data.expires_at);
      document.getElementById('resultSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    let countdownInterval;
    function startCountdown(expiresAt) {
      clearInterval(countdownInterval);
      const el = document.getElementById('countdownText');
      countdownInterval = setInterval(() => {
        const remaining = Math.max(0, expiresAt - Date.now() / 1000);
        if (remaining <= 0) { el.textContent = 'Session expired'; clearInterval(countdownInterval); return; }
        const m = Math.floor(remaining / 60);
        const s = Math.floor(remaining % 60);
        el.textContent = 'Expires in ' + m + ':' + s.toString().padStart(2, '0');
      }, 1000);
    }
  </script>
</body>
</html>"""


# ── Receive Page (instant QR generation) ─────────────────────────────
_RECEIVE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Receive — filecp</title>
  """ + _SHARED_STYLES + """
  <style>
    .page {
      min-height: calc(100vh - 56px);
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      padding: 40px 24px;
    }
    .receive-card {
      max-width: 420px; width: 100%; text-align: center;
    }
    .receive-card h2 {
      font-size: 1.1rem; font-weight: 700; margin-bottom: 8px;
      letter-spacing: 1px;
    }
    .receive-card p {
      font-size: 0.75rem; color: var(--text-muted); margin-bottom: 28px;
      line-height: 1.6;
    }
    .qr-section {
      display: none; flex-direction: column; align-items: center; gap: 20px;
      animation: fadeInUp 0.5s ease forwards;
    }
    .qr-section.active { display: flex; }
    .qr-section img {
      width: 240px; height: 240px; border-radius: var(--radius-lg);
      border: 1px solid var(--border-color); background: rgba(255,255,255,0.92);
      box-shadow: var(--shadow-md);
    }
    .qr-hint { font-size: 0.75rem; color: var(--text-muted); max-width: 300px; line-height: 1.6; }
    .waiting-status {
      display: flex; align-items: center; gap: 10px;
      padding: 12px 20px; border-radius: var(--radius-md);
      background: var(--bg-surface); border: 1px solid var(--border-color);
      font-size: 0.8rem; color: var(--text-secondary);
    }
    .session-code {
      font-family: var(--display-font); font-size: 1.35rem;
      font-weight: 700; letter-spacing: 0.18em; color: var(--accent);
    }
  </style>
</head>
<body>
  """ + _NAV_INNER + """
  <main class="page">
    <div class="receive-card card animate-in">
      <h2>Receive Files</h2>
      <p>Generate a QR code for the sender to scan and upload files directly to you</p>

      <button class="btn btn-primary btn-lg" style="width:100%" id="genBtn" onclick="createReceiveSession()">
        <span class="material-icons-round">qr_code</span>
        Generate QR Code
      </button>

      <div class="qr-section" id="qrSection">
        <img id="qrImage" src="" alt="QR Code">
        <div class="session-code" id="sessionCode"></div>
        <p class="qr-hint">Show this QR code to the sender. They will scan it and upload files to you.</p>
        <div class="waiting-status" id="waitingStatus">
          <div class="spinner"></div>
          <span>Waiting for files...</span>
        </div>
      </div>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    let sessionId = null;
    let pollInterval = null;

    async function createReceiveSession() {
      const btn = document.getElementById('genBtn');
      btn.disabled = true;
      btn.innerHTML = '<div class="spinner" style="width:18px;height:18px;border-width:2px"></div> Creating session...';
      try {
        const res = await fetch('/api/receive-session', { method: 'POST' });
        if (!res.ok) throw new Error('Failed to create session');
        const data = await res.json();
        sessionId = data.session_id;
        document.getElementById('qrImage').src = '/api/receive-qr/' + sessionId;
        document.getElementById('sessionCode').textContent = sessionId;
        document.getElementById('qrSection').classList.add('active');
        btn.style.display = 'none';
        showToast('QR code generated — waiting for files', 'success');
        startPolling();
      } catch (e) {
        btn.disabled = false;
        btn.innerHTML = '<span class="material-icons-round">qr_code</span> Generate QR Code';
        showToast('Failed to create session', 'error');
      }
    }

    function startPolling() {
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch('/api/session/' + sessionId);
          if (res.ok) {
            const data = await res.json();
            if (data.files && data.files.length > 0) {
              clearInterval(pollInterval);
              document.getElementById('waitingStatus').innerHTML =
                '<span class="material-icons-round" style="color:var(--accent)">check_circle</span> Files received! Redirecting...';
              showToast('Files received!', 'success');
              setTimeout(() => { window.location.href = '/session/' + sessionId; }, 1000);
            }
          }
        } catch (e) {}
      }, 2000);
    }
  </script>
</body>
</html>"""


# ── Send-To Page (upload to an existing receive session) ─────────────
_SEND_TO_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Send Files — filecp</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { padding: 32px 0 64px; }
    .page-header { margin-bottom: 28px; text-align: center; }
    .page-header h1 { font-size: 1.4rem; font-weight: 800; letter-spacing: 1px; }
    .page-header p { color: var(--text-muted); font-size: 0.8rem; margin-top: 4px; }
    .page-header .code { color: var(--accent); font-family: var(--display-font); font-weight: 700; letter-spacing: 0.12em; }

    .drop-zone {
      border: 1px dashed var(--border-light); border-radius: var(--radius-lg);
      padding: 44px 24px; text-align: center; cursor: pointer; transition: all var(--transition);
    }
    .drop-zone:hover, .drop-zone.drag-over { border-color: var(--accent); background: var(--accent-subtle); }
    .drop-zone-icon { font-size: 40px; color: var(--text-muted); margin-bottom: 10px; }
    .drop-zone h3 { font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px; }
    .drop-zone p { font-size: 0.7rem; color: var(--text-muted); }
    .drop-zone input { display: none; }

    .file-list { display: flex; flex-direction: column; gap: 6px; margin-top: 14px; }
    .file-item {
      display: flex; align-items: center; gap: 10px; padding: 10px 14px;
      border-radius: var(--radius-sm); background: var(--bg-secondary); border: 1px solid var(--border-color);
      animation: fadeInUp 0.3s ease forwards;
    }
    .file-item-icon {
      width: 32px; height: 32px; border-radius: 6px; background: var(--accent-subtle); color: var(--text-muted);
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }
    .file-item-icon .material-icons-round { font-size: 16px; }
    .file-item-info { flex: 1; min-width: 0; }
    .file-item-name { font-size: 0.8rem; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .file-item-size { font-size: 0.65rem; color: var(--text-muted); }
    .file-item-remove {
      width: 24px; height: 24px; border-radius: 50%; background: none; border: none;
      color: var(--text-muted); cursor: pointer; display: flex; align-items: center; justify-content: center;
    }
    .file-item-remove:hover { color: var(--text-primary); }

    .upload-actions { margin-top: 22px; display: flex; gap: 12px; align-items: center; }
    .upload-actions .file-count { font-size: 0.75rem; color: var(--text-muted); margin-left: auto; }

    .upload-progress {
      margin-top: 22px; padding: 18px; border-radius: var(--radius-md);
      background: var(--bg-surface); border: 1px solid var(--border-color); display: none;
    }
    .upload-progress.active { display: block; }
    .upload-progress-text { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 8px; }

    .success-section { margin-top: 32px; display: none; text-align: center; }
    .success-section.active { display: block; animation: fadeInUp 0.5s ease forwards; }
    .success-card {
      background: var(--bg-surface); border: 1px solid var(--border-color);
      border-radius: var(--radius-lg); padding: 40px;
      display: flex; flex-direction: column; align-items: center; gap: 12px;
    }
    .success-icon { font-size: 48px; color: var(--accent); }
  </style>
</head>
<body>
  """ + _NAV_INNER + """
  <main class="container page">
    <div class="page-header animate-in">
      <h1>Send Files</h1>
      <p>Upload files to session <span class="code">{{SESSION_ID}}</span></p>
    </div>

    <form id="uploadForm" class="animate-in stagger-1">
      <div class="drop-zone" id="dropZone">
        <span class="material-icons-round drop-zone-icon">cloud_upload</span>
        <h3>Drop files here or click to browse</h3>
        <p>Any file type &middot; Up to 200 MB per file &middot; 500 MB total</p>
        <input type="file" id="fileInput" multiple>
      </div>

      <div class="file-list" id="fileList"></div>

      <div class="upload-actions">
        <button type="submit" class="btn btn-primary" id="uploadBtn" disabled>
          <span class="material-icons-round">send</span> Send Files
        </button>
        <button type="button" class="btn btn-ghost btn-sm" id="clearBtn" style="display:none">Clear All</button>
        <span class="file-count" id="fileCount"></span>
      </div>
    </form>

    <div class="upload-progress" id="uploadProgress">
      <div class="upload-progress-text" id="progressText">Uploading...</div>
      <div class="progress-bar"><div class="progress-bar-fill" id="progressFill" style="width:0%"></div></div>
    </div>

    <div class="success-section" id="successSection">
      <div class="success-card">
        <span class="material-icons-round success-icon">check_circle</span>
        <h2>Files Sent Successfully!</h2>
        <p style="color:var(--text-muted);font-size:0.8rem">The receiver now has your files.</p>
      </div>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID = '{{SESSION_ID}}';
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileList = document.getElementById('fileList');
    const uploadBtn = document.getElementById('uploadBtn');
    const clearBtn = document.getElementById('clearBtn');
    const fileCountEl = document.getElementById('fileCount');
    let selectedFiles = [];

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
      e.preventDefault(); dropZone.classList.remove('drag-over');
      addFiles(Array.from(e.dataTransfer.files));
    });
    fileInput.addEventListener('change', () => { addFiles(Array.from(fileInput.files)); fileInput.value = ''; });

    function addFiles(newFiles) {
      for (const f of newFiles) {
        if (!selectedFiles.some(sf => sf.name === f.name && sf.size === f.size)) selectedFiles.push(f);
      }
      renderFileList();
    }
    function removeFile(index) { selectedFiles.splice(index, 1); renderFileList(); }
    function formatSize(bytes) {
      const units = ['B', 'KB', 'MB', 'GB']; let i = 0;
      while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
      return bytes.toFixed(1) + ' ' + units[i];
    }
    function getFileIcon(name) {
      const ext = name.split('.').pop().toLowerCase();
      const map = {pdf:'picture_as_pdf',doc:'description',docx:'description',xls:'table_chart',xlsx:'table_chart',png:'image',jpg:'image',jpeg:'image',gif:'image',mp4:'movie',mp3:'audio_file',zip:'folder_zip',py:'code',js:'code'};
      return map[ext] || 'insert_drive_file';
    }
    function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

    function renderFileList() {
      const total = selectedFiles.reduce((s, f) => s + f.size, 0);
      fileList.innerHTML = selectedFiles.map((f, i) => `
        <div class="file-item">
          <div class="file-item-icon"><span class="material-icons-round">${getFileIcon(f.name)}</span></div>
          <div class="file-item-info">
            <div class="file-item-name">${escapeHtml(f.name)}</div>
            <div class="file-item-size">${formatSize(f.size)}</div>
          </div>
          <button type="button" class="file-item-remove" onclick="removeFile(${i})">
            <span class="material-icons-round" style="font-size:16px">close</span>
          </button>
        </div>`).join('');
      uploadBtn.disabled = selectedFiles.length === 0;
      clearBtn.style.display = selectedFiles.length ? 'inline-flex' : 'none';
      fileCountEl.textContent = selectedFiles.length ? selectedFiles.length + ' file' + (selectedFiles.length > 1 ? 's' : '') + ' \\u00b7 ' + formatSize(total) : '';
    }
    clearBtn.addEventListener('click', () => { selectedFiles = []; renderFileList(); });

    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!selectedFiles.length) return;
      const form = new FormData();
      for (const f of selectedFiles) form.append('files', f);
      form.append('duration', '10');
      form.append('session_id', SESSION_ID);
      const progressEl = document.getElementById('uploadProgress');
      const progressFill = document.getElementById('progressFill');
      const progressText = document.getElementById('progressText');
      progressEl.classList.add('active');
      uploadBtn.disabled = true;
      try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');
        xhr.upload.addEventListener('progress', (ev) => {
          if (ev.lengthComputable) {
            const pct = Math.round((ev.loaded / ev.total) * 100);
            progressFill.style.width = pct + '%';
            progressText.textContent = 'Uploading... ' + pct + '%';
          }
        });
        await new Promise((resolve, reject) => {
          xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText));
            else reject(new Error(JSON.parse(xhr.responseText).detail || 'Upload failed'));
          };
          xhr.onerror = () => reject(new Error('Network error'));
          xhr.send(form);
        });
        progressFill.style.width = '100%';
        progressText.textContent = 'Done';
        document.getElementById('uploadForm').style.display = 'none';
        document.getElementById('successSection').classList.add('active');
        showToast('Files sent successfully!', 'success');
      } catch (err) {
        progressText.textContent = 'Upload failed';
        showToast(err.message, 'error');
        uploadBtn.disabled = false;
      }
    });
  </script>
</body>
</html>"""


# ── Session Page (file download) ────────────────────────────────────
_SESSION_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Session — filecp</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { padding: 32px 0 64px; }

    .loading-state {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      min-height: 50vh; gap: 16px;
    }
    .loading-state p { color: var(--text-muted); font-size: 0.85rem; }

    .error-state {
      display: none; flex-direction: column; align-items: center; justify-content: center;
      min-height: 50vh; gap: 14px; text-align: center;
    }
    .error-state.active { display: flex; }
    .error-state h2 { font-size: 1.1rem; font-weight: 700; }
    .error-state p { color: var(--text-muted); font-size: 0.8rem; max-width: 360px; }

    .session-content { display: none; }
    .session-content.active { display: block; animation: fadeInUp 0.5s ease forwards; }

    .session-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 20px; flex-wrap: wrap; gap: 10px;
    }
    .session-header h1 { font-size: 1.2rem; font-weight: 800; letter-spacing: 1px; }

    .note-box {
      padding: 14px 18px; border-radius: var(--radius-md);
      background: var(--bg-surface); border: 1px solid var(--border-color);
      margin-bottom: 18px; display: flex; align-items: flex-start; gap: 10px;
    }
    .note-box .material-icons-round { color: var(--text-muted); font-size: 18px; margin-top: 2px; flex-shrink: 0; }
    .note-box p { font-size: 0.8rem; color: var(--text-secondary); line-height: 1.6; word-break: break-word; }

    .files-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 10px; margin-bottom: 20px;
    }
    .file-card {
      display: flex; align-items: center; gap: 12px;
      padding: 14px; border-radius: var(--radius-md);
      background: var(--bg-surface); border: 1px solid var(--border-color);
      transition: all var(--transition); cursor: pointer;
    }
    .file-card:hover {
      border-color: var(--border-light); background: var(--bg-surface-hover);
    }
    .file-card-icon {
      width: 38px; height: 38px; border-radius: 8px;
      background: var(--accent-subtle); color: var(--text-muted);
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }
    .file-card-icon .material-icons-round { font-size: 18px; }
    .file-card-info { flex: 1; min-width: 0; }
    .file-card-name { font-size: 0.8rem; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .file-card-size { font-size: 0.65rem; color: var(--text-muted); margin-top: 2px; }
    .file-card-dl {
      width: 32px; height: 32px; border-radius: 50%;
      background: var(--accent-subtle); color: var(--text-secondary);
      display: flex; align-items: center; justify-content: center;
      border: none; cursor: pointer; transition: all var(--transition); flex-shrink: 0;
    }
    .file-card-dl:hover { background: var(--text-secondary); color: var(--bg-primary); }

    .image-preview {
      border-radius: var(--radius-sm); max-width: 100%; max-height: 180px;
      object-fit: cover; margin-top: 8px; cursor: pointer;
    }

    .modal-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.9);
      z-index: 1000; display: none; align-items: center; justify-content: center;
      padding: 24px; cursor: pointer;
    }
    .modal-overlay.active { display: flex; animation: fadeIn 0.2s ease; }
    .modal-overlay img { max-width: 90vw; max-height: 90vh; border-radius: var(--radius-md); object-fit: contain; }
  </style>
</head>
<body>
  """ + _NAV_INNER + """
  <main class="container page">
    <div class="loading-state" id="loadingState">
      <div class="spinner spinner-lg"></div>
      <p>Loading session...</p>
    </div>

    <div class="error-state" id="errorState">
      <span class="material-icons-round" style="font-size:40px;color:var(--text-muted)">error_outline</span>
      <h2 id="errorTitle">Session Not Found</h2>
      <p id="errorText">This session may have expired or doesn't exist.</p>
      <a href="/receive" class="btn btn-outline" style="margin-top:8px">
        <span class="material-icons-round">arrow_back</span> Try Another
      </a>
    </div>

    <div class="session-content" id="sessionContent">
      <div class="session-header">
        <h1 id="sessionTitle">Files</h1>
        <div style="display:flex;gap:8px;flex-wrap:wrap;" id="headerMeta"></div>
      </div>
      <div id="noteContainer"></div>
      <div class="files-grid" id="filesGrid"></div>
      <button class="btn btn-primary" onclick="downloadAll()">
        <span class="material-icons-round">archive</span> Download All
      </button>
    </div>
  </main>

  <div class="modal-overlay" id="imageModal" onclick="this.classList.remove('active')">
    <img id="modalImage" src="" alt="Preview">
  </div>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID = window.location.pathname.split('/').pop().toUpperCase();

    async function loadSession() {
      try {
        const res = await fetch('/api/session/' + SESSION_ID);
        if (!res.ok) {
          const err = await res.json();
          showError(res.status === 410 ? 'Session Expired' : 'Session Not Found',
                    err.detail || 'This session may have expired or does not exist.');
          return;
        }
        renderSession(await res.json());
      } catch (e) {
        showError('Connection Error', 'Could not connect to the server.');
      }
    }

    function showError(title, text) {
      document.getElementById('loadingState').style.display = 'none';
      document.getElementById('errorTitle').textContent = title;
      document.getElementById('errorText').textContent = text;
      document.getElementById('errorState').classList.add('active');
    }

    function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

    function renderSession(data) {
      document.getElementById('loadingState').style.display = 'none';
      document.getElementById('sessionContent').classList.add('active');

      const n = data.files.length;
      document.getElementById('sessionTitle').textContent = n + ' File' + (n > 1 ? 's' : '') + ' Shared';

      const meta = document.getElementById('headerMeta');
      const remaining = Math.max(0, data.remaining_seconds);
      const m = Math.floor(remaining / 60), s = Math.floor(remaining % 60);
      meta.innerHTML =
        '<span class="chip"><span class="material-icons-round">data_usage</span>' + data.total_size_formatted + '</span>' +
        '<span class="chip"><span class="material-icons-round">timer</span><span id="liveCountdown">' + m + ':' + s.toString().padStart(2,'0') + '</span></span>';

      if (data.note) {
        document.getElementById('noteContainer').innerHTML =
          '<div class="note-box"><span class="material-icons-round">sticky_note_2</span><p>' + escapeHtml(data.note) + '</p></div>';
      }

      const grid = document.getElementById('filesGrid');
      grid.innerHTML = data.files.map(f => {
        let preview = '';
        if (f.is_image) {
          preview = '<img class="image-preview" src="/api/preview/' + SESSION_ID + '/' + encodeURIComponent(f.name) + '" alt="' + escapeHtml(f.name) + '" onclick="event.stopPropagation();openPreview(this.src)" loading="lazy">';
        } else if (f.is_pdf) {
          preview = '<div style="margin-top:8px"><a href="/api/preview/' + SESSION_ID + '/' + encodeURIComponent(f.name) + '" target="_blank" class="btn btn-ghost btn-sm" onclick="event.stopPropagation()" style="font-size:0.7rem"><span class="material-icons-round" style="font-size:14px">picture_as_pdf</span> Preview PDF</a></div>';
        }
        return '<div class="file-card" onclick="dlFile(\\'' + encodeURIComponent(f.name) + '\\')">' +
          '<div class="file-card-icon"><span class="material-icons-round">' + f.icon + '</span></div>' +
          '<div class="file-card-info"><div class="file-card-name" title="' + escapeHtml(f.original_name) + '">' + escapeHtml(f.original_name) + '</div>' +
          '<div class="file-card-size">' + f.size_formatted + '</div>' + preview + '</div>' +
          '<button class="file-card-dl" onclick="event.stopPropagation();dlFile(\\'' + encodeURIComponent(f.name) + '\\')" title="Download">' +
          '<span class="material-icons-round" style="font-size:16px">download</span></button></div>';
      }).join('');

      startLive(data.expires_at);
    }

    async function dlFile(fn) {
      try {
        const res = await fetch('/api/download/' + SESSION_ID + '/' + fn);
        if (!res.ok) throw new Error('Download failed');
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = decodeURIComponent(fn);
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch(e) { showToast('Download failed', 'error'); }
    }
    async function downloadAll() {
      try {
        const res = await fetch('/api/download-all/' + SESSION_ID);
        if (!res.ok) throw new Error('Download failed');
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'filecp_' + SESSION_ID + '.zip';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch(e) { showToast('Download failed', 'error'); }
    }
    function openPreview(src) { document.getElementById('modalImage').src = src; document.getElementById('imageModal').classList.add('active'); }

    let liveInterval;
    function startLive(expiresAt) {
      const el = document.getElementById('liveCountdown');
      if (!el) return;
      liveInterval = setInterval(() => {
        const r = Math.max(0, expiresAt - Date.now() / 1000);
        if (r <= 0) { el.textContent = 'Expired'; clearInterval(liveInterval); return; }
        el.textContent = Math.floor(r / 60) + ':' + Math.floor(r % 60).toString().padStart(2, '0');
      }, 1000);
    }

    loadSession();
  </script>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────
# Page Routes
# ──────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def page_welcome():
    return _WELCOME_PAGE


@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard():
    return _DASHBOARD_PAGE


@app.get("/send", response_class=HTMLResponse)
async def page_send():
    return _SEND_PAGE


@app.get("/receive", response_class=HTMLResponse)
async def page_receive():
    return _RECEIVE_PAGE


@app.get("/send-to/{session_id}", response_class=HTMLResponse)
async def page_send_to(session_id: str):
    sid = session_id.upper().strip()
    return _SEND_TO_PAGE.replace("{{SESSION_ID}}", sid)


@app.get("/session/{session_id}", response_class=HTMLResponse)
async def page_session(session_id: str):
    return _SESSION_PAGE


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    url = RENDER_EXTERNAL_URL or f"http://localhost:{PORT}"
    print(f"\n  {APP_NAME} v{APP_VERSION}")
    print(f"  {url}\n")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
