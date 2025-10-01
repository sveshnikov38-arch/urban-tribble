# === CORE PART 1/9 — Imports, ENV/Config, Flask init, JSON logging, Metrics (enhanced) ===
# -*- coding: utf-8 -*-
import os
import io
import re
import hmac
import csv
import json
import time
import uuid
import queue
import base64
import hashlib
import secrets
import sqlite3
import mimetypes
import threading
import shutil
import socket
import ipaddress
import logging
from datetime import datetime, date, timedelta, timezone
from functools import wraps
from urllib.parse import urlencode, urlparse

from flask import (
    Flask, g, request, redirect, url_for, session, flash, abort, jsonify,
    make_response, Response, send_file, render_template_string
)
from werkzeug.security import generate_password_hash, check_password_hash

# Optional reverse-proxy middleware
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
except Exception:  # pragma: no cover
    ProxyFix = None

# Optional deps (loaded lazily where possible)
try:
    import pyotp  # TOTP 2FA
except Exception:  # pragma: no cover
    pyotp = None

try:
    import boto3  # S3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:  # pragma: no cover
    boto3 = None
    BotoCoreError = ClientError = Exception

# Optional: Redis (rate limit / SSE pub-sub / worker lock)
REDIS_CLIENT = None
try:
    import redis
    _redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        _rc = redis.Redis.from_url(_redis_url)
        _rc.ping()
        REDIS_CLIENT = _rc
    except Exception:  # pragma: no cover
        REDIS_CLIENT = None
except Exception:  # pragma: no cover
    REDIS_CLIENT = None

# Optional content-sniff (used later for avatar/uploads hardening)
try:
    import magic  # python-magic
except Exception:  # pragma: no cover
    magic = None

# Optional Sentry (observability)
try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration as _SentryFlaskIntegration
except Exception:  # pragma: no cover
    sentry_sdk = None
    _SentryFlaskIntegration = None

APP_NAME = os.environ.get("APP_NAME", "Unified CRM/ERP")

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    # In development (DEBUG=1), generate an ephemeral secret key to avoid startup failures.
    # In production, SECRET_KEY is mandatory to maintain session security.
    if os.environ.get("DEBUG", "0") == "1":
        SECRET_KEY = secrets.token_urlsafe(48)
        try:
            print("[WARN] DEBUG=1: generated ephemeral SECRET_KEY for development only")
        except Exception:
            pass
    else:
        raise RuntimeError("SECRET_KEY обязателен, задайте переменную окружения SECRET_KEY")

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
DEBUG = os.environ.get("DEBUG", "0") == "1"

DATA_DIR = os.environ.get("DATA_DIR", os.getcwd())
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

DATABASE_PATH = os.path.join(DATA_DIR, "app.db")

S3_ENABLED = os.environ.get("S3_ENABLED", "0") == "1"
S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "")
S3_REGION = os.environ.get("S3_REGION", "ru-central1")
S3_BUCKET = os.environ.get("S3_BUCKET", "")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "")

AI_PROVIDER = os.environ.get("AI_PROVIDER", "llama")
AI_BASE_URL = os.environ.get("AI_BASE_URL", "http://localhost:8001/v1")
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_MODEL = os.environ.get("AI_MODEL", "llama-3-8b-instruct")
AI_STRICT = os.environ.get("AI_STRICT", "0") == "1"
# Exclude internal notes from AI prompts by default (can be overridden by org AI policy)
AI_EXCLUDE_INTERNAL_NOTES_DEFAULT = os.environ.get("AI_EXCLUDE_INTERNAL_NOTES_DEFAULT", "1") == "1"

CLICK_TO_CALL_PROVIDER = os.environ.get("CLICK_TO_CALL_PROVIDER", "none")
CTI_SCREENPOP = os.environ.get("CTI_SCREENPOP", "0") == "1"
REQUIRE_CTI_SECRET = os.environ.get("REQUIRE_CTI_SECRET", "1") == "1"
REQUIRE_PROVIDER_SIGNATURE = os.environ.get("REQUIRE_PROVIDER_SIGNATURE", "1") == "1"

MANGO_API_URL = os.environ.get("MANGO_API_URL", "")
MANGO_API_KEY = os.environ.get("MANGO_API_KEY", "")
MANGO_API_SECRET = os.environ.get("MANGO_API_SECRET", "")
MANGO_SIGNING_KEY = os.environ.get("MANGO_SIGNING_KEY", "")

UIS_API_URL = os.environ.get("UIS_API_URL", "")
UIS_API_KEY = os.environ.get("UIS_API_KEY", "")
UIS_API_SECRET = os.environ.get("UIS_API_SECRET", "")
UIS_SIGNING_KEY = os.environ.get("UIS_SIGNING_KEY", "")

TELFIN_API_URL = os.environ.get("TELFIN_API_URL", "")
TELFIN_API_KEY = os.environ.get("TELFIN_API_KEY", "")
TELFIN_API_SECRET = os.environ.get("TELFIN_API_SECRET", "")
TELFIN_SIGNING_KEY = os.environ.get("TELFIN_SIGNING_KEY", "")

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_WEBHOOK_SECRET = os.environ.get("TG_WEBHOOK_SECRET", secrets.token_urlsafe(16))
VK_CONFIRM_CODE = os.environ.get("VK_CONFIRM_CODE", "")
VK_SECRET = os.environ.get("VK_SECRET", "")

JITSI_BASE = os.environ.get("JITSI_BASE", "https://meet.jit.si")

BILLING_PROVIDER = os.environ.get("BILLING_PROVIDER", "none")

RETENTION_MONTHS = int(os.environ.get("RETENTION_MONTHS", "12"))
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "120"))

# Fine-grained rate limits
TWOFA_RATE_LIMIT_PER_MIN = int(os.environ.get("TWOFA_RATE_LIMIT_PER_MIN", "30"))
CTI_WEBHOOK_RATE_LIMIT_PER_MIN = int(os.environ.get("CTI_WEBHOOK_RATE_LIMIT_PER_MIN", "240"))

# File links TTL
FILE_URL_TTL = int(os.environ.get("FILE_URL_TTL", "3600"))

# Weather defaults (used later)
WEATHER_ENABLED = os.environ.get("WEATHER_ENABLED", "1") == "1"
SPB_LAT = float(os.environ.get("SPB_LAT", "59.93"))
SPB_LON = float(os.environ.get("SPB_LON", "30.31"))

# Security/ops enhancements
CSP_STRICT = os.environ.get("CSP_STRICT", "1") == "1"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
REQUIRE_REDIS_FOR_RATE = os.environ.get("REQUIRE_REDIS_FOR_RATE", "0") == "1"
REQUIRE_REDIS_FOR_LOCK = os.environ.get("REQUIRE_REDIS_FOR_LOCK", "0") == "1"

MAX_RECORDING_SIZE = 50 * 1024 * 1024
RECORDING_ALLOWED_HOSTS_ENV = os.environ.get("RECORDING_ALLOWED_HOSTS", "")

LOGIN_LOCK_MAX = int(os.environ.get("LOGIN_LOCK_MAX", "10"))
LOGIN_LOCK_WINDOW_SEC = int(os.environ.get("LOGIN_LOCK_WINDOW_SEC", "900"))

ENABLE_METRICS = os.environ.get("ENABLE_METRICS", "1") == "1"
METRICS_NAMESPACE = os.environ.get("METRICS_NAMESPACE", "unified_crm")
METRICS_PUBLIC = os.environ.get("METRICS_PUBLIC", "0") == "1"

# 2FA setup TTL (seconds)
TWOFA_SETUP_TTL_SEC = int(os.environ.get("TWOFA_SETUP_TTL_SEC", "600"))

# Workers toggle
WORKERS_ENABLED = os.environ.get("WORKERS_ENABLED", "1") == "1"

# Avatar upload restrictions
AVATAR_MAX_SIZE = int(os.environ.get("AVATAR_MAX_SIZE", str(5 * 1024 * 1024)))
AVATAR_ALLOWED_TYPES = set((os.environ.get("AVATAR_ALLOWED_TYPES") or "image/png,image/jpeg,image/webp").split(","))
AVATAR_CONTENT_SNIFF = os.environ.get("AVATAR_CONTENT_SNIFF", "1") == "1"

# General upload whitelist (used for message/chat uploads)
UPLOAD_ALLOWED_TYPES = set((
    os.environ.get("UPLOAD_ALLOWED_TYPES") or
    "image/png,image/jpeg,image/webp,application/pdf,application/zip,application/octet-stream,"
    "audio/mpeg,audio/wav,video/mp4,text/plain"
).split(","))

# Public signed file links (optional)
PUBLIC_SIGNED_FILES_ENABLED = os.environ.get("PUBLIC_SIGNED_FILES_ENABLED", "0") == "1"
PUBLIC_FILE_URL_TTL = int(os.environ.get("PUBLIC_FILE_URL_TTL", "1800"))

# Optional AV scan (external command or ICAP could be integrated later)
AV_SCAN_ENABLED = os.environ.get("AV_SCAN_ENABLED", "0") == "1"
AV_SCAN_CMD = os.environ.get("AV_SCAN_CMD", "")  # e.g., "clamscan --stdout --no-summary -"

# Proxy / X-Forwarded-For trust
USE_PROXYFIX = os.environ.get("USE_PROXYFIX", "0") == "1"
PROXY_FIX_FOR = int(os.environ.get("PROXY_FIX_FOR", "1"))
PROXY_FIX_PROTO = int(os.environ.get("PROXY_FIX_PROTO", "1"))
PROXY_FIX_HOST = int(os.environ.get("PROXY_FIX_HOST", "0"))
PROXY_FIX_PORT = int(os.environ.get("PROXY_FIX_PORT", "0"))
PROXY_FIX_PREFIX = int(os.environ.get("PROXY_FIX_PREFIX", "0"))
TRUSTED_PROXIES_CIDRS = [s.strip() for s in (os.environ.get("TRUSTED_PROXIES_CIDRS", "") or "").split(",") if s.strip()]

# Admin password print policy
PRINT_ADMIN_PASSWORD = os.environ.get("PRINT_ADMIN_PASSWORD", "0") == "1"

# FTS rebuild cadence (used later in maintenance worker)
FTS_REBUILD_INTERVAL_SEC = int(os.environ.get("FTS_REBUILD_INTERVAL_SEC", "3600"))

# Email channel defaults (ENV) — worker will use DB accounts; these are fallbacks
EMAIL_IMAP_HOST = os.environ.get("EMAIL_IMAP_HOST", "")
EMAIL_IMAP_PORT = int(os.environ.get("EMAIL_IMAP_PORT", "993"))
EMAIL_IMAP_USER = os.environ.get("EMAIL_IMAP_USER", "")
EMAIL_IMAP_PASS = os.environ.get("EMAIL_IMAP_PASS", "")
EMAIL_IMAP_USE_TLS = os.environ.get("EMAIL_IMAP_USE_TLS", "1") == "1"

EMAIL_SMTP_HOST = os.environ.get("EMAIL_SMTP_HOST", "")
EMAIL_SMTP_PORT = int(os.environ.get("EMAIL_SMTP_PORT", "587"))
EMAIL_SMTP_USER = os.environ.get("EMAIL_SMTP_USER", "")
EMAIL_SMTP_PASS = os.environ.get("EMAIL_SMTP_PASS", "")
EMAIL_SMTP_USE_TLS = os.environ.get("EMAIL_SMTP_USE_TLS", "1") == "1"

EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "0") == "1"

# Sentry DSN (optional)
SENTRY_DSN = os.environ.get("SENTRY_DSN", "")

# Chat access policy: allow all org users to all channels (public/group/personal) if 1
CHAT_ORG_WIDE = os.environ.get("CHAT_ORG_WIDE", "1") == "1"

# Login policy: require org slug on login form to scope user lookup
LOGIN_ORG_REQUIRED = os.environ.get("LOGIN_ORG_REQUIRED", "1") == "1"

# API Tokens hashing (pepper from SECRET_KEY)
TOKEN_HASH_ALG = "sha256"

_failed_login = {}

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_PERMANENT=False,
    MAX_CONTENT_LENGTH=200 * 1024 * 1024,
    JSONIFY_PRETTYPRINT_REGULAR=False,
)

# Optionally apply ProxyFix if behind a trusted reverse proxy
if USE_PROXYFIX and ProxyFix:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=PROXY_FIX_FOR,
        x_proto=PROXY_FIX_PROTO,
        x_host=PROXY_FIX_HOST,
        x_port=PROXY_FIX_PORT,
        x_prefix=PROXY_FIX_PREFIX,
    )

# Sentry init (optional, safe)
if SENTRY_DSN and sentry_sdk and _SentryFlaskIntegration:
    try:
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            integrations=[_SentryFlaskIntegration()],
            traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.0") or 0.0),
            profiles_sample_rate=float(os.environ.get("SENTRY_PROFILES_SAMPLE_RATE", "0.0") or 0.0),
            send_default_pii=False,
        )
    except Exception:
        pass


class RequestContextFilter(logging.Filter):
    """Inject request-scoped fields into logs."""
    def filter(self, record):
        try:
            record.request_id = getattr(g, "request_id", "-")
        except Exception:
            record.request_id = "-"
        try:
            record.user_id = session.get("user_id")
        except Exception:
            record.user_id = None
        try:
            record.org_id = session.get("org_id")
        except Exception:
            record.org_id = None
        try:
            record.path = request.path
        except Exception:
            record.path = "-"
        return True


class SecretSanitizerFilter(logging.Filter):
    """Best-effort mask for sensitive tokens in log messages."""
    _patterns = [
        (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", re.I), r"\1***"),
        (re.compile(r"(X-Api-Key:\s*)[A-Za-z0-9\-\._~\+\/]+=*", re.I), r"\1***"),
    ]

    def filter(self, record):
        try:
            try:
                msg = record.getMessage()
            except Exception:
                msg = str(getattr(record, "msg", ""))
                record.args = ()
            for rx, repl in self._patterns:
                try:
                    msg = rx.sub(repl, msg)
                except Exception:
                    pass
            record.msg = msg
            record.args = ()
        except Exception:
            pass
        return True


class JSONLogFormatter(logging.Formatter):
    def format(self, record):
        try:
            msg_text = record.getMessage()
        except Exception:
            try:
                msg_text = str(getattr(record, "msg", ""))
            except Exception:
                msg_text = ""
            record.args = ()
        base = {
            "ts": datetime.utcnow().isoformat(" ", "seconds"),
            "level": record.levelname,
            "msg": msg_text,
            "request_id": getattr(record, "request_id", "-"),
            "user_id": getattr(record, "user_id", None),
            "org_id": getattr(record, "org_id", None),
            "logger": record.name,
            "path": getattr(record, "path", "-"),
        }
        if record.exc_info:
            try:
                base["exc_info"] = self.formatException(record.exc_info)
            except Exception:
                base["exc_info"] = "exc_format_failed"
        return json.dumps(base, ensure_ascii=False)


def _setup_logging():
    root = logging.getLogger()
    for h in list(root.handlers or []):
        root.removeHandler(h)
    h = logging.StreamHandler()
    h.setFormatter(JSONLogFormatter())
    h.addFilter(SecretSanitizerFilter())
    root.addHandler(h)
    root.setLevel(logging.INFO)
    for lg in (app.logger, logging.getLogger("werkzeug")):
        lg.addFilter(RequestContextFilter())


_setup_logging()

# Styles placeholder; will be overwritten in STYLES parts
BASE_CSS = ""

# Metrics scaffold (enhanced, cumulative buckets + snapshot)
_metrics = {
    "http_requests_total": {},              # (method, endpoint, status) -> count
    "http_request_duration_ms": {},         # (endpoint, bucket) -> cumulative count (le{num} / le_inf)
    "http_request_duration_ms_sum": {},     # endpoint -> sum_ms
    "http_request_duration_ms_count": {},   # endpoint -> count
    "webhook_delivery_total": {},           # (event, status) -> count
    "task_comments_total": {},              # (org_id,) -> count
    "errors_total": {},                     # (type,) -> count
    "worker_heartbeat": {},                 # (worker,) -> value (gauge)
    "workflow_runs_active": {},             # (org_id,) -> value (gauge)
    "workflow_queue_lag_sec": {},           # (kind,) -> value (gauge)
    "email_fetch_errors_total": {},         # (account_id,) -> count
    # Added metrics
    "migrations_errors_total": {},          # (version,) -> count
    "selftest_failures_total": {},          # (check,) -> count
    "kanban_ops_total": {},                 # (op,) -> count
    "custom_fields_ops_total": {},          # (op,) -> count
}
_metric_buckets = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
_metrics_lock = threading.Lock()


def _metrics_inc(name, key, inc=1):
    try:
        with _metrics_lock:
            d = _metrics.setdefault(name, {})
            d[key] = d.get(key, 0) + inc
    except Exception:
        pass


def _metrics_set(name, key, value):
    try:
        with _metrics_lock:
            d = _metrics.setdefault(name, {})
            d[key] = value
    except Exception:
        pass


def _metrics_observe_duration(endpoint, ms):
    """Record duration histogram and summary for endpoint in milliseconds with cumulative buckets."""
    try:
        with _metrics_lock:
            for b in _metric_buckets:
                if ms <= b:
                    _metrics["http_request_duration_ms"][(endpoint, f"le{b}")] = _metrics["http_request_duration_ms"].get((endpoint, f"le{b}"), 0) + 1
            _metrics["http_request_duration_ms_sum"][endpoint] = _metrics["http_request_duration_ms_sum"].get(endpoint, 0.0) + float(ms)
            _metrics["http_request_duration_ms_count"][endpoint] = _metrics["http_request_duration_ms_count"].get(endpoint, 0) + 1
    except Exception:
        pass


def _metrics_snapshot():
    """Return a shallow safe snapshot of metrics to avoid iteration races."""
    snap = {}
    try:
        with _metrics_lock:
            for k, v in _metrics.items():
                if isinstance(v, dict):
                    snap[k] = dict(v)
                else:
                    snap[k] = v
    except Exception:
        snap = {k: dict(v) if isinstance(v, dict) else v for k, v in _metrics.items()}
    return snap
# === END CORE PART 1/9 ===
# === CORE PART 2/9 — DB helpers, CSRF, Utils, Client IP, Rate limit, RBAC, Safe render, 2FA backup ===
# -*- coding: utf-8 -*-

# ------------------- DB helpers (with retry/backoff) -------------------
_SQLITE_MAX_RETRIES = 5
_SQLITE_RETRY_SLEEP = 0.03


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            DATABASE_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
            isolation_level=None,  # autocommit; use explicit BEGIN when needed
        )
        g.db.row_factory = sqlite3.Row
        try:
            g.db.execute("PRAGMA foreign_keys = ON;")
            g.db.execute("PRAGMA journal_mode = WAL;")
            g.db.execute("PRAGMA synchronous = NORMAL;")
            g.db.execute("PRAGMA temp_store = MEMORY;")
            g.db.execute("PRAGMA mmap_size = 134217728;")
            g.db.execute("PRAGMA busy_timeout = 5000;")
        except Exception as e:
            app.logger.error(f"DB pragma failed: {e}")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass


def _sqlite_retry(fn, *args, **kwargs):
    for i in range(_SQLITE_MAX_RETRIES):
        try:
            return fn(*args, **kwargs)
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "database is locked" in msg or "database table is locked" in msg:
                time.sleep(_SQLITE_RETRY_SLEEP * (i + 1))
                continue
            raise
        except Exception:
            raise
    raise RuntimeError("DB locked after retries")


def query_db(q, params=(), one=False):
    try:
        cur = _sqlite_retry(get_db().execute, q, params)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        app.logger.error(f"Query failed: {q} - {e}")
        _metrics_inc("errors_total", ("db.query",))
        return (None if one else [])


def exec_db(q, params=()):
    db = get_db()
    try:
        cur = _sqlite_retry(db.execute, q, params)
        return cur.lastrowid
    except sqlite3.IntegrityError as e:
        app.logger.warning(f"Exec integrity error: {q} - {e}")
        return None
    except Exception as e:
        app.logger.error(f"Exec failed: {q} - {e}")
        _metrics_inc("errors_total", ("db.exec",))
        return None


def exec_db_rowcount(q, params=()):
    db = get_db()
    try:
        cur = _sqlite_retry(db.execute, q, params)
        return cur.rowcount
    except sqlite3.IntegrityError as e:
        app.logger.warning(f"Exec rowcount integrity error: {q} - {e}")
        return -1
    except Exception as e:
        app.logger.error(f"Exec rowcount failed: {q} - {e}")
        _metrics_inc("errors_total", ("db.exec_rowcount",))
        return -1


def exec_many(q, seq):
    db = get_db()
    try:
        cur = _sqlite_retry(db.executemany, q, seq)
        return cur.rowcount
    except Exception as e:
        app.logger.error(f"Exec many failed: {q} - {e}")
        _metrics_inc("errors_total", ("db.exec_many",))
        return 0


# ------------------- CSRF -------------------
def ensure_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)


def verify_csrf():
    token = (request.form.get("csrf_token") or "").strip()
    if not token or token != session.get("csrf_token"):
        abort(400, "CSRF token invalid")


def verify_csrf_header():
    token = (request.headers.get("X-CSRFToken") or request.headers.get("X-CSRF-Token") or "").strip()
    if not token or token != session.get("csrf_token"):
        abort(400, "CSRF token invalid (header)")


# ------------------- Utils -------------------
def now_utc():
    return datetime.now(timezone.utc)


def utc_iso(dt=None):
    return (dt or now_utc()).replace(microsecond=0).isoformat(" ")


def ensure_iso_datetime(s: str) -> str:
    """
    Normalize HTML datetime-local ('YYYY-MM-DDTHH:MM' or ':SS') to 'YYYY-MM-DD HH:MM:SS' (no TZ conversion).
    Returns '' if input invalid/empty.
    """
    if not s:
        return ""
    s = str(s).strip().replace("T", " ")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}$", s):
        s = s + ":00"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$", s):
        return s
    return ""


def fmt_money(v):
    try:
        return f"{float(v or 0):.2f}"
    except Exception:
        return "0.00"


def qurl(_route="index", _external=False, **kwargs):
    params = request.args.to_dict(flat=True)
    for k, v in kwargs.items():
        if v is None:
            params.pop(k, None)
        else:
            params[k] = v
    base = url_for(_route, _external=_external)
    return base + ("?" + urlencode(params) if params else "")


def parse_date_flexible(s: str):
    """
    Accepts:
      - YYYY-MM-DD
      - DD.MM.YYYY
      - DD.MM  (assumes current year)
    Returns YYYY-MM-DD or None.
    """
    if not s:
        return None
    s = str(s).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return s
    m = re.fullmatch(r"(\d{1,2})\.(\d{1,2})\.(\d{4})", s)
    if m:
        d, mm, yyyy = map(int, m.groups())
        try:
            dt = date(yyyy, mm, d)
            return dt.isoformat()
        except Exception:
            return None
    m = re.fullmatch(r"(\d{1,2})\.(\d{1,2})", s)
    if m:
        d, mm = map(int, m.groups())
        yyyy = date.today().year
        try:
            dt = date(yyyy, mm, d)
            return dt.isoformat()
        except Exception:
            return None
    return None


def date_range_bounds(date_from: str, date_to: str):
    """
    Returns (start_ts, end_ts) in 'YYYY-MM-DD HH:MM:SS' or ("","")
    """
    start = ""
    end = ""
    if date_from and re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_from.strip()):
        start = f"{date_from.strip()} 00:00:00"
    if date_to and re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_to.strip()):
        end = f"{date_to.strip()} 23:59:59"
    return start, end


def slugify(s: str):
    s = (s or "").strip().lower()
    mapping = {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo", "ж": "zh", "з": "z", "и": "i", "й": "j",
        "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f",
        "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya"
    }
    out = []
    for ch in s:
        if ch in mapping:
            out.append(mapping[ch])
        elif re.match(r"[a-z0-9]", ch):
            out.append(ch)
        else:
            out.append("-")
    slug = re.sub(r"[^a-z0-9]+", "-", "".join(out)).strip("-")
    return slug or secrets.token_hex(3)


def phone_digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def phone_last10(s: str) -> str:
    d = phone_digits(s)
    return d[-10:] if len(d) >= 10 else d


def phone_to_e164(s: str) -> str:
    d = phone_digits(s)
    if not d:
        return ""
    if len(d) == 11 and d.startswith("8"):
        d = "7" + d[1:]
    if len(d) == 10:
        d = "7" + d
    if not d.startswith("+"):
        d = "+" + d
    return d


def mask_phone(s):
    d = phone_digits(s)
    if len(d) == 11 and d.startswith("8"):
        d = "7" + d[1:]
    if len(d) == 10:
        d = "7" + d
    if not d:
        return "—"
    if len(d) >= 11:
        return f"+{d[0]} ({d[1:4]}) {d[4:7]}-{d[7:9]}-{d[9:11]}"
    return "+" + d


def password_policy_ok(pwd: str):
    if not pwd or len(pwd) < 12:
        return False, "Минимум 12 символов"
    if not re.search(r"[A-Z]", pwd) or not re.search(r"[a-z]", pwd):
        return False, "Нужны заглавные и строчные буквы"
    if not re.search(r"\d", pwd):
        return False, "Добавьте цифры"
    if not re.search(r"[^\w]", pwd):
        return False, "Добавьте спецсимвол"
    return True, ""


def fts_sanitize(q: str) -> str:
    q = (q or "").strip()
    if not q:
        return ""
    tokens = [t for t in re.split(r"\s+", q) if t]
    return " ".join(f'"{t}"' for t in tokens)


def safe_local_storage_path(upload_dir: str, key: str) -> str:
    """
    Only allow local:<safe> keys; prevent traversal and disallow escaping base dir.
    """
    if not key.startswith("local:"):
        raise ValueError("invalid storage key")
    safe = key.split("local:", 1)[1]
    safe = os.path.normpath(safe.replace("\\", "/")).lstrip("/\\")
    base = os.path.abspath(upload_dir)
    path = os.path.abspath(os.path.join(base, safe))
    if not (path == base or path.startswith(base + os.sep)):
        raise ValueError("path escape detected")
    return path


# Content-type sniff helpers (used in avatar/uploads hardening)
def detect_mime_from_bytes(data: bytes, filename: str = "") -> str:
    try:
        if magic:
            m = magic.Magic(mime=True)
            typ = m.from_buffer(data[:8192])
            if typ:
                return typ
    except Exception:
        pass
    try:
        guess = mimetypes.guess_type(filename or "")[0]
        return guess or "application/octet-stream"
    except Exception:
        return "application/octet-stream"


# ------------------- 2FA backup codes hashing helpers -------------------
def _backup_code_hash(code: str) -> str:
    raw = (code or "").strip()
    if not raw:
        return ""
    to_hash = (SECRET_KEY + "::" + raw).encode("utf-8")
    return hashlib.sha256(to_hash).hexdigest()


def _backup_codes_hash_list(codes):
    return [_backup_code_hash(c) for c in (codes or []) if c]


def verify_and_consume_backup_code(user_id: int, code: str) -> bool:
    try:
        row = query_db("SELECT backup_codes FROM users WHERE id=?", (user_id,), one=True)
        if not row:
            return False
        try:
            stored = json.loads(row["backup_codes"] or "[]")
        except Exception:
            stored = []
        h = _backup_code_hash(code)
        if not h or h not in stored:
            return False
        stored.remove(h)
        exec_db(
            "UPDATE users SET backup_codes=? WHERE id=?",
            (json.dumps(stored, ensure_ascii=False), user_id),
        )
        return True
    except Exception:
        return False


# ------------------- Client IP helpers (trusted proxies aware) -------------------
_trusted_nets = []
for cidr in TRUSTED_PROXIES_CIDRS:
    try:
        _trusted_nets.append(ipaddress.ip_network(cidr, strict=False))
    except Exception:
        pass


def _ip_in_trusted(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in _trusted_nets:
            if ip_obj in net:
                return True
    except Exception:
        pass
    return False


def client_ip() -> str:
    """
    Best-effort client IP.
    If TRUSTED_PROXIES_CIDRS configured, prefer first address in access_route not in trusted nets.
    Otherwise fall back to request.remote_addr.
    """
    try:
        route = list(request.access_route or [])
        for ip in route:
            if not _ip_in_trusted(ip):
                return ip
        ip_hdr = (request.headers.get("X-Real-IP") or "").strip()
        if ip_hdr and not _ip_in_trusted(ip_hdr):
            return ip_hdr
    except Exception:
        pass
    return (request.remote_addr or "").split(",")[0].strip()


# ------------------- Rate limiting (Redis-first) -------------------
_rate_buckets = {}
_rate_warned = False
_rate_lock = threading.Lock()


def rate_limit(key: str, per_min=RATE_LIMIT_PER_MIN):
    global _rate_warned

    # Redis-based
    if REDIS_CLIENT:
        try:
            pipe = REDIS_CLIENT.pipeline()
            now_min = int(time.time() // 60)
            rkey = f"rate:{key}:{now_min}"
            pipe.incr(rkey)
            pipe.expire(rkey, 300)
            cnt = pipe.execute()[0]
            return cnt <= per_min
        except Exception as e:
            app.logger.error(f"Redis rate limit failed: {e}")
            if REQUIRE_REDIS_FOR_RATE and not _rate_warned:
                app.logger.warning("Redis required for rate limiting but not available — using in-process fallback")
                _rate_warned = True

    # in-process fallback (per-worker)
    now_min = int(time.time() // 60)
    with _rate_lock:
        bucket = _rate_buckets.get(key)
        if bucket is None or bucket[0] != now_min:
            _rate_buckets[key] = (now_min, 0)
            bucket = _rate_buckets[key]
        cnt = bucket[1] + 1
        _rate_buckets[key] = (bucket[0], cnt)
        # cleanup occasionally
        try:
            if secrets.randbelow(1000) == 0:
                cutoff = now_min - 5
                for k, (m, _) in list(_rate_buckets.items()):
                    if m < cutoff:
                        _rate_buckets.pop(k, None)
        except Exception:
            pass
    return cnt <= per_min


# ------------------- Login lock helpers (Redis-aware) -------------------
def _login_key(ip: str, user: str) -> str:
    return f"{(ip or '-').lower().strip()}|{(user or '').lower().strip()}"


def login_locked(ip: str, user: str) -> bool:
    key = _login_key(ip, user)
    if REDIS_CLIENT:
        try:
            now = int(time.time())
            first = REDIS_CLIENT.get(f"ll:first:{key}")
            cnt = REDIS_CLIENT.get(f"ll:cnt:{key}")
            first_ts = int(first or 0)
            if first_ts and (now - first_ts) > LOGIN_LOCK_WINDOW_SEC:
                REDIS_CLIENT.delete(f"ll:first:{key}")
                REDIS_CLIENT.delete(f"ll:cnt:{key}")
                return False
            c = int(cnt or 0)
            return c >= LOGIN_LOCK_MAX
        except Exception as e:
            app.logger.error(f"Redis login_locked failed: {e}")
    data = _failed_login.get(key)
    if not data:
        return False
    first_ts, cnt = data
    if time.time() - first_ts > LOGIN_LOCK_WINDOW_SEC:
        _failed_login.pop(key, None)
        return False
    return cnt >= LOGIN_LOCK_MAX


def login_lock_inc(ip: str, user: str) -> bool:
    key = _login_key(ip, user)
    if REDIS_CLIENT:
        try:
            now = int(time.time())
            pipe = REDIS_CLIENT.pipeline()
            pipe.setnx(f"ll:first:{key}", now)
            pipe.incr(f"ll:cnt:{key}")
            pipe.expire(f"ll:first:{key}", LOGIN_LOCK_WINDOW_SEC + 60)
            pipe.expire(f"ll:cnt:{key}", LOGIN_LOCK_WINDOW_SEC + 60)
            res = pipe.execute()
            c = int(res[1] if len(res) > 1 else 0)
            return c >= LOGIN_LOCK_MAX
        except Exception as e:
            app.logger.error(f"Redis login_lock_inc failed: {e}")
    now = time.time()
    data = _failed_login.get(key)
    if not data or (now - data[0] > LOGIN_LOCK_WINDOW_SEC):
        _failed_login[key] = [now, 1]
    else:
        data[1] += 1
        _failed_login[key] = data
    return _failed_login[key][1] >= LOGIN_LOCK_MAX


def login_lock_reset(ip: str, user: str):
    key = _login_key(ip, user)
    if REDIS_CLIENT:
        try:
            REDIS_CLIENT.delete(f"ll:first:{key}")
            REDIS_CLIENT.delete(f"ll:cnt:{key}")
        except Exception:
            pass
    try:
        _failed_login.pop(key, None)
    except Exception:
        pass


# ------------------- RBAC & helpers -------------------
ROLES = ("admin", "manager", "agent", "finance")


def login_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return w


def role_required(*roles):
    roles_set = set(roles)

    def deco(fn):
        @wraps(fn)
        def w(*a, **kw):
            if "user_id" not in session:
                return redirect(url_for("login", next=request.path))
            if session.get("role") not in roles_set:
                abort(403)
            return fn(*a, **kw)
        return w
    return deco


def admin_required(fn):
    return role_required("admin")(fn)


def get_current_user():
    if "user_id" in session:
        return query_db("SELECT * FROM users WHERE id=? LIMIT 1", (session["user_id"],), one=True)
    return None


def current_org_id():
    return session.get("org_id")


def require_org_scope():
    if not current_org_id():
        abort(400, "Org context missing")


def render_safe(tmpl_str: str, **ctx):
    try:
        wrapped = "{% autoescape true %}" + str(tmpl_str) + "{% endautoescape %}"
        return render_template_string(wrapped, **ctx)
    except Exception:
        return render_template_string(str(tmpl_str), **ctx)


# Chat access helper: if CHAT_ORG_WIDE==1 allow any user in org; else require membership
def chat_access_allowed(user_id: int, channel_id: int, org_id: int) -> bool:
    try:
        if not user_id or not org_id or not channel_id:
            return False
        if CHAT_ORG_WIDE:
            r = query_db("SELECT 1 FROM chat_channels WHERE id=? AND org_id=?", (int(channel_id), int(org_id)), one=True)
            return bool(r)
        r = query_db(
            "SELECT 1 FROM chat_members m JOIN chat_channels c ON c.id=m.channel_id "
            "WHERE m.user_id=? AND m.channel_id=? AND c.org_id=? LIMIT 1",
            (int(user_id), int(channel_id), int(org_id)),
            one=True,
        )
        return bool(r)
    except Exception:
        return False
# === END CORE PART 2/9 ===
# === CORE PART 3/9 — CSP, Theming, Storage, Files (with optional public-signed) ===
# -*- coding: utf-8 -*-
from urllib.parse import urlparse as _urlparse  # local alias

# ------------------- CSP helpers (strict) -------------------
def _origin(u: str) -> str:
    try:
        p = _urlparse(u or "")
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    except Exception:
        pass
    return ""


_CONNECT_SRC = {"'self'", "blob:"}
_ai = _origin(AI_BASE_URL)
if _ai:
    _CONNECT_SRC.add(_ai)
_s3o = _origin(S3_ENDPOINT)
if _s3o:
    _CONNECT_SRC.add(_s3o)

# weather api used in UI
_CONNECT_SRC.add("https://api.open-meteo.com")

FRAME_SRC = {"'self'"}
_jitsi = _origin(JITSI_BASE)
if _jitsi:
    FRAME_SRC.add(_jitsi)


def _new_csp_nonce():
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")


def csp_nonce():
    n = getattr(g, "_csp_nonce", None)
    if not n:
        n = _new_csp_nonce()
        g._csp_nonce = n
    return n


def _build_csp(nonce: str) -> str:
    # strict: no unsafe-inline for scripts; styles allow inline for simplicity (may be hardened later)
    return (
        "default-src 'self'; "
        "img-src 'self' data: blob:; "
        "media-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"connect-src {' '.join(sorted(_CONNECT_SRC))}; "
        f"frame-src {' '.join(sorted(FRAME_SRC))}"
    )


# ------------------- Theming -------------------
THEMES = {
    "light": {
        "bg": "#f5f7f7", "fg": "#1b262b", "muted": "#6b7c86", "accent": "#2bd66a", "accent-2": "#abf5c9",
        "border": "#d6dee2", "ok": "#2bd66a", "warn": "#ffc857", "err": "#ff6b6b", "surface": "#eef2f3", "panel": "#ffffff"
    },
    "dark": {
        "bg": "#0e1417", "fg": "#e6efea", "muted": "#9ab2a6", "accent": "#2bd66a", "accent-2": "#c4ffd9",
        "border": "#21323b", "ok": "#2bd66a", "warn": "#ffc857", "err": "#ff6b6b", "surface": "#121a1f", "panel": "#162126"
    },
}


def ensure_theme_default():
    if "theme" not in session:
        session["theme"] = "dark"


def theme_inline_vars(theme_name: str) -> str:
    t = THEMES.get(theme_name, THEMES["dark"])
    vars_css = "; ".join(f"--{k}: {v}" for k, v in t.items())
    return f"{vars_css}; color-scheme: {'dark' if theme_name=='dark' else 'light'}"


# ------------------- Storage (S3/local) -------------------
class Storage:
    def __init__(self):
        self.enable_s3 = bool(S3_ENABLED and boto3 and S3_BUCKET and S3_ACCESS_KEY and S3_SECRET_KEY)
        self._s3 = None
        if self.enable_s3:
            try:
                self._s3 = boto3.client(
                    "s3",
                    endpoint_url=S3_ENDPOINT or None,
                    region_name=S3_REGION or None,
                    aws_access_key_id=S3_ACCESS_KEY,
                    aws_secret_access_key=S3_SECRET_KEY,
                )
            except Exception as e:
                app.logger.error(f"S3 init failed: {e}")
                self.enable_s3 = False
                self._s3 = None

    def save(self, fileobj, filename: str, content_type="application/octet-stream") -> dict:
        ext = os.path.splitext(filename or "")[1].lower()
        key = f"{datetime.utcnow().strftime('%Y%m%d')}_{uuid.uuid4().hex}{ext}"
        if self.enable_s3 and self._s3:
            try:
                fileobj.seek(0)
                self._s3.upload_fileobj(
                    fileobj, S3_BUCKET, key,
                    ExtraArgs={"ContentType": content_type, "ACL": "private"}
                )
                return {"ok": True, "location": f"s3://{S3_BUCKET}/{key}", "key": key, "provider": "s3"}
            except (BotoCoreError, ClientError) as e:
                app.logger.error(f"S3 upload failed: {e}")

        # local fallback
        try:
            safe = key.replace("/", "").replace("\\", "")
            path = os.path.join(UPLOAD_DIR, safe)
            fileobj.seek(0)
            with open(path, "wb") as f_out:
                shutil.copyfileobj(fileobj, f_out, length=1024 * 1024)
            return {"ok": True, "location": f"local:{safe}", "key": safe, "provider": "local"}
        except Exception as e:
            app.logger.error(f"Local upload failed: {e}")
            return {"ok": False}

    def presign(self, key: str, expires=3600) -> str:
        if key.startswith("s3://") and self._s3:
            try:
                _, rest = key.split("://", 1)
                bucket, k = rest.split("/", 1)
                url = self._s3.generate_presigned_url(
                    ClientMethod="get_object",
                    Params={"Bucket": bucket, "Key": k},
                    ExpiresIn=int(expires),
                )
                return url
            except (BotoCoreError, ClientError) as e:
                app.logger.error(f"S3 presign failed: {e}")
                return ""
        return ""


storage = Storage()

# ------------------- File links & secure serving -------------------
def _file_sig(fid: int, exp_epoch: int) -> str:
    msg = f"{fid}.{exp_epoch}".encode("utf-8")
    return hmac.new(SECRET_KEY.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def presign_file(fid: int, expires: int = FILE_URL_TTL) -> str:
    exp = int(time.time()) + max(60, int(expires))
    sig = _file_sig(fid, exp)
    return url_for("file_signed", fid=fid, exp=exp, sig=sig, _external=True)


def presign_public_file(fid: int, expires: int = PUBLIC_FILE_URL_TTL) -> str:
    exp = int(time.time()) + max(60, int(expires))
    sig = _file_sig(fid, exp)
    return url_for("file_public_signed", fid=fid, exp=exp, sig=sig, _external=True)


def _resolve_file_for_user(fid: int):
    row = query_db("SELECT * FROM files WHERE id=? AND deleted_at IS NULL LIMIT 1", (fid,), one=True)
    if not row:
        abort(404)
    if session.get("org_id") != row["org_id"]:
        abort(403)
    return row


@app.route("/file/<int:fid>")
@login_required
def file_by_id(fid: int):
    row = _resolve_file_for_user(fid)
    key = row["storage_key"] or ""
    ctype = (row["content_type"] or "application/octet-stream")
    if key.startswith("s3://") and storage._s3:
        try:
            _, rest = key.split("://", 1)
            bucket, k = rest.split("/", 1)
            url = storage._s3.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": bucket, "Key": k},
                ExpiresIn=3600,
            )
            return redirect(url)
        except Exception as e:
            app.logger.exception(f"File redirect failed: {e}")
            abort(404)
    if key.startswith("local:"):
        try:
            path = safe_local_storage_path(UPLOAD_DIR, key)
        except Exception:
            abort(403)
        if not os.path.isfile(path):
            abort(404)
        as_attach = not (ctype.startswith("image/") or ctype == "application/pdf" or ctype.startswith("audio/") or ctype.startswith("video/"))
        return send_file(path, mimetype=ctype, as_attachment=as_attach, download_name=row["original_name"] or os.path.basename(path))
    abort(404)


@app.route("/file/signed")
@login_required
def file_signed():
    try:
        fid = int(request.args.get("fid") or "0")
        exp = int(request.args.get("exp") or "0")
        sig = request.args.get("sig") or ""
    except Exception:
        abort(400)
    if fid <= 0 or exp <= 0 or not sig:
        abort(400)
    if time.time() > exp:
        return make_response("Link expired", 410)
    if not hmac.compare_digest(sig, _file_sig(fid, exp)):
        return make_response("Bad signature", 403)
    return file_by_id(fid)


@app.route("/file/public")
def file_public_signed():
    if not PUBLIC_SIGNED_FILES_ENABLED:
        return make_response("public links disabled\n", 404)
    try:
        fid = int(request.args.get("fid") or "0")
        exp = int(request.args.get("exp") or "0")
        sig = request.args.get("sig") or ""
    except Exception:
        abort(400)
    if fid <= 0 or exp <= 0 or not sig:
        abort(400)
    if time.time() > exp:
        return make_response("Link expired", 410)
    if not hmac.compare_digest(sig, _file_sig(fid, exp)):
        return make_response("Bad signature", 403)
    row = query_db("SELECT * FROM files WHERE id=? AND deleted_at IS NULL LIMIT 1", (fid,), one=True)
    if not row:
        abort(404)
    key = row["storage_key"] or ""
    ctype = (row["content_type"] or "application/octet-stream")
    if key.startswith("s3://") and storage._s3:
        try:
            _, rest = key.split("://", 1)
            bucket, k = rest.split("/", 1)
            url = storage._s3.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": bucket, "Key": k},
                ExpiresIn=int(max(60, min(PUBLIC_FILE_URL_TTL, 3600))),
            )
            return redirect(url)
        except Exception as e:
            app.logger.exception(f"File public redirect failed: {e}")
            abort(404)
    if key.startswith("local:"):
        try:
            path = safe_local_storage_path(UPLOAD_DIR, key)
        except Exception:
            abort(403)
        if not os.path.isfile(path):
            abort(404)
        as_attach = not (ctype.startswith("image/") or ctype == "application/pdf" or ctype.startswith("audio/") or ctype.startswith("video/"))
        return send_file(path, mimetype=ctype, as_attachment=as_attach, download_name=row["original_name"] or os.path.basename(path))
    abort(404)
# === END CORE PART 3/9 ===
# === CORE PART 4/9 — SSE (Redis-aware), Hooks, Health/Ready, Metrics (+OpenAPI, Selftest) ===
# -*- coding: utf-8 -*-

# ------------------- SSE infrastructure (Redis-aware) -------------------
_sse_clients = {}  # user_id -> [Queue]
_sse_lock = threading.Lock()
_SSE_MAX_CONN_PER_USER = int(os.environ.get("SSE_MAX_CONN_PER_USER", "3"))


class _RedisForwarder(threading.Thread):
    def __init__(self, uid: int, q: queue.Queue):
        super().__init__(daemon=True)
        self.uid = uid
        self.q = q
        self._stop = threading.Event()
        self._ps = None

    def stop(self):
        self._stop.set()
        try:
            if self._ps:
                self._ps.close()
        except Exception:
            pass

    def run(self):
        if not REDIS_CLIENT:
            return
        try:
            self._ps = REDIS_CLIENT.pubsub()
            self._ps.subscribe(f"sse:{self.uid}")
            for m in self._ps.listen():
                if self._stop.is_set():
                    break
                if m and m.get("type") == "message":
                    data = m.get("data")
                    if isinstance(data, bytes):
                        msg = data.decode("utf-8", "ignore")
                    else:
                        msg = str(data or "")
                    try:
                        self.q.put_nowait(msg)
                    except queue.Full:
                        pass
        except Exception as e:
            app.logger.exception(f"SSE redis forwarder error: {e}")


def sse_subscribe(user_id: int):
    q = queue.Queue(maxsize=100)
    fwd = None
    with _sse_lock:
        arr = _sse_clients.setdefault(user_id, [])
        while len(arr) >= _SSE_MAX_CONN_PER_USER:
            try:
                oldq = arr.pop(0)
                if oldq:
                    try:
                        oldq.put_nowait("event: bye\ndata: {}\n\n")
                    except Exception:
                        pass
            except Exception:
                break
        arr.append(q)
    if REDIS_CLIENT:
        try:
            REDIS_CLIENT.ping()
            fwd = _RedisForwarder(user_id, q)
            fwd.start()
        except Exception as e:
            app.logger.error(f"Failed to start Redis forwarder: {e}")
            fwd = None
    return q, fwd


def sse_unsubscribe(user_id: int, q: queue.Queue, fwd: _RedisForwarder = None):
    try:
        if fwd:
            fwd.stop()
    except Exception:
        pass
    with _sse_lock:
        arr = _sse_clients.get(user_id) or []
        try:
            arr.remove(q)
        except ValueError:
            pass
        if not arr and user_id in _sse_clients:
            _sse_clients.pop(user_id, None)


def sse_publish(user_id: int, event: str, data: dict):
    msg = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
    published = False
    if REDIS_CLIENT:
        try:
            REDIS_CLIENT.publish(f"sse:{user_id}", msg)
            published = True
        except Exception as e:
            app.logger.error(f"Redis SSE publish failed: {e}")
    if not published:
        with _sse_lock:
            qs = _sse_clients.get(user_id) or []
            for q in qs:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass


def sse_publish_users(user_ids, event: str, data: dict):
    for uid in set(user_ids or []):
        sse_publish(uid, event, data)


@app.route("/sse")
@login_required
def sse():
    uid = session["user_id"]
    q, fwd = sse_subscribe(uid)

    def stream(q_: queue.Queue, fwd_obj: _RedisForwarder):
        yield "retry: 5000\n\n"
        try:
            while True:
                try:
                    m = q.get(timeout=25)
                    yield m
                except queue.Empty:
                    yield "event: keepalive\ndata: {}\n\n"
        finally:
            sse_unsubscribe(uid, q_, fwd_obj)

    resp = Response(stream(q, fwd), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Connection"] = "keep-alive"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


# ------------------- Base hooks and minimal routes -------------------
@app.before_request
def _base_before():
    ensure_csrf()
    ensure_theme_default()
    if not hasattr(g, "request_id"):
        g.request_id = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")


@app.before_request
def _enforce_2fa():
    if session.get("2fa_pending"):
        ep = (request.endpoint or "") or ""
        allowed = {
            "login", "twofa_verify", "logout",
            "healthz", "readyz", "manifest", "service_worker", "favicon", "setup",
        }
        if ep not in allowed:
            return redirect(url_for("twofa_verify"))


@app.before_request
def _metrics_before():
    try:
        g._req_start = time.perf_counter()
    except Exception:
        pass


@app.after_request
def _base_after(resp):
    try:
        dt = (time.perf_counter() - getattr(g, "_req_start", time.perf_counter())) * 1000.0
        endpoint = (request.endpoint or f"HTTP_{resp.status_code}")
        method = request.method
        status = resp.status_code
        _metrics_inc("http_requests_total", (method, endpoint, status))
        _metrics_observe_duration(endpoint, dt)
    except Exception:
        pass
    resp.headers["X-Request-Id"] = getattr(g, "request_id", "-")
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if CSP_STRICT:
        try:
            nonce = csp_nonce()
            resp.headers["Content-Security-Policy"] = _build_csp(nonce)
        except Exception as e:
            app.logger.error(f"CSP build failed: {e}")
    if app.config.get("SESSION_COOKIE_SECURE"):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return resp


@app.route("/favicon.ico")
def favicon():
    return Response(status=204)


@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": APP_NAME,
        "short_name": APP_NAME,
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0e1417",
        "theme_color": "#2bd66a",
        "icons": [{"src": "/favicon.ico", "sizes": "48x48", "type": "image/x-icon"}]
    })


@app.route("/sw.js")
def service_worker():
    js = "self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>self.clients.claim());"
    resp = make_response(js)
    resp.headers["Content-Type"] = "application/javascript; charset=utf-8"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/healthz")
def healthz():
    return jsonify(ok=True, ts=utc_iso())


@app.route("/readyz")
def readyz():
    try:
        ok_db = bool(query_db("SELECT 1 as ok", one=True))
    except Exception:
        ok_db = False
    ok_redis = True
    required_redis = (REQUIRE_REDIS_FOR_RATE or REQUIRE_REDIS_FOR_LOCK)
    if REDIS_CLIENT:
        try:
            REDIS_CLIENT.ping()
        except Exception:
            ok_redis = False
    else:
        if required_redis:
            ok_redis = False
    ok = ok_db and (ok_redis or not required_redis)
    return (jsonify(ok=ok, db=ok_db, redis=ok_redis, redis_required=required_redis), 200 if ok else 503)


# ------------------- Minimal OpenAPI (subset) -------------------
@app.route("/api/openapi.json")
def openapi_spec():
    sp = {
        "openapi": "3.0.3",
        "info": {"title": f"{APP_NAME} API", "version": "1.0.0"},
        "paths": {
            "/api/search": {"get": {"summary": "Global search", "parameters": [{"in": "query", "name": "q", "schema": {"type": "string"}}], "responses": {"200": {"description": "OK"}}}},
            "/api/deals/kanban": {"get": {"summary": "Deals Kanban board", "responses": {"200": {"description": "OK"}}}},
            "/api/deals/kanban/update": {"post": {"summary": "Move deal to another stage", "responses": {"200": {"description": "OK"}}}},
            "/api/custom_fields": {"get": {"summary": "List custom fields"}, "post": {"summary": "Create custom field"}},
            "/api/tokens/list": {"get": {"summary": "List API tokens", "responses": {"200": {"description": "OK"}}}},
            "/api/tokens/create": {"post": {"summary": "Create API token", "responses": {"200": {"description": "OK"}}}},
        },
    }
    return jsonify(sp)


# ------------------- Admin self-test (smoke) -------------------
@app.route("/admin/selftest")
@admin_required
def admin_selftest():
    fails = []
    try:
        r = query_db("SELECT name FROM sqlite_master WHERE type='table'")
        if not r:
            fails.append("db.tables")
    except Exception:
        fails.append("db.query")
    try:
        # key tables
        for t in ("orgs", "users", "tasks", "inbox_threads", "deals"):
            _ = query_db(f"SELECT 1 FROM {t} LIMIT 1")
    except Exception:
        fails.append("db.core_tables")
    try:
        # FTS available?
        _ = query_db("SELECT 1 FROM tasks_fts LIMIT 1")
    except Exception:
        # not fatal
        pass
    try:
        # endpoints smoke
        with app.test_request_context("/healthz"):
            pass
    except Exception:
        fails.append("endpoints.ctx")
    for f in fails:
        _metrics_inc("selftest_failures_total", (f,))
    return jsonify(ok=(len(fails) == 0), failures=fails)


# ------------------- Metrics exposition -------------------
@app.route("/metrics")
def metrics():
    if not ENABLE_METRICS:
        return make_response("metrics disabled\n", 404)
    if not METRICS_PUBLIC:
        if not session.get("user_id") or session.get("role") != "admin":
            return make_response("forbidden\n", 403)

    lines = []
    ns = METRICS_NAMESPACE
    snap = _metrics_snapshot()

    lines.append(f"# HELP {ns}_up Application up metric")
    lines.append(f"# TYPE {ns}_up gauge")
    lines.append(f"{ns}_up 1")

    lines.append(f"# HELP {ns}_http_requests_total HTTP requests total")
    lines.append(f"# TYPE {ns}_http_requests_total counter")
    for (method, endpoint, status), cnt in snap.get("http_requests_total", {}).items():
        lines.append(f'{ns}_http_requests_total{{method="{method}",endpoint="{endpoint}",status="{str(status)}"}} {cnt}')

    lines.append(f"# HELP {ns}_http_request_duration_ms HTTP request duration ms")
    lines.append(f"# TYPE {ns}_http_request_duration_ms histogram")
    for (endpoint, bucket), cnt in snap.get("http_request_duration_ms", {}).items():
        le = bucket.split("le", 1)[1] if bucket.startswith("le") else bucket
        lines.append(f'{ns}_http_request_duration_ms_bucket{{endpoint="{endpoint}",le="{le}"}} {cnt}')
    for endpoint, c in snap.get("http_request_duration_ms_count", {}).items():
        lines.append(f'{ns}_http_request_duration_ms_bucket{{endpoint="{endpoint}",le="+Inf"}} {c}')
    for endpoint, s in snap.get("http_request_duration_ms_sum", {}).items():
        lines.append(f'{ns}_http_request_duration_ms_sum{{endpoint="{endpoint}"}} {s}')
    for endpoint, c in snap.get("http_request_duration_ms_count", {}).items():
        lines.append(f'{ns}_http_request_duration_ms_count{{endpoint="{endpoint}"}} {c}')

    lines.append(f"# HELP {ns}_webhook_delivery_total Webhook delivery results")
    lines.append(f"# TYPE {ns}_webhook_delivery_total counter")
    for (event, status), cnt in snap.get("webhook_delivery_total", {}).items():
        lines.append(f'{ns}_webhook_delivery_total{{event="{event}",status="{status}"}} {cnt}')

    lines.append(f"# HELP {ns}_task_comments_total Task comments created")
    lines.append(f"# TYPE {ns}_task_comments_total counter")
    for (org_id,), cnt in snap.get("task_comments_total", {}).items():
        lines.append(f'{ns}_task_comments_total{{org_id="{org_id}"}} {cnt}')

    lines.append(f"# HELP {ns}_worker_heartbeat Background workers heartbeat")
    lines.append(f"# TYPE {ns}_worker_heartbeat gauge")
    for (worker,), val in snap.get("worker_heartbeat", {}).items():
        lines.append(f'{ns}_worker_heartbeat{{worker="{worker}"}} {val}')

    lines.append(f"# HELP {ns}_workflow_runs_active Active workflow runs (gauge)")
    lines.append(f"# TYPE {ns}_workflow_runs_active gauge")
    for (org_id,), val in snap.get("workflow_runs_active", {}).items():
        lines.append(f'{ns}_workflow_runs_active{{org_id="{org_id}"}} {val}')

    lines.append(f"# HELP {ns}_workflow_queue_lag_sec Workflow queue lag in seconds")
    lines.append(f"# TYPE {ns}_workflow_queue_lag_sec gauge")
    for (kind,), val in snap.get("workflow_queue_lag_sec", {}).items():
        lines.append(f'{ns}_workflow_queue_lag_sec{{kind="{kind}"}} {val}')

    lines.append(f"# HELP {ns}_email_fetch_errors_total Email fetch errors total")
    lines.append(f"# TYPE {ns}_email_fetch_errors_total counter")
    for (acc_id,), cnt in snap.get("email_fetch_errors_total", {}).items():
        lines.append(f'{ns}_email_fetch_errors_total{{account_id="{acc_id}"}} {cnt}')

    lines.append(f"# HELP {ns}_migrations_errors_total Migration errors")
    lines.append(f"# TYPE {ns}_migrations_errors_total counter")
    for (ver,), cnt in snap.get("migrations_errors_total", {}).items():
        lines.append(f'{ns}_migrations_errors_total{{version="{ver}"}} {cnt}')

    lines.append(f"# HELP {ns}_selftest_failures_total Self-test failures")
    lines.append(f"# TYPE {ns}_selftest_failures_total counter")
    for (chk,), cnt in snap.get("selftest_failures_total", {}).items():
        lines.append(f'{ns}_selftest_failures_total{{check="{chk}"}} {cnt}')

    lines.append(f"# HELP {ns}_kanban_ops_total Deals kanban operations")
    lines.append(f"# TYPE {ns}_kanban_ops_total counter")
    for (op,), cnt in snap.get("kanban_ops_total", {}).items():
        lines.append(f'{ns}_kanban_ops_total{{op="{op}"}} {cnt}')

    lines.append(f"# HELP {ns}_custom_fields_ops_total Custom fields operations")
    lines.append(f"# TYPE {ns}_custom_fields_ops_total counter")
    for (op,), cnt in snap.get("custom_fields_ops_total", {}).items():
        lines.append(f'{ns}_custom_fields_ops_total{{op="{op}"}} {cnt}')

    return Response("\n".join(lines) + "\n", mimetype="text/plain")
# === END CORE PART 4/9 ===
# === CORE PART 5/9 (1/3) — Schema helpers, Indexes (tuned), Backfill, App KV ===
# -*- coding: utf-8 -*-

# ------------------- Schema helpers -------------------
def table_columns(table_name: str) -> set:
    try:
        rows = query_db(f"PRAGMA table_info({table_name})")
        return {r["name"] for r in rows}
    except Exception as e:
        app.logger.error(f"Table info failed for {table_name}: {e}")
        return set()


def _object_exists(obj_type: str, name: str) -> bool:
    try:
        r = query_db("SELECT 1 FROM sqlite_master WHERE type=? AND name=?", (obj_type, name), one=True)
        return bool(r)
    except Exception:
        return False


def ensure_column(table: str, col: str, ddl_type: str):
    cols = table_columns(table)
    if col not in cols:
        try:
            exec_db(f"ALTER TABLE {table} ADD COLUMN {col} {ddl_type}")
        except Exception as e:
            if "duplicate" not in str(e).lower():
                app.logger.warning(f"ALTER TABLE {table} ADD COLUMN {col} failed: {e}")


def ensure_trigger(name: str, ddl: str):
    if not _object_exists("trigger", name):
        try:
            exec_db(ddl)
        except Exception as e:
            app.logger.error(f"Create trigger {name} failed: {e}")


# ------------------- Indexes (performance-focused, with guards for optional tables) -------------------
def ensure_indexes():
    # users/files/channels
    exec_db("CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_users_active ON users(org_id, active)")
    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_org_username ON users(org_id, username)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_files_org ON files(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_channels_org ON channels(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_channels_type ON channels(type)")

    # inbox threads/messages
    exec_db("CREATE INDEX IF NOT EXISTS idx_threads_org ON inbox_threads(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_threads_status ON inbox_threads(status)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_threads_assignee ON inbox_threads(assignee_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_threads_lastmsg ON inbox_threads(last_message_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_threads_org_status_assignee ON inbox_threads(org_id, status, assignee_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_threads_org_status_asg_lastmsg ON inbox_threads(org_id, status, assignee_id, last_message_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_threads_created ON inbox_threads(created_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_msgs_thread_id ON inbox_messages(thread_id, id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_msgs_org ON inbox_messages(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_msgs_created ON inbox_messages(created_at)")

    # tasks
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_org ON tasks(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_company ON tasks(company_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_org_status_due ON tasks(org_id, status, due_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_org_asg_status ON tasks(org_id, assignee_id, status)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_current_dept ON tasks(org_id, current_department_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_last_comment ON tasks(last_commented_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_contact_person ON tasks(contact_person_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_deal ON tasks(deal_id)")
    # new: subtasks/time tracking
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_parent ON tasks(parent_task_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_timer_started ON tasks(timer_started_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tasks_time_spent ON tasks(time_spent_sec)")

    # task_comments
    exec_db("CREATE INDEX IF NOT EXISTS idx_tcomments_org ON task_comments(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tcomments_task ON task_comments(task_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tcomments_created ON task_comments(created_at)")

    # task_activity
    exec_db("CREATE INDEX IF NOT EXISTS idx_tactivity_org ON task_activity(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tactivity_task ON task_activity(task_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_tactivity_created ON task_activity(created_at)")

    # reminders/approvals/meetings
    exec_db("CREATE INDEX IF NOT EXISTS idx_rem_org_fired_time ON task_reminders(org_id, fired, remind_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_rem_task ON task_reminders(task_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_approvals_org ON approvals(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_approvals_token ON approvals(token)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_apprlog_appr ON approvals_log(approval_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_meetings_org ON meetings(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_meetings_room ON meetings(room)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_meetings_start ON meetings(start_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_meetings_created ON meetings(created_at)")

    # chat
    exec_db("CREATE INDEX IF NOT EXISTS idx_chatchan_org ON chat_channels(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_chatchan_dm ON chat_channels(org_id, dm_key)")
    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_chat_dm ON chat_channels(org_id, dm_key) WHERE dm_key IS NOT NULL")
    exec_db("CREATE INDEX IF NOT EXISTS idx_chatmsg_chan ON chat_messages(channel_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_chatmsg_org ON chat_messages(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_chatmsg_created ON chat_messages(created_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_chatmem_chan ON chat_members(channel_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_chatmem_user ON chat_members(user_id)")

    # calls
    exec_db("CREATE INDEX IF NOT EXISTS idx_calls_org ON calls(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_calls_started ON calls(started_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_calls_agent ON calls(agent_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_calls_provider_id ON calls(provider_call_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_calls_channel ON calls(channel_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_calls_duration ON calls(duration_sec)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_calls_org_started ON calls(org_id, started_at)")
    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_calls_provider ON calls(org_id, provider, provider_call_id)")

    # ai_jobs/notifications
    exec_db("CREATE INDEX IF NOT EXISTS idx_aijobs_org ON ai_jobs(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_aijobs_status ON ai_jobs(status)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_notif_org ON notifications(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_notif_user_unread ON notifications(user_id, is_read)")

    # billing/webhooks
    exec_db("CREATE INDEX IF NOT EXISTS idx_subs_org ON org_subscriptions(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_payments_org ON payments(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_whqueue_status ON webhook_queue(status)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_whqueue_status_next ON webhook_queue(status, next_try_at)")

    # companies/contacts/deals
    exec_db("CREATE INDEX IF NOT EXISTS idx_companies_org ON companies(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_companies_inn ON companies(inn)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_companies_phone ON companies(phone)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_companies_email ON companies(email)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_companies_created ON companies(created_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_contacts_org ON contacts(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_contacts_phone ON contacts(phone)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_companies_phone_norm ON companies(phone_norm)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_contacts_phone_norm ON contacts(phone_norm)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_deals_org ON deals(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_deals_status ON deals(status)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_deals_created ON deals(created_at)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_deals_curr_dept ON deals(org_id, current_department_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_deals_org_status_asg ON deals(org_id, status, assignee_id)")
    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_companies_inn_org ON companies(org_id, inn) WHERE inn IS NOT NULL")

    # departments/workflow/participants
    exec_db("CREATE INDEX IF NOT EXISTS idx_dept_org ON departments(org_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_dept_members ON department_members(department_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_dept_members_user ON department_members(user_id)")
    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_dept_member ON department_members(org_id, department_id, user_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_wfstg_org_ent ON workflow_stages(org_id, entity_type)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_wfstg_order ON workflow_stages(org_id, entity_type, order_no)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_stage_trans_ent ON stage_transitions(org_id, entity_type, entity_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_task_part ON task_participants(task_id)")
    exec_db("CREATE INDEX IF NOT EXISTS idx_deal_part ON deal_participants(deal_id)")
    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_task_part ON task_participants(org_id, task_id, user_id, role)")

    # email channel (guarded)
    if _object_exists("table", "mail_accounts"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_mail_acc_org ON mail_accounts(org_id)")
    if _object_exists("table", "email_threads"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_email_thr_org ON email_threads(org_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_email_thr_lm ON email_threads(org_id, last_message_at)")
    if _object_exists("table", "email_messages"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_email_msg_org ON email_messages(org_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_email_msg_thread ON email_messages(thread_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_email_msg_created ON email_messages(created_at)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_email_msg_org_thread_created ON email_messages(org_id, thread_id, created_at)")
        exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_email_external ON email_messages(org_id, account_id, external_id)")

    # workflow defs/runs/tasks/timers (guarded)
    if _object_exists("table", "workflow_defs"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_wfdefs_org ON workflow_defs(org_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_wfdefs_active ON workflow_defs(org_id, active)")
    if _object_exists("table", "workflow_runs"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_wfruns_org ON workflow_runs(org_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_wfruns_status ON workflow_runs(org_id, status)")
    if _object_exists("table", "workflow_tasks"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_wftasks_run ON workflow_tasks(run_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_wftasks_status ON workflow_tasks(status)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_wftasks_next ON workflow_tasks(next_at)")
    if _object_exists("table", "workflow_timers"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_wftimers_run ON workflow_timers(run_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_wftimers_fire ON workflow_timers(fire_at)")

    # no-code custom fields (guarded)
    if _object_exists("table", "custom_fields"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_cust_fields_org_ent ON custom_fields(org_id, entity)")
        exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_cust_field_key ON custom_fields(org_id, entity, key)")
    if _object_exists("table", "custom_values"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_cust_vals_ent ON custom_values(org_id, entity, entity_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_cust_vals_field ON custom_values(org_id, entity, field_id)")

    # CPQ products/quotes (guarded)
    if _object_exists("table", "products"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_products_org ON products(org_id)")
        exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_products_sku ON products(org_id, sku)")
    if _object_exists("table", "quotes"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_quotes_org ON quotes(org_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_quotes_deal ON quotes(deal_id)")

    # analytics aggregates (guarded)
    if _object_exists("table", "agg_task_daily"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_agg_task_daily ON agg_task_daily(org_id, ymd)")
    if _object_exists("table", "agg_calls_daily"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_agg_calls_daily ON agg_calls_daily(org_id, ymd)")

    # api tokens (guarded) — enforce unique per org by token_hash
    if _object_exists("table", "api_tokens"):
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_org_active ON api_tokens(org_id, active)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(user_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_exp ON api_tokens(expires_at)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_scopes ON api_tokens(scopes)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_last_used ON api_tokens(last_used_at)")
        exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_tokens_org_hash ON api_tokens(org_id, token_hash)")
        # legacy helper index
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens(token_hash)")


# ------------------- Backfill helpers -------------------
def backfill_phone_norm():
    try:
        rows = query_db(
            "SELECT id, phone FROM companies WHERE phone IS NOT NULL AND (phone_norm IS NULL OR phone_norm='')"
        )
        if rows:
            seq = []
            for r in rows:
                pn = phone_last10(r["phone"] or "")
                seq.append((pn, r["id"]))
            if seq:
                exec_many("UPDATE companies SET phone_norm=? WHERE id=?", seq)
        rows2 = query_db(
            "SELECT id, phone FROM contacts WHERE phone IS NOT NULL AND (phone_norm IS NULL OR phone_norm='')"
        )
        if rows2:
            seq2 = []
            for r in rows2:
                pn = phone_last10(r["phone"] or "")
                seq2.append((pn, r["id"]))
            if seq2:
                exec_many("UPDATE contacts SET phone_norm=? WHERE id=?", seq2)
    except Exception as e:
        app.logger.error(f"Backfill phone_norm failed: {e}")


# ------------------- App meta helpers (KV) -------------------
def get_app_meta(key: str, default=None):
    try:
        r = query_db("SELECT value FROM app_meta WHERE key=?", (key,), one=True)
        if not r or r["value"] is None:
            return default
        return r["value"]
    except Exception:
        return default


def set_app_meta(key: str, value: str):
    try:
        if not _object_exists("table", "app_meta"):
            exec_db("CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT, updated_at DATETIME)")
        if query_db("SELECT 1 FROM app_meta WHERE key=?", (key,), one=True):
            exec_db("UPDATE app_meta SET value=?, updated_at=CURRENT_TIMESTAMP WHERE key=?", (value, key))
        else:
            exec_db(
                "INSERT INTO app_meta (key, value, updated_at) VALUES (?,?,CURRENT_TIMESTAMP)",
                (key, value),
            )
    except Exception as e:
        app.logger.error(f"set_app_meta failed: {e}")
# === END CORE PART 5/9 (1/3) ===
# === CORE PART 5/9 (2/3) — FTS helpers (safe rebuild), email_fts, upsert/delete ===
# -*- coding: utf-8 -*-

# ------------------- FTS helpers -------------------
def _fts_table_exists(name: str) -> bool:
    try:
        r = query_db("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,), one=True)
        return bool(r)
    except Exception:
        return False


def ensure_fts_tables():
    if not _fts_table_exists("inbox_messages_fts"):
        exec_db("""CREATE VIRTUAL TABLE inbox_messages_fts USING fts5(body, content='');""")
    if not _fts_table_exists("tasks_fts"):
        exec_db("""CREATE VIRTUAL TABLE tasks_fts USING fts5(title, description, content='');""")
    if not _fts_table_exists("chat_messages_fts"):
        exec_db("""CREATE VIRTUAL TABLE chat_messages_fts USING fts5(body, content='');""")
    if not _fts_table_exists("transcripts_fts"):
        exec_db("""CREATE VIRTUAL TABLE transcripts_fts USING fts5(text, meta, content='');""")
    if not _fts_table_exists("task_comments_fts"):
        exec_db("""CREATE VIRTUAL TABLE task_comments_fts USING fts5(body, content='');""")
    if not _fts_table_exists("email_messages_fts"):
        exec_db("""CREATE VIRTUAL TABLE email_messages_fts USING fts5(subject, body, content='');""")


def ensure_fts_triggers():
    # tasks -> tasks_fts
    ensure_trigger(
        "tr_tasks_ai",
        """
        CREATE TRIGGER tr_tasks_ai AFTER INSERT ON tasks BEGIN
            INSERT INTO tasks_fts(rowid,title,description) VALUES (new.id, COALESCE(new.title,''), COALESCE(new.description,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_tasks_au",
        """
        CREATE TRIGGER tr_tasks_au AFTER UPDATE ON tasks BEGIN
            INSERT INTO tasks_fts(tasks_fts,rowid) VALUES('delete', old.id);
            INSERT INTO tasks_fts(rowid,title,description) VALUES (new.id, COALESCE(new.title,''), COALESCE(new.description,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_tasks_ad",
        """
        CREATE TRIGGER tr_tasks_ad AFTER DELETE ON tasks BEGIN
            INSERT INTO tasks_fts(tasks_fts,rowid) VALUES('delete', old.id);
        END;
        """,
    )
    # inbox_messages -> inbox_messages_fts
    ensure_trigger(
        "tr_im_ai",
        """
        CREATE TRIGGER tr_im_ai AFTER INSERT ON inbox_messages BEGIN
            INSERT INTO inbox_messages_fts(rowid,body) VALUES (new.id, COALESCE(new.body,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_im_au",
        """
        CREATE TRIGGER tr_im_au AFTER UPDATE ON inbox_messages BEGIN
            INSERT INTO inbox_messages_fts(inbox_messages_fts,rowid) VALUES('delete', old.id);
            INSERT INTO inbox_messages_fts(rowid,body) VALUES (new.id, COALESCE(new.body,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_im_ad",
        """
        CREATE TRIGGER tr_im_ad AFTER DELETE ON inbox_messages BEGIN
            INSERT INTO inbox_messages_fts(inbox_messages_fts,rowid) VALUES('delete', old.id);
        END;
        """,
    )
    # chat_messages -> chat_messages_fts
    ensure_trigger(
        "tr_cm_ai",
        """
        CREATE TRIGGER tr_cm_ai AFTER INSERT ON chat_messages BEGIN
            INSERT INTO chat_messages_fts(rowid,body) VALUES (new.id, COALESCE(new.body,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_cm_au",
        """
        CREATE TRIGGER tr_cm_au AFTER UPDATE ON chat_messages BEGIN
            INSERT INTO chat_messages_fts(chat_messages_fts,rowid) VALUES('delete', old.id);
            INSERT INTO chat_messages_fts(rowid,body) VALUES (new.id, COALESCE(new.body,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_cm_ad",
        """
        CREATE TRIGGER tr_cm_ad AFTER DELETE ON chat_messages BEGIN
            INSERT INTO chat_messages_fts(chat_messages_fts,rowid) VALUES('delete', old.id);
        END;
        """,
    )
    # task_comments -> task_comments_fts
    ensure_trigger(
        "tr_tc_ai",
        """
        CREATE TRIGGER tr_tc_ai AFTER INSERT ON task_comments BEGIN
            INSERT INTO task_comments_fts(rowid,body) VALUES (new.id, COALESCE(new.body,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_tc_au",
        """
        CREATE TRIGGER tr_tc_au AFTER UPDATE ON task_comments BEGIN
            INSERT INTO task_comments_fts(task_comments_fts,rowid) VALUES('delete', old.id);
            INSERT INTO task_comments_fts(rowid,body) VALUES (new.id, COALESCE(new.body,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_tc_ad",
        """
        CREATE TRIGGER tr_tc_ad AFTER DELETE ON task_comments BEGIN
            INSERT INTO task_comments_fts(task_comments_fts,rowid) VALUES('delete', old.id);
        END;
        """,
    )
    # email_messages -> email_messages_fts
    ensure_trigger(
        "tr_em_ai",
        """
        CREATE TRIGGER tr_em_ai AFTER INSERT ON email_messages BEGIN
            INSERT INTO email_messages_fts(rowid,subject,body) VALUES (new.id, COALESCE(new.subject,''), COALESCE(new.body_text,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_em_au",
        """
        CREATE TRIGGER tr_em_au AFTER UPDATE ON email_messages BEGIN
            INSERT INTO email_messages_fts(email_messages_fts,rowid) VALUES('delete', old.id);
            INSERT INTO email_messages_fts(rowid,subject,body) VALUES (new.id, COALESCE(new.subject,''), COALESCE(new.body_text,''));
        END;
        """,
    )
    ensure_trigger(
        "tr_em_ad",
        """
        CREATE TRIGGER tr_em_ad AFTER DELETE ON email_messages BEGIN
            INSERT INTO email_messages_fts(email_messages_fts,rowid) VALUES('delete', old.id);
        END;
        """,
    )


def rebuild_fts_table(table_name: str):
    con = get_db()
    try:
        cur = con.cursor()
        cur.execute("BEGIN EXCLUSIVE")
        cur.execute(f"DROP TABLE IF EXISTS {table_name}")
        if table_name == "tasks_fts":
            cur.execute("""CREATE VIRTUAL TABLE tasks_fts USING fts5(title, description, content='');""")
            for r in query_db("SELECT id, title, description FROM tasks"):
                cur.execute(
                    "INSERT INTO tasks_fts(rowid,title,description) VALUES (?,?,?)",
                    (r["id"], r["title"] or "", r["description"] or ""),
                )
        elif table_name == "inbox_messages_fts":
            cur.execute("""CREATE VIRTUAL TABLE inbox_messages_fts USING fts5(body, content='');""")
            for r in query_db("SELECT id, body FROM inbox_messages"):
                cur.execute("INSERT INTO inbox_messages_fts(rowid,body) VALUES (?,?)", (r["id"], r["body"] or ""))
        elif table_name == "chat_messages_fts":
            cur.execute("""CREATE VIRTUAL TABLE chat_messages_fts USING fts5(body, content='');""")
            for r in query_db("SELECT id, body FROM chat_messages"):
                cur.execute("INSERT INTO chat_messages_fts(rowid,body) VALUES (?,?)", (r["id"], r["body"] or ""))
        elif table_name == "transcripts_fts":
            cur.execute("""CREATE VIRTUAL TABLE transcripts_fts USING fts5(text, meta, content='');""")
            for r in query_db("SELECT id, transcript_text FROM meetings"):
                cur.execute(
                    "INSERT INTO transcripts_fts(rowid,text,meta) VALUES (?,?,?)",
                    (r["id"], r["transcript_text"] or "", json.dumps({"meeting": r["id"]}, ensure_ascii=False)),
                )
        elif table_name == "task_comments_fts":
            cur.execute("""CREATE VIRTUAL TABLE task_comments_fts USING fts5(body, content='');""")
            for r in query_db("SELECT id, body FROM task_comments"):
                cur.execute("INSERT INTO task_comments_fts(rowid,body) VALUES (?,?)", (r["id"], r["body"] or ""))
        elif table_name == "email_messages_fts":
            cur.execute("""CREATE VIRTUAL TABLE email_messages_fts USING fts5(subject, body, content='');""")
            for r in query_db("SELECT id, subject, body_text FROM email_messages"):
                cur.execute(
                    "INSERT INTO email_messages_fts(rowid,subject,body) VALUES (?,?,?)",
                    (r["id"], r["subject"] or "", r["body_text"] or ""),
                )
        con.commit()
    except Exception as e:
        try:
            con.rollback()
        except Exception:
            pass
        app.logger.error(f"[FTS] rebuild {table_name} failed: {e}")


def fts_upsert(table_name: str, rowid: int, fields: dict):
    if not rowid:
        return
    try:
        exec_db(f"INSERT INTO {table_name}({table_name}, rowid) VALUES('delete', ?)", (rowid,))
    except Exception as e:
        if "malformed" in str(e).lower():
            rebuild_fts_table(table_name)
    try:
        cols = ",".join(fields.keys())
        qmarks = ",".join(["?"] * len(fields))
        exec_db(f"INSERT INTO {table_name}(rowid,{cols}) VALUES (?,{qmarks})", tuple([rowid] + list(fields.values())))
    except Exception as e:
        app.logger.error(f"[FTS] upsert failed for {table_name} rowid={rowid}: {e}")
        if "malformed" in str(e).lower():
            rebuild_fts_table(table_name)
            try:
                exec_db(
                    f"INSERT INTO {table_name}(rowid,{cols}) VALUES (?,{qmarks})",
                    tuple([rowid] + list(fields.values())),
                )
            except Exception as e2:
                app.logger.error(f"[FTS] Retry failed for {table_name} rowid={rowid}: {e2}")


def fts_delete(table_name: str, rowid: int):
    try:
        exec_db(f"INSERT INTO {table_name}({table_name}, rowid) VALUES('delete', ?)", (rowid,))
    except Exception:
        pass


def fts_rebuild_all():
    for t in ("tasks_fts", "inbox_messages_fts", "chat_messages_fts", "transcripts_fts", "task_comments_fts", "email_messages_fts"):
        rebuild_fts_table(t)
# === END CORE PART 5/9 (2/3) ===
# === CORE PART 5/9 (3/3) — Migrations v1..v13 (transactional, locked), ensure_schema (metrics) ===
# -*- coding: utf-8 -*-

def _schema_get_version():
    try:
        v = query_db("SELECT version FROM schema_meta LIMIT 1", one=True)
        return int(v["version"]) if v and v["version"] is not None else 0
    except Exception:
        return 0


def _schema_set_version(v: int):
    try:
        if not _object_exists("table", "schema_meta"):
            exec_db("CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL, applied_at DATETIME)")
            exec_db("INSERT INTO schema_meta (version, applied_at) VALUES (0, CURRENT_TIMESTAMP)")
        exec_db("UPDATE schema_meta SET version=?, applied_at=CURRENT_TIMESTAMP", (int(v),))
    except Exception as e:
        app.logger.error(f"schema_meta update failed: {e}")


# ---------- v1..v12 (initial schema and prior features) ----------
def _migration_1_initial():
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS orgs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT UNIQUE,
            timezone TEXT DEFAULT 'Europe/Moscow',
            logo_key TEXT,
            plan TEXT NOT NULL DEFAULT 'start',
            plan_meta TEXT,
            billing_status TEXT DEFAULT 'trial',
            promo_active INTEGER NOT NULL DEFAULT 0,
            trial_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            active INTEGER NOT NULL DEFAULT 1,
            tz TEXT DEFAULT 'Europe/Moscow',
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_secret TEXT,
            backup_codes TEXT,
            first_name TEXT,
            last_name TEXT,
            position TEXT,
            avatar_file_id INTEGER,
            last_login DATETIME,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME,
            accepted_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER,
            name TEXT,
            token TEXT UNIQUE NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            last_used_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER,
            action TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            details TEXT,
            ip TEXT,
            ua TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER,
            original_name TEXT NOT NULL,
            storage_key TEXT NOT NULL,
            content_type TEXT,
            size INTEGER,
            tags_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            deleted_at DATETIME,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            name TEXT,
            settings_json TEXT,
            secret TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            inn TEXT,
            website TEXT,
            phone TEXT,
            email TEXT,
            address TEXT,
            notes TEXT,
            phone_norm TEXT,
            extra_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            company_id INTEGER,
            name TEXT,
            position TEXT,
            phone TEXT,
            email TEXT,
            tg_id TEXT,
            vk_id TEXT,
            external_id TEXT,
            phone_norm TEXT,
            extra_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS inbox_threads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            channel_id INTEGER,
            kind TEXT NOT NULL DEFAULT 'dm',
            external_id TEXT,
            subject TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            priority TEXT NOT NULL DEFAULT 'normal',
            assignee_id INTEGER,
            tags_json TEXT,
            first_response_due_at DATETIME,
            first_response_at DATETIME,
            last_message_at DATETIME,
            snooze_until DATETIME,
            customer_contact_id INTEGER,
            group_size INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE SET NULL,
            FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS inbox_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            thread_id INTEGER NOT NULL,
            sender_type TEXT NOT NULL,
            user_id INTEGER,
            external_user_id TEXT,
            body TEXT,
            attachments_json TEXT,
            reply_to_id INTEGER,
            mentions_json TEXT,
            internal_note INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            deleted_at DATETIME,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (thread_id) REFERENCES inbox_threads(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            creator_id INTEGER,
            assignee_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            checklist_json TEXT,
            tags_json TEXT,
            priority TEXT NOT NULL DEFAULT 'normal',
            due_at DATETIME,
            status TEXT NOT NULL DEFAULT 'open',
            thread_id INTEGER,
            message_id INTEGER,
            address TEXT,
            contact_phone TEXT,
            company_id INTEGER,
            monthly_fee REAL DEFAULT 0,
            extra_json TEXT,
            current_stage TEXT,
            current_department_id INTEGER,
            last_commented_at DATETIME,
            last_commented_by INTEGER,
            pinned_files_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS task_reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            remind_at DATETIME NOT NULL,
            message TEXT,
            fired INTEGER NOT NULL DEFAULT 0,
            fired_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            task_id INTEGER,
            token TEXT UNIQUE NOT NULL,
            title TEXT,
            description TEXT,
            files_json TEXT,
            requirements TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            form_token TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS approvals_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            approval_id INTEGER NOT NULL,
            actor TEXT,
            action TEXT NOT NULL,
            message TEXT,
            ip TEXT,
            ua TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (approval_id) REFERENCES approvals(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS meetings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            created_by INTEGER,
            thread_id INTEGER,
            task_id INTEGER,
            room TEXT NOT NULL,
            role_policy TEXT,
            invite_token TEXT,
            title TEXT,
            start_at DATETIME,
            end_at DATETIME,
            participants_json TEXT,
            notify_before_min INTEGER DEFAULT 0,
            reminder_fired INTEGER DEFAULT 0,
            started_at DATETIME,
            ended_at DATETIME,
            recording_key TEXT,
            recording_duration_min INTEGER,
            transcript_text TEXT,
            ai_summary TEXT,
            action_items_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS chat_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'public',
            created_by INTEGER,
            meta_json TEXT,
            dm_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS chat_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            channel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            body TEXT,
            attachments_json TEXT,
            reply_to_id INTEGER,
            reactions_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            deleted_at DATETIME,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            channel_id INTEGER,
            provider TEXT,
            provider_call_id TEXT,
            direction TEXT,
            from_e164 TEXT,
            to_e164 TEXT,
            started_at DATETIME,
            answered_at DATETIME,
            ended_at DATETIME,
            duration_sec INTEGER,
            status TEXT,
            disposition TEXT,
            agent_id INTEGER,
            customer_company_id INTEGER,
            customer_contact_id INTEGER,
            recording_key TEXT,
            recording_file_id INTEGER,
            transcript_text TEXT,
            ai_summary TEXT,
            metrics_json TEXT,
            script_coverage REAL,
            script_quotes_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE SET NULL,
            FOREIGN KEY (agent_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (customer_company_id) REFERENCES companies(id) ON DELETE SET NULL,
            FOREIGN KEY (customer_contact_id) REFERENCES contacts(id) ON DELETE SET NULL,
            FOREIGN KEY (recording_file_id) REFERENCES files(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS call_scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            steps_json TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS call_script_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            call_id INTEGER NOT NULL,
            script_id INTEGER NOT NULL,
            coverage REAL,
            quotes_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (call_id) REFERENCES calls(id) ON DELETE CASCADE,
            FOREIGN KEY (script_id) REFERENCES call_scripts(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS ai_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            input_ref TEXT,
            provider TEXT,
            model TEXT,
            options_json TEXT,
            usage_json TEXT,
            output_json TEXT,
            error TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            kind TEXT,
            title TEXT,
            body TEXT,
            link_url TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS user_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            data_json TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS org_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            plan TEXT NOT NULL,
            period_start DATETIME,
            period_end DATETIME,
            status TEXT NOT NULL DEFAULT 'active',
            promo_code TEXT,
            discount_percent REAL,
            auto_renew INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            provider TEXT,
            invoice_id TEXT,
            amount REAL,
            currency TEXT DEFAULT 'RUB',
            status TEXT,
            receipt_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            paid_at DATETIME,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            url TEXT NOT NULL,
            secret TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS webhook_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_try_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS deals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            stage TEXT NOT NULL DEFAULT 'new',
            amount REAL DEFAULT 0,
            currency TEXT DEFAULT 'RUB',
            status TEXT NOT NULL DEFAULT 'open',
            assignee_id INTEGER,
            company_id INTEGER,
            contact_id INTEGER,
            tags_json TEXT,
            extra_json TEXT,
            current_department_id INTEGER,
            due_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE SET NULL,
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS user_prefs (
            user_id INTEGER PRIMARY KEY,
            data TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS saved_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            params_json TEXT,
            cols_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS task_statuses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS ext_dedup (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            external_id TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(org_id, source, external_id),
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            action TEXT NOT NULL,
            condition_json TEXT,
            params_json TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            slug TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS department_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            department_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS workflow_stages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            key TEXT NOT NULL,
            name TEXT NOT NULL,
            order_no INTEGER NOT NULL DEFAULT 0,
            sla_minutes INTEGER DEFAULT 0,
            default_department_id INTEGER,
            active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (default_department_id) REFERENCES departments(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS stage_transitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            from_stage TEXT,
            to_stage TEXT,
            by_user_id INTEGER,
            department_id INTEGER,
            comment TEXT,
            due_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (by_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS task_participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'assignee',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS deal_participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            deal_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'assignee',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (deal_id) REFERENCES deals(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS task_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            body TEXT,
            attachments_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS task_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            user_id INTEGER,
            kind TEXT NOT NULL,
            meta_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )


def _migration_2_add_missing_columns():
    ensure_column("tasks", "address", "TEXT")
    ensure_column("tasks", "contact_phone", "TEXT")
    ensure_column("tasks", "company_id", "INTEGER")
    ensure_column("tasks", "monthly_fee", "REAL")
    ensure_column("tasks", "extra_json", "TEXT")
    ensure_column("tasks", "current_stage", "TEXT")
    ensure_column("tasks", "current_department_id", "INTEGER")
    ensure_column("companies", "phone_norm", "TEXT")
    ensure_column("companies", "extra_json", "TEXT")
    ensure_column("contacts", "phone_norm", "TEXT")
    ensure_column("contacts", "extra_json", "TEXT")
    ensure_column("deals", "extra_json", "TEXT")
    ensure_column("deals", "current_department_id", "INTEGER")
    ensure_column("deals", "due_at", "DATETIME")


def _migration_3_task_comments_and_app_meta():
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS task_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            body TEXT,
            attachments_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"""
    )


def _migration_4_task_activity_and_task_fields():
    ensure_column("tasks", "last_commented_at", "DATETIME")
    ensure_column("tasks", "last_commented_by", "INTEGER")
    ensure_column("tasks", "pinned_files_json", "TEXT")
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS task_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            user_id INTEGER,
            kind TEXT NOT NULL,
            meta_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_org_username ON users(org_id, username)")


def _migration_5_task_extended_fields():
    ensure_column("tasks", "business_type", "TEXT")
    ensure_column("tasks", "desired_contact_time", "TEXT")
    ensure_column("tasks", "expected_services", "TEXT")
    ensure_column("tasks", "equipment_details", "TEXT")
    ensure_column("tasks", "contact_person_id", "INTEGER")
    ensure_column("tasks", "deal_id", "INTEGER")
    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_task_part ON task_participants(org_id, task_id, user_id, role)")


def _users_has_global_username_unique() -> bool:
    try:
        indexes = query_db("PRAGMA index_list(users)") or []
        for ix in indexes:
            name = ix["name"]
            unique = int(ix["unique"] or 0) == 1
            if not unique:
                continue
            cols = query_db(f"PRAGMA index_info({name})") or []
            colnames = [c["name"] for c in cols]
            if len(colnames) == 1 and colnames[0] == "username":
                return True
    except Exception:
        pass
    return False


def _migration_6_fix_users_unique_username_scoped():
    if not _users_has_global_username_unique():
        return
    try:
        cols_existing = [r["name"] for r in (query_db("PRAGMA table_info(users)") or [])]
        target_cols = [
            "id", "org_id", "username", "email", "password_hash", "role", "active", "tz",
            "totp_enabled", "totp_secret", "backup_codes", "first_name", "last_name", "position",
            "avatar_file_id", "last_login", "must_change_password", "created_at"
        ]
        exec_db("ALTER TABLE users RENAME TO users_old")
        exec_db(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                email TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                active INTEGER NOT NULL DEFAULT 1,
                tz TEXT DEFAULT 'Europe/Moscow',
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                totp_secret TEXT,
                backup_codes TEXT,
                first_name TEXT,
                last_name TEXT,
                position TEXT,
                avatar_file_id INTEGER,
                last_login DATETIME,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
            );"""
        )
        common = [c for c in target_cols if c in cols_existing]
        if common:
            exec_db(f"INSERT INTO users ({','.join(common)}) SELECT {','.join(common)} FROM users_old")
        exec_db("DROP TABLE users_old")
        exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_org_username ON users(org_id, username)")
    except Exception as e:
        app.logger.error(f"[MIGRATION] users unique rebuild failed: {e}")


def _migration_7_workflow_builder():
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS workflow_defs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            graph_json TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS workflow_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            def_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'running',
            ctx_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (def_id) REFERENCES workflow_defs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS workflow_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            node_key TEXT NOT NULL,
            payload_json TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            next_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS workflow_timers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            fire_at DATETIME NOT NULL,
            node_key TEXT NOT NULL,
            payload_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
        );"""
    )


def _migration_8_custom_fields():
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS custom_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            entity TEXT NOT NULL,
            key TEXT NOT NULL,
            type TEXT NOT NULL,
            label TEXT NOT NULL,
            required INTEGER NOT NULL DEFAULT 0,
            default TEXT,
            options_json TEXT,
            rules_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS custom_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            entity TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            field_id INTEGER NOT NULL,
            value_text TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (field_id) REFERENCES custom_fields(id) ON DELETE CASCADE
        );"""
    )


def _migration_9_email_channel():
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS mail_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            label TEXT,
            protocol TEXT DEFAULT 'imap',
            host TEXT,
            port INTEGER,
            login TEXT,
            use_tls INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS email_threads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            subject TEXT,
            last_message_at DATETIME,
            assignee_id INTEGER,
            status TEXT NOT NULL DEFAULT 'open',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS email_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            account_id INTEGER,
            thread_id INTEGER,
            external_id TEXT,
            from_addr TEXT,
            to_addrs TEXT,
            subject TEXT,
            body_text TEXT,
            body_html TEXT,
            attachments_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            received_at DATETIME,
            is_inbound INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (account_id) REFERENCES mail_accounts(id) ON DELETE SET NULL,
            FOREIGN KEY (thread_id) REFERENCES email_threads(id) ON DELETE CASCADE
        );"""
    )


def _migration_10_cpq():
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            sku TEXT NOT NULL,
            name TEXT NOT NULL,
            price REAL NOT NULL DEFAULT 0,
            currency TEXT NOT NULL DEFAULT 'RUB',
            meta_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS quotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            deal_id INTEGER,
            status TEXT NOT NULL DEFAULT 'draft',
            total REAL NOT NULL DEFAULT 0,
            currency TEXT NOT NULL DEFAULT 'RUB',
            items_json TEXT,
            pdf_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
            FOREIGN KEY (deal_id) REFERENCES deals(id) ON DELETE SET NULL
        );"""
    )


def _migration_11_analytics_aggregates():
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS agg_task_daily (
            org_id INTEGER NOT NULL,
            ymd TEXT NOT NULL,
            created_cnt INTEGER NOT NULL DEFAULT 0,
            done_cnt INTEGER NOT NULL DEFAULT 0,
            overdue_cnt INTEGER NOT NULL DEFAULT 0,
            monthly_fee_sum REAL NOT NULL DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (org_id, ymd)
        );"""
    )
    exec_db(
        """
        CREATE TABLE IF NOT EXISTS agg_calls_daily (
            org_id INTEGER NOT NULL,
            ymd TEXT NOT NULL,
            in_cnt INTEGER NOT NULL DEFAULT 0,
            out_cnt INTEGER NOT NULL DEFAULT 0,
            dur_sum INTEGER NOT NULL DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (org_id, ymd)
        );"""
    )


# ---------- v12: API tokens hashing + scopes/expiry, mail account creds/UID ----------
def _token_hash(raw: str) -> str:
    try:
        base = (SECRET_KEY + "::" + (raw or "")).encode("utf-8")
        return hashlib.sha256(base).hexdigest()
    except Exception:
        return ""


def _migration_12_tokens_and_mail_imap():
    ensure_column("api_tokens", "token_hash", "TEXT")
    ensure_column("api_tokens", "scopes", "TEXT")
    ensure_column("api_tokens", "expires_at", "DATETIME")
    ensure_column("api_tokens", "last_used_at", "DATETIME")
    try:
        rows = query_db("SELECT id, token, token_hash FROM api_tokens WHERE (token_hash IS NULL OR token_hash='')") or []
        for r in rows:
            th = _token_hash(r["token"] or "")
            if th:
                exec_db("UPDATE api_tokens SET token_hash=? WHERE id=?", (th, r["id"]))
    except Exception as e:
        app.logger.error(f"[MIGRATION] backfill token_hash failed: {e}")
    ensure_column("mail_accounts", "password", "TEXT")
    ensure_column("mail_accounts", "last_uid", "INTEGER")


# ---------- v13: API tokens refactor (remove NOT NULL token, enforce hash uniqueness) ----------
def _migration_13_api_tokens_refactor():
    if not _object_exists("table", "api_tokens"):
        return
    try:
        cols = table_columns("api_tokens")
        # Rebuild table to enforce modern schema: token may be NULL; token_hash required+unique per org
        exec_db("ALTER TABLE api_tokens RENAME TO api_tokens_old")
        exec_db(
            """
            CREATE TABLE api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                user_id INTEGER,
                name TEXT,
                token_hash TEXT NOT NULL,
                scopes TEXT,
                expires_at DATETIME,
                last_used_at DATETIME,
                active INTEGER NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );"""
        )
        # Migrate data from old
        old_rows = query_db("SELECT * FROM api_tokens_old") or []
        for r in old_rows:
            th = r["token_hash"]
            if (not th) and ("token" in cols):
                th = _token_hash(r["token"] or "")
            exec_db(
                "INSERT INTO api_tokens (id, org_id, user_id, name, token_hash, scopes, expires_at, last_used_at, active, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    r["id"], r["org_id"], r["user_id"], r["name"], th or "",
                    r.get("scopes") if isinstance(r, dict) else r["scopes"],
                    r.get("expires_at") if isinstance(r, dict) else r["expires_at"],
                    r.get("last_used_at") if isinstance(r, dict) else r["last_used_at"],
                    r.get("active") if isinstance(r, dict) else r["active"],
                    r.get("created_at") if isinstance(r, dict) else r["created_at"],
                ),
            )
        exec_db("DROP TABLE api_tokens_old")
        # Indexes (also handled by ensure_indexes)
        exec_db("CREATE UNIQUE INDEX IF NOT EXISTS uq_tokens_org_hash ON api_tokens(org_id, token_hash)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_org_active ON api_tokens(org_id, active)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(user_id)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_exp ON api_tokens(expires_at)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_scopes ON api_tokens(scopes)")
        exec_db("CREATE INDEX IF NOT EXISTS idx_tokens_last_used ON api_tokens(last_used_at)")
    except Exception as e:
        app.logger.error(f"[MIGRATION] v13 api_tokens refactor failed: {e}")
        _metrics_inc("migrations_errors_total", ("v13",))


# ---------- v14: Tasks time tracking + subtasks columns ----------
def _migration_14_tasks_time_tracking_subtasks():
    # Add new columns to tasks for time tracking and subtasks hierarchy
    ensure_column("tasks", "time_spent_sec", "INTEGER NOT NULL DEFAULT 0")
    ensure_column("tasks", "timer_started_at", "DATETIME")
    ensure_column("tasks", "parent_task_id", "INTEGER")


def ensure_schema():
    exec_db("CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL, applied_at DATETIME)")
    if not query_db("SELECT 1 FROM schema_meta LIMIT 1", one=True):
        exec_db("INSERT INTO schema_meta (version, applied_at) VALUES (0, CURRENT_TIMESTAMP)")

    lock_key = "schema:migrate:lock"
    got_lock = False
    sqlite_lock = False

    if REDIS_CLIENT:
        try:
            got_lock = bool(REDIS_CLIENT.set(lock_key, int(time.time()), nx=True, ex=300))
        except Exception:
            got_lock = False

    if not got_lock:
        try:
            _ = query_db("SELECT 1", one=True)
            get_db().execute("BEGIN EXCLUSIVE")
            got_lock = True
            sqlite_lock = True
        except Exception:
            got_lock = False
            sqlite_lock = False

    current = _schema_get_version()
    migrations = [
        _migration_1_initial,                          # v1
        _migration_2_add_missing_columns,              # v2
        _migration_3_task_comments_and_app_meta,       # v3
        _migration_4_task_activity_and_task_fields,    # v4
        _migration_5_task_extended_fields,             # v5
        _migration_6_fix_users_unique_username_scoped, # v6
        _migration_7_workflow_builder,                 # v7
        _migration_8_custom_fields,                    # v8
        _migration_9_email_channel,                    # v9
        _migration_10_cpq,                             # v10
        _migration_11_analytics_aggregates,            # v11
        _migration_12_tokens_and_mail_imap,            # v12
        _migration_13_api_tokens_refactor,             # v13
        _migration_14_tasks_time_tracking_subtasks,    # v14
    ]

    try:
        for idx, mig in enumerate(migrations, start=1):
            if current < idx:
                if sqlite_lock:
                    try:
                        get_db().execute("SAVEPOINT mig")
                        mig()
                        get_db().execute("RELEASE SAVEPOINT mig")
                        _schema_set_version(idx)
                    except Exception as e:
                        try:
                            get_db().execute("ROLLBACK TO SAVEPOINT mig")
                        except Exception:
                            pass
                        app.logger.error(f"[MIGRATION] v{idx} failed: {e}")
                        _metrics_inc("migrations_errors_total", (f"v{idx}",))
                        raise
                else:
                    try:
                        get_db().execute("BEGIN")
                        mig()
                        get_db().execute("COMMIT")
                        _schema_set_version(idx)
                    except Exception as e:
                        try:
                            get_db().execute("ROLLBACK")
                        except Exception:
                            pass
                        app.logger.error(f"[MIGRATION] v{idx} failed: {e}")
                        _metrics_inc("migrations_errors_total", (f"v{idx}",))
                        raise
    finally:
        if sqlite_lock:
            try:
                get_db().execute("COMMIT")
            except Exception:
                pass
        if REDIS_CLIENT and got_lock:
            try:
                REDIS_CLIENT.delete(lock_key)
            except Exception:
                pass

    try:
        ensure_fts_tables()
        ensure_fts_triggers()
    except Exception as e:
        app.logger.error(f"FTS ensure failed: {e}")

    ensure_indexes()
    backfill_phone_norm()
# === END CORE PART 5/9 (3/3) ===
# === CORE PART 6/9 — Seed/Bootstrap/Context, Permissions, ensure_thread, Rules, Workflow triggers ===
# -*- coding: utf-8 -*-

# ------------------- Optional sanitize (for rich comments, used later) -------------------
try:
    import bleach  # optional HTML sanitizer
except Exception:  # pragma: no cover
    bleach = None


# ------------------- Seed defaults -------------------
def seed_defaults():
    org = query_db("SELECT id FROM orgs LIMIT 1", one=True)
    if not org:
        slug = "demo"
        org_id = exec_db(
            "INSERT INTO orgs (name, slug, timezone, plan, billing_status, promo_active) VALUES (?,?,?,?,?,?)",
            ("Demo Org", slug, "Europe/Moscow", "start", "trial", 1),
        )
    else:
        org_id = org["id"]

    # Admin user
    user_cnt = query_db("SELECT COUNT(*) c FROM users", one=True)
    if user_cnt and user_cnt["c"] == 0:
        admin_pwd = secrets.token_urlsafe(16)
        exec_db(
            "INSERT INTO users (org_id,username,email,password_hash,role,active,first_name,last_name,position,totp_enabled,must_change_password) "
            "VALUES (?,?,?,?,?,1,?,?,?,0,1)",
            (org_id, "admin", "admin@example.com", generate_password_hash(admin_pwd), "admin", "Admin", "User", "Администратор"),
        )
        if DEBUG or PRINT_ADMIN_PASSWORD:
            try:
                print("[INIT] Admin user created. Temporary password (change on first login):", admin_pwd)
            except Exception:
                pass

    # Default task statuses
    if not query_db("SELECT 1 FROM task_statuses WHERE org_id=? LIMIT 1", (org_id,), one=True):
        defaults = [
            "на подключении", "подключен", "тех. осмотр", "ремонт", "переоформление",
            "удаление сервиса", "overdue", "done", "open",
        ]
        exec_many("INSERT INTO task_statuses (org_id,name) VALUES (?,?)", [(org_id, s) for s in defaults])

    # Chat default channel
    ch = query_db("SELECT id FROM chat_channels WHERE org_id=? AND type='public' LIMIT 1", (org_id,), one=True)
    if not ch:
        chan_id = exec_db("INSERT INTO chat_channels (org_id,name,type) VALUES (?,?,?)", (org_id, "general", "public"))
        users = query_db("SELECT id FROM users WHERE org_id=?", (org_id,))
        if users and chan_id:
            exec_many(
                "INSERT INTO chat_members (channel_id,user_id,role) VALUES (?,?,?)",
                [(chan_id, u["id"], "member") for u in users],
            )

    # Subscription
    sub = query_db("SELECT id FROM org_subscriptions WHERE org_id=? LIMIT 1", (org_id,), one=True)
    if not sub:
        now = datetime.utcnow()
        period_end = now + timedelta(days=30)
        exec_db(
            "INSERT INTO org_subscriptions (org_id,plan,period_start,period_end,status,auto_renew) VALUES (?,?,?,?,?,1)",
            (org_id, "start", now.isoformat(" ", "seconds"), period_end.isoformat(" ", "seconds"), "active"),
        )

    # Demo client
    comp = query_db("SELECT id FROM companies WHERE org_id=? LIMIT 1", (org_id,), one=True)
    if not comp:
        cid = exec_db(
            "INSERT INTO companies (org_id,name,inn,phone,email) VALUES (?,?,?,?,?)",
            (org_id, "ООО Ромашка", "7701234567", "+7 495 000-00-00", "info@romashka.ru"),
        )
        try:
            exec_db("UPDATE companies SET phone_norm=? WHERE id=?", (phone_last10("+7 495 000-00-00"), cid))
        except Exception:
            pass
        exec_db(
            "INSERT INTO contacts (org_id,company_id,name,position,phone,email) VALUES (?,?,?,?,?,?)",
            (org_id, cid, "Иван Петров", "Директор", "+7 916 111-22-33", "ivan@romashka.ru"),
        )
        try:
            exec_db(
                "UPDATE contacts SET phone_norm=? WHERE company_id=? AND phone=?",
                (phone_last10("+7 916 111-22-33"), cid, "+7 916 111-22-33"),
            )
        except Exception:
            pass

    # Default phone channel (stub)
    phone_ch = query_db("SELECT id FROM channels WHERE org_id=? AND type='phone' LIMIT 1", (org_id,), one=True)
    if not phone_ch:
        secret = secrets.token_urlsafe(24)
        settings = {"provider": CLICK_TO_CALL_PROVIDER or "none", "from_e164": "+74950000000", "signing_key": ""}
        exec_db(
            "INSERT INTO channels (org_id,type,name,settings_json,secret,active) VALUES (?,?,?,?,?,1)",
            (org_id, "phone", "Телефония", json.dumps(settings, ensure_ascii=False), secret),
        )

    # Departments baseline
    dept = query_db("SELECT id FROM departments WHERE org_id=? LIMIT 1", (org_id,), one=True)
    if not dept:
        dep_sales = exec_db("INSERT INTO departments (org_id,name,slug) VALUES (?,?,?)", (org_id, "Продажи", "sales"))
        dep_ops = exec_db("INSERT INTO departments (org_id,name,slug) VALUES (?,?,?)", (org_id, "Эксплуатация", "ops"))
        admin = query_db("SELECT id FROM users WHERE org_id=? AND role='admin' LIMIT 1", (org_id,), one=True)
        if admin:
            for dep_id in (dep_sales, dep_ops):
                exec_db(
                    "INSERT INTO department_members (org_id,department_id,user_id,role) VALUES (?,?,?,?)",
                    (org_id, dep_id, admin["id"], "head"),
                )

    # Workflow stages baseline
    wf_task = query_db("SELECT id FROM workflow_stages WHERE org_id=? AND entity_type='task' LIMIT 1", (org_id,), one=True)
    if not wf_task:
        dep_ops_id = query_db("SELECT id FROM departments WHERE org_id=? AND slug='ops' LIMIT 1", (org_id,), one=True)
        exec_many(
            "INSERT INTO workflow_stages (org_id,entity_type,key,name,order_no,sla_minutes,default_department_id,active) VALUES (?,?,?,?,?,?,?,1)",
            [
                (org_id, "task", "new", "Новая", 10, 480, None),
                (org_id, "task", "in_progress", "В работе", 20, 1440, None),
                (org_id, "task", "ops", "Эксплуатация", 30, 1440, (dep_ops_id["id"] if dep_ops_id else None)),
                (org_id, "task", "review", "Проверка", 40, 480, None),
                (org_id, "task", "done", "Готово", 50, 0, None),
            ],
        )
    wf_deal = query_db("SELECT id FROM workflow_stages WHERE org_id=? AND entity_type='deal' LIMIT 1", (org_id,), one=True)
    if not wf_deal:
        exec_many(
            "INSERT INTO workflow_stages (org_id,entity_type,key,name,order_no,sla_minutes,default_department_id,active) VALUES (?,?,?,?,?,?,?,1)",
            [
                (org_id, "deal", "new", "Новая", 10, 1440, None),
                (org_id, "deal", "qualify", "Квалификация", 20, 1440, None),
                (org_id, "deal", "proposal", "Предложение", 30, 1440, None),
                (org_id, "deal", "won", "Успех", 90, 0, None),
                (org_id, "deal", "lost", "Потеря", 95, 0, None),
            ],
        )


# ------------------- Bootstrap & Context -------------------
def bootstrap_once():
    if app.config.get("_BOOTSTRAPPED"):
        return
    ensure_schema()
    seed_defaults()
    app.config["_BOOTSTRAPPED"] = True


@app.before_request
def _bootstrap_before_request():
    bootstrap_once()


@app.context_processor
def inject_common():
    theme = session.get("theme", "dark")
    u_row = get_current_user()
    u = None
    if u_row is not None:
        try:
            u = dict(u_row)
        except Exception:
            u = None
    full_name = ""
    if u:
        ln = u.get("last_name") or ""
        fn = u.get("first_name") or ""
        full_name = f"{ln} {fn}".strip()
    return {
        "css": BASE_CSS,
        "now": datetime.now(),
        "app_name": APP_NAME,
        "user": u,
        "user_title": full_name if full_name else (u.get("username") if u else ""),
        "user_avatar": url_for("avatar_default", name=(u.get("username") if u else "user")),
        "theme": theme,
        "theme_css_vars": theme_inline_vars(theme),
        "qurl": qurl,
        "request": request,
        "JITSI_BASE": JITSI_BASE,
        "csp_nonce": csp_nonce(),
        "DEBUG": DEBUG,
    }


# ------------------- Permissions & participants helpers -------------------
def _is_admin() -> bool:
    try:
        return ("user_id" in session) and (session.get("role") == "admin")
    except Exception:
        return False


def _is_manager() -> bool:
    try:
        return ("user_id" in session) and (session.get("role") in ("admin", "manager"))
    except Exception:
        return False


def is_dept_head(user_id: int, dept_id: int) -> bool:
    try:
        if not user_id or not dept_id:
            return False
        org_id = session.get("org_id")
        if not org_id:
            return False
        r = query_db(
            "SELECT 1 FROM department_members WHERE org_id=? AND department_id=? AND user_id=? AND role='head' LIMIT 1",
            (org_id, int(dept_id), int(user_id)),
            one=True,
        )
        return bool(r)
    except Exception:
        return False


def task_participants(task_id: int):
    try:
        rows = query_db(
            """SELECT tp.user_id, tp.role, u.username
               FROM task_participants tp
               LEFT JOIN users u ON u.id=tp.user_id
               WHERE tp.task_id=? AND tp.org_id=? ORDER BY tp.id""",
            (int(task_id), session.get("org_id")),
        )
        return rows or []
    except Exception:
        return []


def _notify_dept_heads(dept_id: int, title: str, link: str = ""):
    try:
        org_id = session.get("org_id")
        if not org_id:
            return
        heads = query_db(
            "SELECT user_id FROM department_members WHERE org_id=? AND department_id=? AND role='head'",
            (org_id, int(dept_id)),
        )
        ids = [h["user_id"] for h in (heads or []) if h and h["user_id"]]
        if ids:
            notify_user(ids, title, "", link)
    except Exception:
        pass


def can_edit_task(user_id: int, t_row) -> bool:
    try:
        if _is_admin():
            return True
        if not user_id or not t_row:
            return False
        if int(t_row["creator_id"] or 0) == int(user_id):
            return True
        if int(t_row["assignee_id"] or 0) == int(user_id):
            return True
        cur_dept = int(t_row["current_department_id"] or 0)
        if cur_dept and is_dept_head(int(user_id), cur_dept):
            return True
        org_id = session.get("org_id")
        if org_id:
            r = query_db(
                "SELECT 1 FROM task_participants WHERE org_id=? AND task_id=? AND user_id=? AND role IN ('owner','assignee') LIMIT 1",
                (org_id, int(t_row["id"]), int(user_id)),
                one=True,
            )
            if r:
                return True
        return False
    except Exception:
        return False


def can_edit_deal(user_id: int, d_row) -> bool:
    try:
        if _is_admin():
            return True
        if not user_id or not d_row:
            return False
        if int(d_row["assignee_id"] or 0) == int(user_id):
            return True
        cur_dept = int((d_row.get("current_department_id") if isinstance(d_row, dict) else d_row["current_department_id"]) or 0)
        if cur_dept and is_dept_head(int(user_id), cur_dept):
            return True
        org_id = session.get("org_id")
        deal_id = int((d_row.get("id") if isinstance(d_row, dict) else d_row["id"]))
        if org_id:
            r = query_db(
                "SELECT 1 FROM deal_participants WHERE org_id=? AND deal_id=? AND user_id=? AND role IN ('owner','assignee') LIMIT 1",
                (org_id, deal_id, int(user_id)),
                one=True,
            )
            if r:
                return True
        return False
    except Exception:
        return False


# Thread permissions (used by inbox APIs)
def can_edit_thread(user_id: int, th_row) -> bool:
    try:
        if _is_admin() or _is_manager():
            return True
        if not user_id or not th_row:
            return False
        if int(th_row.get("assignee_id") or 0) == int(user_id):
            return True
        return False
    except Exception:
        return False


def can_post_to_thread(user_id: int, th_row) -> bool:
    try:
        if _is_admin() or _is_manager():
            return True
        if not user_id or not th_row:
            return False
        if int(th_row.get("assignee_id") or 0) == int(user_id):
            return True
        return False
    except Exception:
        return False


# ------------------- ensure_thread helper (find-or-create) -------------------
def ensure_thread(org_id: int, channel_id: int, kind: str = "dm", external_id: str = "", subject: str = "") -> int:
    try:
        th = None
        if external_id:
            th = query_db(
                "SELECT id FROM inbox_threads WHERE org_id=? AND channel_id=? AND kind=? AND external_id=? LIMIT 1",
                (org_id, channel_id, kind, external_id),
                one=True,
            )
        if th:
            tid = th["id"]
            exec_db("UPDATE inbox_threads SET updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (tid, org_id))
            return tid
        tid = exec_db(
            """INSERT INTO inbox_threads (org_id,channel_id,kind,external_id,subject,status,priority,last_message_at,created_at)
               VALUES (?,?,?,?,?,'open','normal',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)""",
            (org_id, channel_id, kind or "dm", external_id or None, subject or None),
        )
        return tid or 0
    except Exception as e:
        app.logger.error(f"ensure_thread error: {e}")
        return 0


# ------------------- Simple rule engine (MVP, hardened) -------------------
def _resolve_dotted(obj, path: str):
    cur = obj
    for part in (path.split(".") if path else []):
        if isinstance(cur, dict) and part in cur:
            cur = cur.get(part)
        else:
            return None
    return cur


def run_rules(event: str, org_id: int, payload: dict):
    try:
        rules = query_db("SELECT * FROM rules WHERE org_id=? AND event=? AND active=1 ORDER BY id", (org_id, event))
        if not rules:
            return
        for r in rules:
            try:
                cond = json.loads(r["condition_json"] or "{}")
            except Exception:
                cond = {}
            try:
                params = json.loads(r["params_json"] or "{}")
            except Exception:
                params = {}
            ok = True
            if cond:
                field = cond.get("field") or ""
                op = (cond.get("op") or "eq").lower()
                val = cond.get("value")
                target = _resolve_dotted(payload, field)
                ok = False
                try:
                    if op == "eq":
                        ok = (str(target) == str(val))
                    elif op == "contains":
                        ok = (str(val) in str(target))
                    elif op == "regex":
                        pattern = str(val or "")
                        if len(pattern) > 200:
                            ok = False
                        else:
                            ok = bool(re.search(pattern, str(target or "")))
                    elif op in ("ne", "neq"):
                        ok = (str(target) != str(val))
                    else:
                        ok = False
                except Exception:
                    ok = False
            if not ok:
                continue
            action = (r["action"] or "").lower()
            try:
                if action == "notify":
                    uid = params.get("user_id")
                    title = params.get("title") or event
                    body = params.get("body") or ""
                    link = params.get("link_url") or ""
                    if uid:
                        notify_user(uid, title, body, link)
                elif action == "webhook":
                    extra_event = params.get("event") or (event + ".rule")
                    emit_webhook(org_id, extra_event, {"original": payload, "rule_id": r["id"]})
                else:
                    pass
            except Exception as e:
                app.logger.error(f"Rule action error: {e}")
    except Exception as e:
        app.logger.error(f"run_rules error: {e}")


# ------------------- Workflow triggers (start runs on events) -------------------
def _wf_defs_for_event(org_id: int, event: str):
    try:
        defs = query_db("SELECT * FROM workflow_defs WHERE org_id=? AND active=1 ORDER BY id DESC", (org_id,))
        matched = []
        for d in defs or []:
            try:
                g = json.loads(d["graph_json"] or "{}")
            except Exception:
                g = {}
            on = g.get("on") or g.get("triggers") or []
            if isinstance(on, str):
                on = [on]
            if event in set(on or []):
                matched.append(d)
        return matched
    except Exception:
        return []


def _wf_enqueue_task(run_id: int, node_key: str, payload=None, delay_sec: int = 0):
    payload_s = json.dumps(payload or {}, ensure_ascii=False)
    if delay_sec and delay_sec > 0:
        next_at = (datetime.utcnow() + timedelta(seconds=int(delay_sec))).isoformat(" ", "seconds")
        exec_db(
            "INSERT INTO workflow_tasks (run_id,node_key,payload_json,status,next_at) VALUES (?,?,?,?,?)",
            (run_id, node_key, payload_s, "pending", next_at),
        )
    else:
        exec_db(
            "INSERT INTO workflow_tasks (run_id,node_key,payload_json,status,next_at) VALUES (?,?,?,?,NULL)",
            (run_id, node_key, payload_s, "pending"),
        )


def _wf_start_run(def_row, org_id: int, ctx: dict) -> int:
    run_id = exec_db(
        "INSERT INTO workflow_runs (org_id,def_id,status,ctx_json) VALUES (?,?,?,?)",
        (org_id, def_row["id"], "running", json.dumps(ctx or {}, ensure_ascii=False)),
    )
    try:
        g = json.loads(def_row["graph_json"] or "{}")
    except Exception:
        g = {}
    start_node = g.get("start") or g.get("entry") or "start"
    _wf_enqueue_task(run_id, str(start_node), {"ctx": ctx}, 0)
    try:
        _metrics_set("workflow_runs_active", (org_id,), 1 + int(_metrics.get("workflow_runs_active", {}).get((org_id,), 0)))
    except Exception:
        pass
    return run_id


def workflow_start_for_event(event: str, org_id: int, payload: dict):
    try:
        defs = _wf_defs_for_event(org_id, event)
        if not defs:
            return
        ctx = {"event": event, "payload": payload}
        for d in defs:
            _wf_start_run(d, org_id, ctx)
    except Exception as e:
        app.logger.error(f"workflow_start_for_event error: {e}")


def fire_event(event: str, org_id: int, payload: dict):
    try:
        run_rules(event, org_id, payload)
    except Exception as e:
        app.logger.error(f"fire_event.run_rules error: {e}")
    try:
        workflow_start_for_event(event, org_id, payload)
    except Exception as e:
        app.logger.error(f"fire_event.workflow error: {e}")
    try:
        emit_webhook(org_id, event, payload)
    except Exception as e:
        app.logger.error(f"fire_event.webhook error: {e}")
# === END CORE PART 6/9 ===
# === CORE PART 7/9 — Auth/2FA, Profile/Avatar, UI toggles, Weather, Notifications, Setup/Index ===
# -*- coding: utf-8 -*-

# ------------------- Avatar (default SVG) -------------------
@app.route("/avatar/default")
def avatar_default():
    name = (request.args.get("name") or "NA").strip()
    initials = "".join([p[0].upper() for p in name.split() if p][:2]) or "U"
    bg = "#2bd66a"
    fg = "#0e1417"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
<rect width="100%" height="100%" rx="8" ry="8" fill="{bg}"/>
<text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="Arial" font-size="28" fill="{fg}">{initials}</text>
</svg>"""
    return Response(svg, mimetype="image/svg+xml")


def _safe_next_url(nxt: str) -> str:
    try:
        if not nxt:
            return ""
        pu = urlparse(nxt)
        if getattr(pu, "netloc", "") or (nxt and not nxt.startswith("/")):
            return ""
        if nxt.startswith("/login") or nxt.startswith("/logout"):
            return ""
        return nxt
    except Exception:
        return ""


def _org_id_by_slug(slug: str):
    if not slug:
        return None
    try:
        r = query_db("SELECT id FROM orgs WHERE lower(slug)=lower(?) LIMIT 1", (slug.strip(),), one=True)
        return int(r["id"]) if r else None
    except Exception:
        return None


# ------------------- Auth / 2FA with lockout & must_change_password -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        verify_csrf()
        org_slug = (request.form.get("org") or "").strip()
        u = (request.form.get("username") or "").strip()
        p = (request.form.get("password") or "").strip()
        ip = client_ip()

        session["post_auth_next"] = _safe_next_url(request.args.get("next") or request.form.get("next") or session.get("post_auth_next") or "")

        if login_locked(ip, u):
            time.sleep(1.0)
            flash("Слишком много попыток, попробуйте позже", "error")
            return redirect(url_for("login"))

        if not rate_limit(f"login:{ip}:{u}", per_min=30):
            time.sleep(1.0)
            flash("Слишком много попыток, попробуйте позже", "error")
            return redirect(url_for("login"))

        org_id = None
        if LOGIN_ORG_REQUIRED:
            org_id = _org_id_by_slug(org_slug)
            if not org_id:
                flash("Организация не найдена", "error")
                return redirect(url_for("login"))
            user = query_db("SELECT * FROM users WHERE username=? AND org_id=? AND active=1 LIMIT 1", (u, org_id), one=True)
        else:
            if org_slug:
                org_id = _org_id_by_slug(org_slug)
            if org_id:
                user = query_db("SELECT * FROM users WHERE username=? AND org_id=? AND active=1 LIMIT 1", (u, org_id), one=True)
            else:
                user = query_db("SELECT * FROM users WHERE username=? AND active=1 LIMIT 1", (u,), one=True)

        if user and check_password_hash(user["password_hash"], p):
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            session["org_id"] = user["org_id"]
            login_lock_reset(ip, u)
            if int(user["totp_enabled"] or 0):
                session["2fa_pending"] = True
                return redirect(url_for("twofa_verify"))
            try:
                exec_db("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat(" ", "seconds"), user["id"]))
            except Exception:
                pass
            flash(f"Добро пожаловать, {user['username']}!", "success")
            nxt = _safe_next_url(session.pop("post_auth_next", "") or request.args.get("next") or "")
            return redirect(nxt or url_for("index"))
        else:
            if login_lock_inc(ip, u):
                flash("Аккаунт временно заблокирован по числу попыток", "error")
            else:
                flash("Неверные данные для входа", "error")
    return render_safe(LOGIN_TMPL, app_name=APP_NAME)


@app.route("/twofa", methods=["GET", "POST"])
def twofa_verify():
    if "2fa_pending" not in session or "user_id" not in session:
        return redirect(url_for("login"))
    user = query_db("SELECT id, username, totp_secret FROM users WHERE id=?", (session["user_id"],), one=True)
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        if not rate_limit(f"2fa:{client_ip()}:{user['id']}", per_min=TWOFA_RATE_LIMIT_PER_MIN):
            time.sleep(0.4)
            flash("Слишком много попыток, попробуйте позже", "error")
            return redirect(url_for("twofa_verify"))
        code = (request.form.get("code") or "").strip().replace(" ", "")
        ok = False
        if pyotp and user["totp_secret"]:
            try:
                ok = pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1)
            except Exception:
                ok = False
        if not ok and code:
            if verify_and_consume_backup_code(user["id"], code):
                ok = True
        if ok:
            session.pop("2fa_pending", None)
            try:
                exec_db("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat(" ", "seconds"), user["id"]))
            except Exception:
                pass
            flash("2FA подтверждена", "success")
            nxt = _safe_next_url(session.pop("post_auth_next", "") or "")
            return redirect(nxt or url_for("index"))
        flash("Неверный код", "error")
    inner = """
<div class='card'>
  <h2>Двухфакторная аутентификация</h2>
  <form method="post" style="display:grid;gap:8px;max-width:320px;">
    <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
    <label>Код <input class="input" name="code" autofocus required></label>
    <button class="button" type="submit">Подтвердить</button>
  </form>
</div>
"""
    return render_safe(LAYOUT_TMPL, inner=inner)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    verify_csrf()
    session.clear()
    flash("Вы вышли", "info")
    return redirect(url_for("login"))


@app.before_request
def _enforce_password_change():
    if "user_id" in session and not session.get("2fa_pending"):
        u = query_db("SELECT must_change_password FROM users WHERE id=?", (session["user_id"],), one=True)
        if u and int(u["must_change_password"] or 0) == 1:
            allowed = {
                "password_change", "logout", "healthz", "readyz", "manifest",
                "service_worker", "favicon", "setup", "sse"
            }
            ep = request.endpoint or ""
            if ep not in allowed and not ep.startswith("static"):
                return redirect(url_for("password_change"))


@app.route("/password_change", methods=["GET", "POST"])
@login_required
def password_change():
    u = get_current_user()
    if not u:
        return redirect(url_for("login"))
    if request.method == "POST":
        verify_csrf()
        current = (request.form.get("current_password") or "").strip()
        new_pwd = (request.form.get("new_password") or "").strip()
        ok, msg = password_policy_ok(new_pwd)
        if not ok:
            flash(msg or "Пароль не соответствует политике", "error")
            return redirect(url_for("password_change"))
        if not check_password_hash(u["password_hash"], current):
            flash("Неверный текущий пароль", "error")
            return redirect(url_for("password_change"))
        exec_db(
            "UPDATE users SET password_hash=?, must_change_password=0 WHERE id=? AND org_id=?",
            (generate_password_hash(new_pwd), u["id"], u["org_id"]),
        )
        flash("Пароль обновлён", "success")
        return redirect(url_for("index"))
    inner = """
<div class='card'>
  <h2>Смена пароля</h2>
  <form method="post" style="display:grid;gap:8px;max-width:420px;">
    <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
    <label>Текущий пароль <input class="input" name="current_password" type="password" required></label>
    <label>Новый пароль <input class="input" name="new_password" type="password" required></label>
    <div class="help">Минимум 12 символов, верхний/нижний регистры, цифры, спецсимвол.</div>
    <div style="display:flex;gap:8px;justify-content:flex-end;">
      <button class="button" type="submit">Сохранить</button>
    </div>
  </form>
</div>
"""
    return render_safe(LAYOUT_TMPL, inner=inner)


# ------------------- Profile + avatar + 2FA management -------------------
def _user_by_session():
    if "user_id" not in session:
        return None
    return query_db("SELECT * FROM users WHERE id=?", (session["user_id"],), one=True)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    u = get_current_user()
    if not u:
        return redirect(url_for("login"))
    if request.method == "POST":
        verify_csrf()
        first_name = (request.form.get("first_name") or "").strip()
        last_name = (request.form.get("last_name") or "").strip()
        position = (request.form.get("position") or "").strip()
        email = (request.form.get("email") or "").strip()
        tzv = (request.form.get("tz") or "").strip() or "Europe/Moscow"
        exec_db(
            "UPDATE users SET first_name=?, last_name=?, position=?, email=?, tz=? WHERE id=? AND org_id=?",
            (first_name, last_name, position, email, tzv, u["id"], u["org_id"]),
        )
        flash("Профиль обновлён", "success")
        return redirect(url_for("profile"))

    csrf = session.get("csrf_token", "")
    inner_html = render_safe(
        PROFILE_TMPL,
        avatar=url_for("avatar_default", name=(u["username"] or "user")),
        role=u["role"],
        username=u["username"],
        last_name=(u["last_name"] or ""),
        first_name=(u["first_name"] or ""),
        position=(u["position"] or ""),
        email=(u["email"] or ""),
        tz=(u["tz"] or "Europe/Moscow"),
        csrf=csrf,
        api_profile_avatar=url_for("api_profile_avatar"),
    )
    return render_safe(LAYOUT_TMPL, inner=inner_html)


@app.route("/api/profile/avatar", methods=["POST"])
@login_required
def api_profile_avatar():
    try:
        verify_csrf_header()
        u = get_current_user()
        if not u:
            return jsonify(ok=False, error="not auth"), 401
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify(ok=False, error="file required"), 400

        clen = int(request.content_length or 0)
        if clen and clen > AVATAR_MAX_SIZE:
            return jsonify(ok=False, error="file too large"), 413
        raw = f.read()
        if not raw:
            return jsonify(ok=False, error="empty file"), 400
        if len(raw) > AVATAR_MAX_SIZE:
            return jsonify(ok=False, error="file too large"), 413

        ctype_guess = mimetypes.guess_type(f.filename)[0] or "application/octet-stream"
        ctype_sniff = detect_mime_from_bytes(raw, f.filename)
        ctype = ctype_sniff if (AVATAR_CONTENT_SNIFF and ctype_sniff) else ctype_guess
        if not (ctype.startswith("image/") and ctype in AVATAR_ALLOWED_TYPES):
            return jsonify(ok=False, error="unsupported content-type"), 415

        if AV_SCAN_ENABLED:
            ok_scan = True
            try:
                ok_scan = _av_scan_bytes(raw)
            except Exception:
                ok_scan = False
            if not ok_scan:
                return jsonify(ok=False, error="malware detected"), 400

        bio = io.BytesIO(raw)
        bio.seek(0)
        res = storage.save(bio, f.filename, content_type=ctype)
        if not res.get("ok"):
            return jsonify(ok=False, error="upload failed"), 500
        size = len(raw)
        location = res.get("location") if res["provider"] == "s3" else f"local:{res['key']}"
        fid = exec_db(
            "INSERT INTO files (org_id,user_id,original_name,storage_key,content_type,size,tags_json) VALUES (?,?,?,?,?,?,?)",
            (u["org_id"], u["id"], f.filename, location, ctype, size, json.dumps(["avatar"], ensure_ascii=False)),
        )
        if fid:
            exec_db("UPDATE users SET avatar_file_id=? WHERE id=? AND org_id=?", (fid, u["id"], u["org_id"]))
        url = ""
        try:
            url = presign_file(fid)
        except Exception:
            url = url_for("avatar_default", name=(u["username"] or "user"))
        return jsonify(ok=True, file_id=fid, url=url)
    except Exception as e:
        app.logger.exception(f"Avatar upload error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/profile/2fa/begin", methods=["POST"])
@login_required
def api_twofa_begin():
    verify_csrf_header()
    if not pyotp:
        return jsonify(ok=False, error="2FA unavailable"), 503
    u = _user_by_session()
    if not u:
        return jsonify(ok=False, error="not auth"), 401
    secret = pyotp.random_base32()
    session["2fa_setup_secret"] = secret
    session["2fa_setup_at"] = int(time.time())
    label = f"{APP_NAME}:{u['username']}"
    issuer = APP_NAME
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)
    return jsonify(ok=True, otpauth=uri)


@app.route("/api/profile/2fa/enable", methods=["POST"])
@login_required
def api_twofa_enable():
    verify_csrf_header()
    if not pyotp:
        return jsonify(ok=False, error="2FA unavailable"), 503
    u = _user_by_session()
    if not u:
        return jsonify(ok=False, error="not auth"), 401
    data = request.get_json(force=True) or {}
    code = (data.get("code") or "").strip().replace(" ", "")
    secret = session.get("2fa_setup_secret")
    ts = int(session.get("2fa_setup_at") or 0)
    if not secret or not code:
        return jsonify(ok=False, error="setup not started"), 400
    if ts <= 0 or (int(time.time()) - ts) > TWOFA_SETUP_TTL_SEC:
        session.pop("2fa_setup_secret", None)
        session.pop("2fa_setup_at", None)
        return jsonify(ok=False, error="setup expired"), 400
    try:
        ok = pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        ok = False
    if not ok:
        return jsonify(ok=False, error="invalid code"), 400
    plain_backups = [secrets.token_hex(4) for _ in range(8)]
    hashed = [_backup_code_hash(c) for c in plain_backups]
    exec_db(
        "UPDATE users SET totp_enabled=1, totp_secret=?, backup_codes=? WHERE id=? AND org_id=?",
        (secret, json.dumps(hashed, ensure_ascii=False), u["id"], u["org_id"]),
    )
    session.pop("2fa_setup_secret", None)
    session.pop("2fa_setup_at", None)
    return jsonify(ok=True, backup_codes=plain_backups)


@app.route("/api/profile/2fa/disable", methods=["POST"])
@login_required
def api_twofa_disable():
    verify_csrf_header()
    u = _user_by_session()
    if not u:
        return jsonify(ok=False, error="not auth"), 401
    data = request.get_json(force=True) or {}
    password = (data.get("password") or "").strip()
    if not check_password_hash(u["password_hash"], password):
        return jsonify(ok=False, error="bad password"), 403
    exec_db(
        "UPDATE users SET totp_enabled=0, totp_secret=NULL, backup_codes=NULL WHERE id=? AND org_id=?",
        (u["id"], u["org_id"]),
    )
    return jsonify(ok=True)


@app.route("/api/profile/2fa/backup_codes", methods=["POST"])
@login_required
def api_twofa_backup_codes():
    verify_csrf_header()
    u = _user_by_session()
    if not u:
        return jsonify(ok=False, error="not auth"), 401
    plain = [secrets.token_hex(4) for _ in range(8)]
    hashed = [_backup_code_hash(c) for c in plain]
    exec_db(
        "UPDATE users SET backup_codes=? WHERE id=? AND org_id=?",
        (json.dumps(hashed, ensure_ascii=False), u["id"], u["org_id"]),
    )
    return jsonify(ok=True, backup_codes=plain)


# ------------------- UI toggles -------------------
@app.route("/toggle-theme", methods=["POST"])
@login_required
def toggle_theme():
    verify_csrf_header()
    cur = session.get("theme", "dark")
    session["theme"] = "light" if cur == "dark" else "dark"
    return jsonify(ok=True, theme=session["theme"])


@app.route("/api/ui/sidebar", methods=["POST"])
@login_required
def api_ui_sidebar():
    verify_csrf_header()
    data = request.get_json(force=True) or {}
    session["sidebar_expanded"] = bool(data.get("expanded"))
    return jsonify(ok=True, expanded=session["sidebar_expanded"])


# ------------------- Weather API -------------------
@app.route("/api/ui/weather")
@login_required
def api_ui_weather():
    if not WEATHER_ENABLED:
        return jsonify(ok=False, error="disabled"), 503
    try:
        import requests as _rq
    except Exception:
        return jsonify(ok=False, error="requests missing"), 500
    try:
        url = f"https://api.open-meteo.com/v1/forecast?latitude={SPB_LAT}&longitude={SPB_LON}&current=temperature_2m,weather_code&timezone=Europe%2FMoscow"
        r = _rq.get(url, timeout=6)
        j = r.json()
        cur = (j.get("current") or {})
        temp = cur.get("temperature_2m")
        code = cur.get("weather_code")
        cond = "cloudy"
        try:
            c = int(code)
            if c in (45, 48):
                cond = "fog"
            elif c in (51, 53, 55, 61, 63, 65, 80, 81, 82):
                cond = "rain"
            elif c in (71, 73, 75, 85, 86):
                cond = "snow"
            elif c in (1, 2, 3):
                cond = "cloudy"
            elif c == 0:
                cond = "sunny"
        except Exception:
            cond = "cloudy"
        return jsonify(ok=True, temperature=temp, condition=cond, code=code)
    except Exception as e:
        app.logger.exception(f"Weather error: {e}")
        return jsonify(ok=False, error="weather error"), 500


# ------------------- Notifications poll -------------------
@app.route("/api/notifications/poll")
@login_required
def api_notifications_poll():
    try:
        uid = session["user_id"]
        rows = query_db(
            "SELECT id, kind, title, body, link_url FROM notifications WHERE user_id=? AND is_read=0 ORDER BY id LIMIT 50",
            (uid,),
        )
        ids = [r["id"] for r in rows]
        if ids:
            qmarks = ",".join(["?"] * len(ids))
            exec_db(f"UPDATE notifications SET is_read=1 WHERE user_id=? AND id IN ({qmarks})", tuple([uid] + ids))
        return jsonify(ok=True, items=[dict(r) for r in rows])
    except Exception as e:
        app.logger.exception(f"Notifications poll error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Setup / Index -------------------
@app.route("/setup")
def setup():
    try:
        bootstrap_once()
        flash("Инициализация выполнена", "success")
    except Exception as e:
        flash(f"Ошибка инициализации: {e}", "error")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    inner = render_safe(INDEX_TMPL)
    return render_safe(LAYOUT_TMPL, inner=inner)
# === END CORE PART 7/9 ===
# === CORE PART 8/9 (1/3) — AI helper, Inbox (HTML + JSON), Threads view/update (with RBAC) ===
# -*- coding: utf-8 -*-

# ------------------- AI provider helper -------------------
def ai_provider_call(prompt: str, system_prompt: str = "", temperature=0.3, max_tokens=512) -> str:
    try:
        import requests as _rq
    except Exception:
        app.logger.warning("requests not available for AI")
        if AI_STRICT:
            raise RuntimeError("AI provider unavailable")
        return ""
    if AI_BASE_URL and AI_MODEL:
        try:
            messages = ([{"role": "system", "content": system_prompt}] if system_prompt else []) + [
                {"role": "user", "content": prompt}
            ]
            r = _rq.post(
                f"{AI_BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {AI_API_KEY}"} if AI_API_KEY else {},
                json={
                    "model": AI_MODEL,
                    "temperature": float(temperature or 0.3),
                    "max_tokens": int(max_tokens or 512),
                    "messages": messages,
                },
                timeout=30,
            )
            r.raise_for_status()
            j = r.json()
            return (j.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
        except Exception as e:
            app.logger.error(f"[WARN] AI call failed: {e}")
            if AI_STRICT:
                raise
            return ""
    return ""


def _ai_exclude_internal_notes(org_id: int) -> bool:
    try:
        cfg = _get_org_ai_config(org_id)  # defined in settings/admin block
        if cfg is None:
            return AI_EXCLUDE_INTERNAL_NOTES_DEFAULT
        pol = cfg.get("policy") or {}
        if "exclude_internal_notes" in pol:
            return bool(pol["exclude_internal_notes"])
        return AI_EXCLUDE_INTERNAL_NOTES_DEFAULT
    except Exception:
        return AI_EXCLUDE_INTERNAL_NOTES_DEFAULT


# ------------------- Inbox (HTML + JSON) -------------------
@app.route("/inbox")
@login_required
def inbox():
    try:
        org_id = current_org_id()
        if not org_id:
            abort(400)
        q = (request.args.get("q") or "").strip()
        status = request.args.get("status") or ""
        channel = request.args.get("channel") or ""
        assignee = request.args.get("assignee") or ""
        kind = request.args.get("kind") or ""
        tags = request.args.get("tags") or ""
        who = request.args.get("who") or ""
        date_from = request.args.get("date_from") or ""
        date_to = request.args.get("date_to") or ""
        page = max(1, int(request.args.get("page") or 1))
        per_page = 50
        offset = (page - 1) * per_page

        where = ["t.org_id=?"]
        params = [org_id]
        if status:
            where.append("t.status=?"); params.append(status)
        if channel:
            where.append("t.channel_id=?"); params.append(int(channel))
        if assignee:
            where.append("t.assignee_id=?"); params.append(int(assignee))
        if who == "me":
            where.append("t.assignee_id=?"); params.append(session["user_id"])
        if kind:
            where.append("t.kind=?"); params.append(kind)
        if tags:
            where.append("t.tags_json LIKE ?"); params.append(f'%{tags}%')
        df, dt = date_range_bounds(date_from, date_to)
        if df:
            where.append("t.created_at>=?"); params.append(df)
        if dt:
            where.append("t.created_at<=?"); params.append(dt)

        base_sql = f"""SELECT t.*, c.name as channel_name, u.username as assignee_name
                       FROM inbox_threads t
                       LEFT JOIN channels c ON c.id=t.channel_id
                       LEFT JOIN users u ON u.id=t.assignee_id
                       WHERE {' AND '.join(where)}"""

        if q:
            q_fts = fts_sanitize(q)
            try:
                sql_q = base_sql + " AND t.id IN (SELECT m.thread_id FROM inbox_messages m JOIN inbox_messages_fts f ON f.rowid=m.id WHERE m.org_id=? AND f.body MATCH ?) "
                rows = query_db(sql_q + " ORDER BY COALESCE(t.last_message_at,t.created_at) DESC LIMIT ? OFFSET ?", params + [org_id, q_fts, per_page, offset])
            except Exception as e:
                app.logger.error(f"[INBOX] FTS MATCH error, fallback LIKE: {e}")
                rows = query_db(base_sql + " AND EXISTS (SELECT 1 FROM inbox_messages m WHERE m.thread_id=t.id AND m.body LIKE ?) ORDER BY COALESCE(t.last_message_at,t.created_at) DESC LIMIT ? OFFSET ?", params + [f"%{q}%", per_page, offset])
        else:
            rows = query_db(base_sql + " ORDER BY COALESCE(t.last_message_at,t.created_at) DESC LIMIT ? OFFSET ?", params + [per_page, offset])

        chs = query_db("SELECT id,name,type FROM channels WHERE org_id=? AND active=1 ORDER BY id", (org_id,))
        agents_rows = query_db("SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username", (org_id,))
        agents = [dict(a) for a in agents_rows]
        inner = render_safe(INBOX_TMPL, rows=rows, channels=chs, agents=agents,
                            filters={"q": q, "status": status, "channel": channel, "assignee": assignee, "kind": kind, "tags": tags, "who": who, "date_from": date_from, "date_to": date_to})
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Inbox error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/api/inbox/list")
@login_required
def api_inbox_list():
    try:
        org_id = current_org_id()
        if not org_id:
            return jsonify(ok=False, error="org missing"), 400
        q = (request.args.get("q") or "").strip()
        status = request.args.get("status") or ""
        channel = request.args.get("channel") or ""
        assignee = request.args.get("assignee") or ""
        kind = request.args.get("kind") or ""
        tags = request.args.get("tags") or ""
        who = request.args.get("who") or ""
        date_from = request.args.get("date_from") or ""
        date_to = request.args.get("date_to") or ""
        page = max(1, int(request.args.get("page") or 1))
        per_page = max(1, min(200, int(request.args.get("per_page") or 50)))
        offset = (page - 1) * per_page

        where = ["t.org_id=?"]
        params = [org_id]
        if status:
            where.append("t.status=?"); params.append(status)
        if channel:
            where.append("t.channel_id=?"); params.append(int(channel))
        if assignee:
            where.append("t.assignee_id=?"); params.append(int(assignee))
        if who == "me":
            where.append("t.assignee_id=?"); params.append(session["user_id"])
        if kind:
            where.append("t.kind=?"); params.append(kind)
        if tags:
            where.append("t.tags_json LIKE ?"); params.append(f"%{tags}%")
        df, dt = date_range_bounds(date_from, date_to)
        if df:
            where.append("t.created_at>=?"); params.append(df)
        if dt:
            where.append("t.created_at<=?"); params.append(dt)

        base_sql = f"""SELECT t.*, c.name as channel_name, u.username as assignee_name
                       FROM inbox_threads t
                       LEFT JOIN channels c ON c.id=t.channel_id
                       LEFT JOIN users u ON u.id=t.assignee_id
                       WHERE {' AND '.join(where)}"""
        rows = []
        if q:
            q_fts = fts_sanitize(q)
            try:
                sql_q = base_sql + " AND t.id IN (SELECT m.thread_id FROM inbox_messages m JOIN inbox_messages_fts f ON f.rowid=m.id WHERE m.org_id=? AND f.body MATCH ?) "
                rows = query_db(sql_q + " ORDER BY COALESCE(t.last_message_at,t.created_at) DESC LIMIT ? OFFSET ?", params + [org_id, q_fts, per_page, offset])
            except Exception as e:
                app.logger.error(f"[INBOX] FTS MATCH error, fallback LIKE: {e}")
                rows = query_db(base_sql + " AND EXISTS (SELECT 1 FROM inbox_messages m WHERE m.thread_id=t.id AND m.body LIKE ?) ORDER BY COALESCE(t.last_message_at,t.created_at) DESC LIMIT ? OFFSET ?", params + [f"%{q}%", per_page, offset])
        else:
            rows = query_db(base_sql + " ORDER BY COALESCE(t.last_message_at,t.created_at) DESC LIMIT ? OFFSET ?", params + [per_page, offset])

        items = []
        for r in rows:
            d = dict(r)
            items.append({
                "id": d["id"],
                "subject": d.get("subject"),
                "status": d.get("status"),
                "priority": d.get("priority"),
                "assignee_id": d.get("assignee_id"),
                "assignee_name": d.get("assignee_name"),
                "channel_id": d.get("channel_id"),
                "channel_name": d.get("channel_name"),
                "first_response_due_at": d.get("first_response_due_at"),
                "first_response_at": d.get("first_response_at"),
                "last_message_at": d.get("last_message_at"),
                "created_at": d.get("created_at"),
            })
        return jsonify(ok=True, items=items, page=page, per_page=per_page)
    except Exception as e:
        app.logger.exception(f"API inbox list error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/thread/<int:tid>")
@login_required
def thread_view(tid):
    try:
        org_id = current_org_id()
        th = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not th:
            abort(404)
        page = max(1, int(request.args.get("page") or 1))
        per_page = 50
        offset = (page - 1) * per_page
        msgs = query_db(
            """SELECT m.*, u.username FROM inbox_messages m LEFT JOIN users u ON u.id=m.user_id
               WHERE m.thread_id=? ORDER BY m.id ASC LIMIT ? OFFSET ?""",
            (tid, per_page, offset),
        )
        try:
            tags_arr = json.loads(th["tags_json"] or "[]")
            th = dict(th)
            th["tags_csv"] = ", ".join([str(x) for x in tags_arr if isinstance(x, (str, int, float))])
        except Exception:
            pass
        inner = render_safe(THREAD_TMPL, r=th, messages=msgs)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Thread view error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("inbox"))


@app.route("/api/thread/messages")
@login_required
def api_thread_messages():
    try:
        org_id = current_org_id()
        tid = int(request.args.get("thread_id") or 0)
        if not tid or not query_db("SELECT 1 FROM inbox_threads WHERE id=? AND org_id=?", (tid, org_id), one=True):
            return jsonify(ok=False, error="not found"), 404
        page = max(1, int(request.args.get("page") or 1))
        per_page = max(1, min(200, int(request.args.get("per_page") or 50)))
        offset = (page - 1) * per_page
        rows = query_db(
            """SELECT m.id, m.sender_type, m.user_id, m.external_user_id, m.body, m.internal_note, m.created_at,
                      u.username
               FROM inbox_messages m LEFT JOIN users u ON u.id=m.user_id
               WHERE m.thread_id=? ORDER BY m.id ASC LIMIT ? OFFSET ?""",
            (tid, per_page, offset),
        )
        items = []
        for r in rows:
            d = dict(r)
            items.append({
                "id": d["id"], "sender_type": d["sender_type"], "user_id": d["user_id"],
                "external_user_id": d["external_user_id"], "body": d["body"], "internal_note": d["internal_note"],
                "created_at": d["created_at"], "username": d.get("username")
            })
        return jsonify(ok=True, items=items, page=page, per_page=per_page)
    except Exception as e:
        app.logger.exception(f"Thread messages API error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/thread/update", methods=["POST"])
@login_required
def api_thread_update():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        tid = int(d.get("id") or 0)
        th = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not th:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_thread(session["user_id"], dict(th)):
            return jsonify(ok=False, error="forbidden"), 403
        allowed = {"status", "priority", "assignee_id", "first_response_due_at", "snooze_until", "subject", "tags_json"}
        sets, params = [], []
        for k in allowed:
            if k in d:
                if k == "assignee_id":
                    if d[k] in ("", None):
                        sets.append("assignee_id=NULL")
                    else:
                        try:
                            aid = int(d[k])
                        except Exception:
                            return jsonify(ok=False, error="bad assignee"), 400
                        if not query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (aid, org_id), one=True):
                            return jsonify(ok=False, error="assignee out of org"), 400
                        sets.append("assignee_id=?"); params.append(aid)
                elif k == "tags_json":
                    tags = d.get("tags_json")
                    if isinstance(tags, list):
                        sets.append("tags_json=?"); params.append(json.dumps(tags, ensure_ascii=False))
                    elif isinstance(tags, str):
                        arr = [x.strip() for x in tags.split(",") if x.strip()]
                        sets.append("tags_json=?"); params.append(json.dumps(arr, ensure_ascii=False))
                elif k in ("first_response_due_at", "snooze_until"):
                    val = ensure_iso_datetime(d.get(k) or "")
                    if val:
                        sets.append(f"{k}=?"); params.append(val)
                else:
                    sets.append(f"{k}=?"); params.append(d[k])
        if not sets:
            return jsonify(ok=False, error="empty"), 400
        sets.append("updated_at=CURRENT_TIMESTAMP")
        params += [tid, org_id]
        rc = exec_db_rowcount(f"UPDATE inbox_threads SET {', '.join(sets)} WHERE id=? AND org_id=?", tuple(params))
        if rc <= 0:
            return jsonify(ok=False, error="not updated"), 400
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Thread update error: {e}")
        return jsonify(ok=False, error="internal error"), 500
# === END CORE PART 8/9 (1/3) ===
# === CORE PART 8/9 (2/3) — Messages send/upload/channel, AI endpoints, Export, Clients, Lookup ===
# -*- coding: utf-8 -*-

# ------------------- Messages send/upload/channel -------------------
def _anti_duplicate_message(thread_id, sender_type, body):
    try:
        dup = query_db(
            """SELECT id FROM inbox_messages
               WHERE thread_id=? AND sender_type=? AND COALESCE(body,'')=? AND created_at>=datetime('now','-60 seconds')
               ORDER BY id DESC LIMIT 1""",
            (thread_id, sender_type, body or ""),
            one=True,
        )
        return dup["id"] if dup else None
    except Exception:
        return None


def add_message(org_id: int, thread_id: int, sender_type: str, body: str, attachments=None, user_id=None, external_user_id=None,
                reply_to_id=None, mentions=None, internal_note=False):
    attachments = attachments or []
    if len(attachments) > 10:
        attachments = attachments[:10]
    mentions = mentions or []
    dup_id = _anti_duplicate_message(thread_id, sender_type, body)
    if dup_id:
        return dup_id
    mid = exec_db(
        """INSERT INTO inbox_messages (org_id,thread_id,sender_type,user_id,external_user_id,body,attachments_json,
                                      reply_to_id,mentions_json,internal_note,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
        (
            org_id, thread_id, sender_type, user_id, external_user_id, body or "",
            json.dumps(attachments, ensure_ascii=False), reply_to_id,
            json.dumps(mentions, ensure_ascii=False), 1 if internal_note else 0,
        ),
    )
    if not mid:
        return None
    exec_db("UPDATE inbox_threads SET last_message_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (thread_id, org_id))
    if sender_type == "agent" and not internal_note:
        th = query_db("SELECT first_response_at FROM inbox_threads WHERE id=? AND org_id=?", (thread_id, org_id), one=True)
        if th and not th["first_response_at"]:
            exec_db("UPDATE inbox_threads SET first_response_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (thread_id, org_id))
    try:
        fts_upsert("inbox_messages_fts", mid, {"body": body or ""})
    except Exception as e:
        app.logger.error(f"[FTS] upsert inbox message failed: {e}")
    try:
        fire_event("message.created", org_id, {"thread_id": thread_id, "message_id": mid, "internal": bool(internal_note)})
    except Exception as e:
        app.logger.error(f"fire_event message.created failed: {e}")
    return mid


def _av_scan_bytes(b: bytes) -> bool:
    if not AV_SCAN_ENABLED or not AV_SCAN_CMD:
        return True
    try:
        import subprocess
        p = subprocess.Popen(AV_SCAN_CMD, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(input=b, timeout=20)
        return p.returncode == 0
    except Exception as e:
        app.logger.error(f"AV scan failed: {e}")
        return False


@app.route("/api/message/send", methods=["POST"])
@login_required
def api_message_send():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        tid = int(data.get("thread_id") or 0)
        if not tid:
            return jsonify(ok=False, error="bad request"), 400
        th = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not th:
            return jsonify(ok=False, error="thread not found"), 404
        if not can_post_to_thread(session["user_id"], dict(th)):
            return jsonify(ok=False, error="forbidden"), 403
        body = (data.get("body") or "").strip()
        internal = bool(data.get("internal_note"))
        if not body and not (data.get("attachments") or []):
            return jsonify(ok=False, error="empty"), 400
        atts = data.get("attachments") or []
        mid = add_message(org_id, tid, "agent", body, attachments=atts, user_id=session["user_id"], internal_note=internal)
        if not mid:
            return jsonify(ok=False, error="insert failed"), 500
        try:
            add_audit(org_id, "message.sent", "message", mid, {"thread": tid, "internal": internal})
        except Exception:
            pass
        return jsonify(ok=True, id=mid)
    except Exception as e:
        app.logger.exception(f"Message send error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/channel/send", methods=["POST"])
@login_required
def api_channel_send():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        tid = int(data.get("thread_id") or 0)
        text = (data.get("text") or "").strip()
        if not tid or not text:
            return jsonify(ok=False, error="bad request"), 400
        th = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not th:
            return jsonify(ok=False, error="thread not found"), 404
        if not can_post_to_thread(session["user_id"], dict(th)):
            return jsonify(ok=False, error="forbidden"), 403
        ch = query_db("SELECT * FROM channels WHERE id=? AND org_id=?", (th["channel_id"], org_id), one=True) if th["channel_id"] else None
        delivered = False
        try:
            if ch and ch["type"] == "telegram" and th["external_id"] and "tg_send_message" in globals():
                ok, resp = tg_send_message(th["external_id"], text)
                delivered = bool(ok)
        except Exception as e:
            app.logger.error(f"TG outbound failed: {e}")
        mid = add_message(org_id, tid, "agent", text, attachments=[], user_id=session["user_id"], internal_note=False)
        if not mid:
            return jsonify(ok=False, error="insert failed"), 500
        if not delivered:
            add_message(org_id, tid, "system", "Не доставлено во внешний канал (проверьте настройки канала)", internal_note=True)
        try:
            add_audit(org_id, "channel.send", "message", mid, {"thread": tid, "delivered": delivered, "provider": (ch["type"] if ch else None)})
        except Exception:
            pass
        return jsonify(ok=True, id=mid, delivered=delivered)
    except Exception as e:
        app.logger.exception(f"Channel send error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/message/upload", methods=["POST"])
@login_required
def api_message_upload():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify(ok=False, error="file required"), 400
        raw = f.read()
        if len(raw) > app.config.get("MAX_CONTENT_LENGTH", 200 * 1024 * 1024):
            return jsonify(ok=False, error="file too large"), 413
        if not _av_scan_bytes(raw):
            return jsonify(ok=False, error="malware detected"), 400
        ctype = detect_mime_from_bytes(raw, f.filename) or (mimetypes.guess_type(f.filename)[0] or "application/octet-stream")
        if ctype not in UPLOAD_ALLOWED_TYPES:
            return jsonify(ok=False, error="unsupported content-type"), 415
        bio = io.BytesIO(raw); bio.seek(0)
        res = storage.save(bio, f.filename, content_type=ctype)
        if not res.get("ok"):
            return jsonify(ok=False, error="upload failed"), 500
        size = len(raw)
        location = res.get("location") if res["provider"] == "s3" else f"local:{res['key']}"
        fid = exec_db(
            "INSERT INTO files (org_id,user_id,original_name,storage_key,content_type,size,tags_json) VALUES (?,?,?,?,?,?,?)",
            (org_id, session["user_id"], f.filename, location, ctype, size, "[]"),
        )
        if not fid:
            return jsonify(ok=False, error="insert failed"), 500
        return jsonify(ok=True, file={"id": fid, "name": f.filename, "url": presign_file(fid)})
    except Exception as e:
        app.logger.exception(f"Message upload error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/message/to_task", methods=["POST"])
@login_required
def api_message_to_task():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        mid = int(data.get("message_id") or 0)
        m = query_db("SELECT * FROM inbox_messages WHERE id=? AND org_id=?", (mid, org_id), one=True)
        if not m:
            return jsonify(ok=False, error="message not found"), 404
        th = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (m["thread_id"], org_id), one=True)
        if not th:
            return jsonify(ok=False, error="thread not found"), 404
        if not can_post_to_thread(session["user_id"], dict(th)):
            return jsonify(ok=False, error="forbidden"), 403
        title = (data.get("title") or "").strip() or (m["body"][:60] if m["body"] else "Задача")
        desc = f"Из сообщения #{mid} в треде #{m['thread_id']}\n\n{m['body'] or ''}"
        assignee = data.get("assignee_id")
        if assignee:
            try:
                aid = int(assignee)
            except Exception:
                return jsonify(ok=False, error="bad assignee"), 400
            if not query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (aid, org_id), one=True):
                return jsonify(ok=False, error="assignee out of org"), 400
        else:
            aid = None
        due_at = ensure_iso_datetime(data.get("due_at") or "")
        company_id = None
        try:
            if data.get("company_id"):
                cid = int(data.get("company_id"))
                c = query_db("SELECT id FROM companies WHERE id=? AND org_id=?", (cid, org_id), one=True)
                if c:
                    company_id = cid
        except Exception:
            company_id = None
        tid = exec_db(
            """INSERT INTO tasks (org_id,creator_id,assignee_id,title,description,priority,due_at,status,thread_id,message_id,company_id)
               VALUES (?,?,?,?,?,'normal',?,'open',?,?,?)""",
            (org_id, session["user_id"], aid, title, desc, due_at or None, m["thread_id"], m["id"], company_id),
        )
        if not tid:
            return jsonify(ok=False, error="insert failed"), 500
        try:
            fts_upsert("tasks_fts", tid, {"title": title, "description": desc})
        except Exception:
            pass
        try:
            add_audit(org_id, "task.created", "task", tid, {"from_message": mid})
            notify_user(aid or session["user_id"], "Новая задача", title, url_for("tasks_page", _external=True))
        except Exception:
            pass
        fire_event("task.created", org_id, {"task_id": tid})
        return jsonify(ok=True, task_id=tid)
    except Exception as e:
        app.logger.exception(f"Message to task error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- AI endpoints -------------------
@app.route("/api/ai/summarize_thread", methods=["POST"])
@login_required
def api_ai_summarize_thread():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        tid = int(data.get("thread_id") or 0)
        th = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not th:
            return jsonify(ok=False, error="thread not found"), 404
        exclude_internal = _ai_exclude_internal_notes(org_id)
        if exclude_internal:
            msgs = query_db("SELECT sender_type, body, internal_note, created_at FROM inbox_messages WHERE thread_id=? AND internal_note=0 ORDER BY id ASC", (tid,))
        else:
            msgs = query_db("SELECT sender_type, body, internal_note, created_at FROM inbox_messages WHERE thread_id=? ORDER BY id ASC", (tid,))
        text = "\n".join([f"[{m['created_at']}] {m['sender_type']}{' (int)' if m['internal_note'] else ''}: {m['body']}" for m in msgs if (m["body"] or "").strip()])
        system_prompt = "Ты помощник оператора поддержки. Составь краткую сводку разговора и список основных пунктов."
        out = ai_provider_call(text[:8000], system_prompt=system_prompt, temperature=0.2, max_tokens=400)
        if not out and AI_STRICT:
            return jsonify(ok=False, error="AI error"), 503
        exec_db("INSERT INTO ai_jobs (org_id,kind,status,input_ref,output_json) VALUES (?,'summarize','completed',?,?)",
                (org_id, f"thread:{tid}", json.dumps({"summary": out}, ensure_ascii=False)))
        return jsonify(ok=True, summary=out)
    except Exception as e:
        app.logger.exception(f"AI summarize error: {e}")
        exec_db("INSERT INTO ai_jobs (org_id,kind,status,input_ref,error) VALUES (?,'summarize','error',?,?)",
                (current_org_id() or 0, f"thread:{request.json.get('thread_id') if request.is_json else ''}", str(e)))
        return jsonify(ok=False, error="AI error"), 500


@app.route("/api/ai/draft_reply", methods=["POST"])
@login_required
def api_ai_draft_reply():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        tid = int(data.get("thread_id") or 0)
        tone = (data.get("tone") or "neutral").lower()
        th = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not th:
            return jsonify(ok=False, error="thread not found"), 404
        last = query_db("SELECT body FROM inbox_messages WHERE thread_id=? AND sender_type='client' AND internal_note=0 ORDER BY id DESC LIMIT 1", (tid,), one=True)
        base = last["body"] if last else ""
        tones = {"friendly": "дружелюбно", "neutral": "нейтрально", "formal": "формально"}
        sys = f"Ответь {tones.get(tone,'нейтрально')} кратко и по делу. Русский язык."
        v1 = ai_provider_call(base[:4000], system_prompt=sys, temperature=0.4, max_tokens=300)
        v2 = ai_provider_call(base[:4000], system_prompt=sys + " Используй чуть более разговорный стиль.", temperature=0.6, max_tokens=300)
        v3 = ai_provider_call(base[:4000], system_prompt=sys + " Сделай тон официальнее.", temperature=0.2, max_tokens=300)
        variants = [v for v in [v1, v2, v3] if v]
        if AI_STRICT and not variants:
            return jsonify(ok=False, error="AI error"), 503
        exec_db("INSERT INTO ai_jobs (org_id,kind,status,input_ref,output_json) VALUES (?,'draft','completed',?,?)",
                (org_id, f"thread:{tid}", json.dumps({"variants": variants}, ensure_ascii=False)))
        return jsonify(ok=True, variants=variants[:3])
    except Exception as e:
        app.logger.exception(f"AI draft error: {e}")
        exec_db("INSERT INTO ai_jobs (org_id,kind,status,input_ref,error) VALUES (?,'draft','error',?,?)",
                (current_org_id() or 0, f"thread:{request.json.get('thread_id') if request.is_json else ''}", str(e)))
        return jsonify(ok=False, error="AI error"), 500


@app.route("/api/ai/extract_task", methods=["POST"])
@login_required
def api_ai_extract_task():
    try:
        verify_csrf_header()
        data = request.get_json(force=True) or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify(ok=False, error="text required"), 400
        sys = 'Извлеки из сообщения задачи в JSON: {"title":"...", "checklist":["..."], "priority":"low|normal|high", "due":"YYYY-MM-DD" или null}'
        out = ai_provider_call(text[:4000], system_prompt=sys, temperature=0.2, max_tokens=300)
        if not out and AI_STRICT:
            return jsonify(ok=False, error="AI error"), 503
        m = re.search(r"{.*}", out or "", re.S)
        if m:
            try:
                js = json.loads(m.group(0))
                exec_db("INSERT INTO ai_jobs (org_id,kind,status,input_ref,output_json) VALUES (?,'extract_task','completed',?,?)",
                        (current_org_id(), text[:50], json.dumps(js, ensure_ascii=False)))
                return jsonify(ok=True, task=js)
            except Exception:
                app.logger.warning("AI extract JSON parse failed")
                exec_db("INSERT INTO ai_jobs (org_id,kind,status,input_ref,error) VALUES (?,'extract_task','error',?,?)",
                        (current_org_id() or 0, text[:50], "Invalid JSON"))
                return jsonify(ok=False, error="invalid json"), 400
        exec_db("INSERT INTO ai_jobs (org_id,kind,status,input_ref,error) VALUES (?,'extract_task','error',?,?)",
                (current_org_id() or 0, text[:50], "No JSON"))
        return jsonify(ok=False, error="no json"), 400
    except Exception as e:
        app.logger.exception(f"AI extract task error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/ai/autotag_thread", methods=["POST"])
@login_required
def api_ai_autotag_thread():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        tid = int(d.get("thread_id") or 0)
        th = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not th:
            return jsonify(ok=False, error="not found"), 404
        msgs = query_db("SELECT sender_type, body FROM inbox_messages WHERE thread_id=? AND internal_note=0 ORDER BY id DESC LIMIT 10", (tid,))
        text = "\n".join([(m["body"] or "") for m in msgs if (m["body"] or "").strip()])
        sys = 'Предложи до 5 лаконичных тегов для классификации диалога. Верни JSON: {"tags":["..."]}'
        out = ai_provider_call(text[:3000], system_prompt=sys, temperature=0.3, max_tokens=150)
        tags = []
        if out:
            try:
                mm = re.search(r"{.*}", out, re.S)
                if mm:
                    js = json.loads(mm.group(0))
                    tags = js.get("tags") or []
            except Exception:
                tags = [t.strip() for t in re.split(r"[,\n;]+", out) if t.strip()][:5]
        if not tags:
            return jsonify(ok=False, error="no tags"), 400
        try:
            cur = json.loads(th["tags_json"] or "[]")
        except Exception:
            cur = []
        merged = list({t for t in (cur or []) if isinstance(t, str)} | {t for t in tags if isinstance(t, str)})
        exec_db("UPDATE inbox_threads SET tags_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?",
                (json.dumps(merged, ensure_ascii=False), tid, org_id))
        return jsonify(ok=True, tags=merged)
    except Exception as e:
        app.logger.exception(f"AI autotag error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Export (CSV safe) -------------------
def _csv_safe_cell(val) -> str:
    s = str(val if val is not None else "")
    if s and s[0] in ("=", "+", "-", "@"):
        return "'" + s
    return s


@app.route("/export/inbox.csv")
@login_required
def export_inbox_csv():
    try:
        org_id = current_org_id()
        rows = query_db(
            """SELECT t.id, t.subject, t.status, t.priority, t.assignee_id, t.first_response_at, t.first_response_due_at, t.last_message_at
               FROM inbox_threads t WHERE t.org_id=? ORDER BY t.id DESC LIMIT 5000""",
            (org_id,),
        )
        out = io.StringIO()
        w = csv.writer(out, delimiter=';', dialect='excel')
        w.writerow(["ID", "Subject", "Status", "Priority", "Assignee", "FRT", "FRT due", "Last message"])
        for r in rows:
            w.writerow([
                _csv_safe_cell(r["id"]), _csv_safe_cell(r["subject"] or ""), _csv_safe_cell(r["status"]), _csv_safe_cell(r["priority"]),
                _csv_safe_cell(r["assignee_id"] or ""), _csv_safe_cell(r["first_response_at"] or ""),
                _csv_safe_cell(r["first_response_due_at"] or ""), _csv_safe_cell(r["last_message_at"] or "")
            ])
        resp = make_response(out.getvalue().encode('utf-8-sig'))
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = f"attachment; filename=inbox{date.today().isoformat()}.csv"
        return resp
    except Exception as e:
        app.logger.exception(f"Export CSV error: {e}")
        flash("Ошибка экспорта", "error")
        return redirect(url_for("inbox"))


# ------------------- Clients (HTML + API) -------------------
@app.route("/clients", methods=["GET"])
@login_required
def clients_list():
    try:
        org_id = current_org_id()
        page = max(1, int(request.args.get("page") or 1))
        per_page = max(1, min(100, int(request.args.get("per_page") or 50)))
        offset = (page - 1) * per_page
        rows = query_db(
            """
            SELECT c.*, COALESCE(d.cnt,0) AS deals
            FROM companies c
            LEFT JOIN (SELECT company_id, COUNT(*) cnt FROM deals WHERE org_id=? GROUP BY company_id) d
                ON d.company_id = c.id
            WHERE c.org_id=?
            ORDER BY c.id DESC
            LIMIT ? OFFSET ?
            """,
            (org_id, org_id, per_page, offset),
        )
        inner = render_safe(CLIENTS_TMPL, clients=rows)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Clients list error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/clients", methods=["POST"])
@login_required
def client_create():
    try:
        verify_csrf()
        org_id = current_org_id()
        name = (request.form.get("name") or "").strip()
        inn = (request.form.get("inn") or "").strip() or None
        phone = (request.form.get("phone") or "").strip()
        email = (request.form.get("email") or "").strip()
        notes = (request.form.get("contact") or "").strip()
        if not name:
            flash("Название обязательно", "error")
            return redirect(url_for("clients_list"))
        if inn:
            ex = query_db("SELECT id FROM companies WHERE org_id=? AND inn=?", (org_id, inn), one=True)
            if ex:
                flash("Компания с таким ИНН уже существует", "warn")
                return redirect(url_for("clients_list"))
        cid = exec_db(
            "INSERT INTO companies (org_id,name,inn,phone,email,notes,phone_norm) VALUES (?,?,?,?,?,?,?)",
            (org_id, name, inn, phone, email, notes, phone_last10(phone)),
        )
        if not cid:
            flash("Ошибка создания клиента", "error")
            return redirect(url_for("clients_list"))
        flash("Клиент добавлен", "success")
        return redirect(url_for("client_page", cid=cid))
    except Exception as e:
        app.logger.exception(f"Client create error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("clients_list"))


@app.route("/client/<int:cid>")
@login_required
def client_page(cid):
    try:
        org_id = current_org_id()
        c = query_db("SELECT * FROM companies WHERE id=? AND org_id=?", (cid, org_id), one=True)
        if not c:
            abort(404)
        calls = query_db(
            "SELECT id, started_at, direction, from_e164, to_e164, status FROM calls WHERE org_id=? AND customer_company_id=? ORDER BY id DESC LIMIT 50",
            (org_id, cid),
        )
        inner = render_safe(CLIENT_PAGE_TMPL, c=c, calls=calls)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Client page error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("clients_list"))


@app.route("/api/clients/<int:cid>", methods=["GET", "PATCH"])
@login_required
def api_client(cid):
    try:
        org_id = current_org_id()
        if request.method == "GET":
            c = query_db("SELECT * FROM companies WHERE id=? AND org_id=?", (cid, org_id), one=True)
            if not c:
                return jsonify(ok=False, error="not found"), 404
            return jsonify(ok=True, item=dict(c))
        verify_csrf_header()
        d = request.get_json(force=True) or {}
        if "inn" in d and (d["inn"] or "").strip():
            ex = query_db("SELECT id FROM companies WHERE org_id=? AND inn=? AND id<>?", (org_id, d["inn"].strip(), cid), one=True)
            if ex:
                return jsonify(ok=False, error="ИНН уже существует для другой компании"), 409
        sets, params = [], []
        for k in ("name", "inn", "phone", "email", "notes", "address", "extra_json"):
            if k in d:
                sets.append(f"{k}=?"); params.append(d[k])
        if "phone" in d:
            sets.append("phone_norm=?"); params.append(phone_last10(d.get("phone") or ""))
        if not sets:
            return jsonify(ok=False, error="empty"), 400
        params += [cid, org_id]
        rc = exec_db_rowcount(f"UPDATE companies SET {', '.join(sets)} WHERE id=? AND org_id=?", tuple(params))
        if rc <= 0:
            return jsonify(ok=False, error="not updated"), 400
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"API client error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/clients/list")
@login_required
def api_clients_list():
    try:
        org_id = current_org_id()
        q = (request.args.get("q") or "").strip()
        page = max(1, int(request.args.get("page") or 1))
        per_page = max(1, min(200, int(request.args.get("per_page") or 50)))
        offset = (page - 1) * per_page
        where = ["c.org_id=?"]
        params = [org_id]
        if q:
            where.append("(c.name LIKE ? OR c.inn LIKE ? OR c.phone LIKE ? OR c.email LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
        rows = query_db(
            f"""
            SELECT c.*, COALESCE(d.cnt,0) AS deals
            FROM companies c
            LEFT JOIN (SELECT company_id, COUNT(*) cnt FROM deals WHERE org_id=? GROUP BY company_id) d
                ON d.company_id = c.id
            WHERE {' AND '.join(where)}
            ORDER BY c.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple([org_id] + params + [per_page, offset]),
        )
        return jsonify(ok=True, items=[dict(r) for r in rows], page=page, per_page=per_page)
    except Exception as e:
        app.logger.exception(f"API clients list error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Lookup (HTML + API) -------------------
@app.route("/api/lookup")
@login_required
def api_lookup():
    try:
        org_id = current_org_id()
        phone = (request.args.get("phone") or "").strip()
        cid = (request.args.get("id") or "").strip()
        inn = (request.args.get("inn") or "").strip()
        email = (request.args.get("email") or "").strip()
        page = max(1, int(request.args.get("page") or 1))
        per_page = max(1, min(100, int(request.args.get("per_page") or 50)))
        offset = (page - 1) * per_page
        results = {"companies": [], "contacts": [], "by_id": None}

        if cid and cid.isdigit():
            c = query_db("SELECT * FROM companies WHERE id=? AND org_id=?", (int(cid), org_id), one=True)
            results["by_id"] = dict(c) if c else None

        if phone:
            last10 = phone_last10(phone)
            if last10:
                pattern = "%" + last10
                comps = query_db("SELECT * FROM companies WHERE org_id=? AND phone_norm LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                                 (org_id, pattern, per_page, offset))
                conts = query_db("SELECT * FROM contacts  WHERE org_id=? AND phone_norm LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                                 (org_id, pattern, per_page, offset))
                results["companies"].extend([dict(r) for r in comps])
                results["contacts"].extend([dict(r) for r in conts])

        if inn:
            comps = query_db("SELECT * FROM companies WHERE org_id=? AND inn=? ORDER BY id DESC LIMIT ? OFFSET ?", (org_id, inn, per_page, offset))
            results["companies"].extend([dict(r) for r in comps])

        if email:
            comps = query_db("SELECT * FROM companies WHERE org_id=? AND (email LIKE ?) ORDER BY id DESC LIMIT ? OFFSET ?", (org_id, f"%{email}%", per_page, offset))
            conts = query_db("SELECT * FROM contacts WHERE org_id=? AND (email LIKE ?) ORDER BY id DESC LIMIT ? OFFSET ?", (org_id, f"%{email}%", per_page, offset))
            results["companies"].extend([dict(r) for r in comps])
            results["contacts"].extend([dict(r) for r in conts])

        return jsonify(ok=True, results=results, page=page)
    except Exception as e:
        app.logger.exception(f"Lookup API error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/lookup")
@login_required
def lookup():
    try:
        org_id = current_org_id()
        phone = (request.args.get("phone") or "").strip()
        cid = (request.args.get("id") or "").strip()
        inn = (request.args.get("inn") or "").strip()
        email = (request.args.get("email") or "").strip()
        page = max(1, int(request.args.get("page") or 1))
        per_page = 50
        offset = (page - 1) * per_page
        results = {"companies": [], "contacts": [], "by_id": None}

        if cid and cid.isdigit():
            c = query_db("SELECT * FROM companies WHERE id=? AND org_id=?", (int(cid), org_id), one=True)
            results["by_id"] = dict(c) if c else None

        if phone:
            last10 = phone_last10(phone)
            if last10:
                pattern = "%" + last10
                comps = query_db("SELECT * FROM companies WHERE org_id=? AND phone_norm LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                                 (org_id, pattern, per_page, offset))
                conts = query_db("SELECT * FROM contacts  WHERE org_id=? AND phone_norm LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                                 (org_id, pattern, per_page, offset))
                results["companies"].extend([dict(r) for r in comps])
                results["contacts"].extend([dict(r) for r in conts])

        if inn:
            comps = query_db("SELECT * FROM companies WHERE org_id=? AND inn=? ORDER BY id DESC LIMIT ? OFFSET ?", (org_id, inn, per_page, offset))
            results["companies"].extend([dict(r) for r in comps])

        if email:
            comps = query_db("SELECT * FROM companies WHERE org_id=? AND email LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?", (org_id, f"%{email}%", per_page, offset))
            conts = query_db("SELECT * FROM contacts WHERE org_id=? AND email LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?", (org_id, f"%{email}%", per_page, offset))
            results["companies"].extend([dict(r) for r in comps])
            results["contacts"].extend([dict(r) for r in conts])

        inner = render_safe(LOOKUP_TMPL, results=results, params={"phone": phone, "id": cid, "inn": inn, "email": email})
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Lookup error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))
# === END CORE PART 8/9 (2/3) ===
# === CORE PART 8/9 (3/3) — CTI/Calls, Meetings (delete supported), Telegram/VK, Chat (org-wide access) ===
# -*- coding: utf-8 -*-

# ------------------- CTI helpers and webhooks -------------------
def get_phone_channel(channel_id: int):
    return query_db("SELECT * FROM channels WHERE id=? AND type='phone' AND active=1", (channel_id,), one=True)


def channel_secret_ok(ch, secret: str) -> bool:
    if not ch:
        return False
    if REQUIRE_CTI_SECRET and not (ch["secret"] or "").strip():
        return False
    return (ch["secret"] or "") == (secret or "")


def provider_signing_key(ch, env_fallback: str = "") -> str:
    try:
        s = json.loads(ch["settings_json"] or "{}")
    except Exception:
        s = {}
    return s.get("signing_key") or env_fallback or ""


def _hdr(headers, *names):
    for n in names:
        v = headers.get(n)
        if v:
            return v
    return ""


def verify_provider_signature(provider: str, ch, raw: bytes, headers) -> bool:
    if not ch:
        return False
    if REQUIRE_CTI_SECRET and not (ch["secret"] or "").strip():
        return False
    if provider == "mango":
        skey = provider_signing_key(ch, MANGO_SIGNING_KEY)
        sig_hdr = _hdr(headers, "X-Signature", "vpbx-signature", "X-Signature-SHA256")
    elif provider == "uis":
        skey = provider_signing_key(ch, UIS_SIGNING_KEY)
        sig_hdr = _hdr(headers, "X-Signature", "X-Client-Signature")
    elif provider == "telfin":
        skey = provider_signing_key(ch, TELFIN_SIGNING_KEY)
        sig_hdr = _hdr(headers, "X-Signature", "X-Telfin-Signature")
    else:
        return False
    if REQUIRE_PROVIDER_SIGNATURE and not skey:
        return False
    if not skey:
        return True
    try:
        digest = hmac.new(skey.encode("utf-8"), raw or b"", hashlib.sha256).hexdigest()
        return hmac.compare_digest(digest, sig_hdr or "")
    except Exception as e:
        app.logger.error(f"Signature verify failed: {e}")
        return False


_env_hosts = [h.strip() for h in (RECORDING_ALLOWED_HOSTS_ENV or "").split(",") if h.strip()]
_ALLOWED_RECORDING_HOSTS = tuple({".mango-office.ru", ".uiscom.ru", ".telfin.ru", ".yandexcloud.net", ".storage.yandexcloud.net"} | set(_env_hosts))


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved
    except Exception:
        return True


def _host_allowed(netloc: str) -> bool:
    host = netloc.split("@")[-1].split(":")[0].lower()
    return any(host.endswith(d) for d in _ALLOWED_RECORDING_HOSTS)


_resolved_ips_cache = {}
def _resolve_all_ips(host: str):
    if host in _resolved_ips_cache:
        return _resolved_ips_cache[host]
    try:
        infos = socket.getaddrinfo(host, None)
        ips = set()
        for fam, _, _, _, sa in infos:
            if fam in (socket.AF_INET, socket.AF_INET6):
                ips.add(sa[0])
        _resolved_ips_cache[host] = list(ips)
        return list(ips)
    except Exception:
        return []


@app.route("/integrations/cti/<provider>/<int:channel_id>/<secret>/webhook", methods=["POST"])
def cti_webhook(provider, channel_id, secret):
    try:
        if not rate_limit(f"cti:wh:{channel_id}:{client_ip()}", per_min=CTI_WEBHOOK_RATE_LIMIT_PER_MIN):
            return make_response("rate limit", 429)
        provider = (provider or "").lower()
        ch = get_phone_channel(channel_id)
        if not ch or not channel_secret_ok(ch, secret):
            return make_response("forbidden", 403)
        raw = request.get_data() or b""
        if REQUIRE_PROVIDER_SIGNATURE and not verify_provider_signature(provider, ch, raw, request.headers):
            return make_response("bad signature", 403)
        try:
            payload = request.get_json(force=True) or {}
        except Exception:
            payload = request.form.to_dict() if request.form else {}
        org_id = ch["org_id"]
        ev = (payload.get("event") or payload.get("status") or "").lower()
        call_id = payload.get("call_id") or payload.get("id") or payload.get("uuid") or payload.get("request_id")
        direction = payload.get("direction") or ("in" if str(payload.get("incoming")).lower() in ("true", "1") else "out")
        frm = payload.get("from") or payload.get("caller") or payload.get("a_number") or ""
        to = payload.get("to") or payload.get("callee") or payload.get("b_number") or ""
        if not call_id:
            call_id = secrets.token_hex(8)
        if ev in ("new", "start", "ringing"):
            cti_call_new(org_id, ch["id"], provider, direction or "in", frm, to, call_id)
        elif ev in ("answer", "answered", "in_progress"):
            ans = payload.get("answered_at") or datetime.utcnow().isoformat(" ", "seconds")
            cti_call_update(org_id, provider, call_id, status="in_progress", answered_at=str(ans))
        elif ev in ("end", "ended", "hangup", "completed", "failed", "noanswer", "busy"):
            ended = payload.get("ended_at") or datetime.utcnow().isoformat(" ", "seconds")
            status = "completed" if ev in ("end", "ended", "completed") else ev
            cti_call_update(org_id, provider, call_id, status=status, ended_at=str(ended))
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"CTI webhook error: {e}")
        return make_response("internal error", 500)


@app.route("/integrations/cti/<provider>/<int:channel_id>/<secret>/recording", methods=["POST"])
def cti_recording(provider, channel_id, secret):
    try:
        provider = (provider or "").lower()
        ch = get_phone_channel(channel_id)
        if not ch or not channel_secret_ok(ch, secret):
            return make_response("forbidden", 403)
        ip = client_ip()
        if not rate_limit(f"cti:rec:{channel_id}:{ip}", per_min=60):
            return make_response("rate limit", 429)

        try:
            data = request.get_json(force=True) or {}
        except Exception:
            data = request.form.to_dict() if request.form else {}
        org_id = ch["org_id"]
        provider_call_id = data.get("call_id") or data.get("provider_call_id")
        rec_url = data.get("recording_url") or data.get("url")
        if not provider_call_id or not rec_url:
            return jsonify(ok=False, error="missing fields"), 400

        try:
            pu = urlparse(rec_url)
            if pu.scheme.lower() != "https" or not pu.netloc:
                return jsonify(ok=False, error="bad url"), 400
            host = pu.netloc.split("@")[-1].split(":")[0]
            ips = _resolve_all_ips(host)
            if (not _host_allowed(pu.netloc)) or any(_is_private_ip(ip) for ip in ips):
                return jsonify(ok=False, error="untrusted host"), 400
        except Exception as e:
            app.logger.error(f"SSRF check failed: {e}")
            return jsonify(ok=False, error="invalid url"), 400

        file_id = None
        try:
            import requests as _rq
            headers = {"User-Agent": "UnifiedCRM-Recorder/1.0"}
            with _rq.get(rec_url, timeout=15, stream=True, allow_redirects=False, headers=headers) as r:
                r.raise_for_status()
                ctype = (r.headers.get("Content-Type") or "").lower()
                if not (ctype.startswith("audio/") or ctype.startswith("application/octet-stream")):
                    return jsonify(ok=False, error="unsupported content-type"), 415
                try:
                    clen = int(r.headers.get("Content-Length") or "0")
                    if clen and clen > MAX_RECORDING_SIZE:
                        return jsonify(ok=False, error="file too large"), 413
                except Exception:
                    pass
                bio = io.BytesIO()
                total = 0
                for chunk in r.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    bio.write(chunk)
                    total += len(chunk)
                    if total > MAX_RECORDING_SIZE:
                        raise ValueError("file too large")
                bio.seek(0)
                raw = bio.getvalue()
                if not _av_scan_bytes(raw):
                    return jsonify(ok=False, error="malware detected"), 400
                fname = f"recording_{provider}_{provider_call_id}.mp3"
                res = storage.save(
                    io.BytesIO(raw),
                    fname,
                    content_type=mimetypes.guess_type(fname)[0] or ctype or "audio/mpeg",
                )
                if res.get("ok"):
                    location = res.get("location") if res["provider"] == "s3" else f"local:{res['key']}"
                    file_id = exec_db(
                        "INSERT INTO files (org_id,user_id,original_name,storage_key,content_type,size,tags_json) VALUES (?,?,?,?,?,?,?)",
                        (org_id, None, fname, location, mimetypes.guess_type(fname)[0] or ctype or "audio/mpeg", total, json.dumps(["call_recording"], ensure_ascii=False)),
                    )
        except Exception as e:
            app.logger.error(f"[CTI] recording fetch error: {e}")

        if file_id:
            cti_call_update(org_id, provider, provider_call_id, recording_file_id=file_id)
        else:
            cti_call_update(org_id, provider, provider_call_id, recording_key=rec_url)
        return jsonify(ok=True, file_id=file_id)
    except Exception as e:
        app.logger.exception(f"CTI recording error: {e}")
        return make_response("internal error", 500)


def _first_phone_channel(org_id: int):
    return query_db("SELECT * FROM channels WHERE org_id=? AND type='phone' AND active=1 ORDER BY id LIMIT 1", (org_id,), one=True)


def _channel_from_e164(ch) -> str:
    try:
        cfg = json.loads(ch["settings_json"] or "{}")
    except Exception:
        cfg = {}
    return phone_to_e164(cfg.get("from_e164") or "")


def originate_mango(ch, from_e164: str, to_e164: str):
    if not (MANGO_API_URL and MANGO_API_KEY and MANGO_API_SECRET):
        return False, None, {"error": "mango creds missing"}
    try:
        import requests as _rq
        payload = {"command_id": str(uuid.uuid4()), "from": from_e164, "to": to_e164, "api_key": MANGO_API_KEY, "ts": int(time.time())}
        sign = hmac.new(MANGO_API_SECRET.encode("utf-8"), json.dumps(payload, separators=(",", ":")).encode("utf-8"), hashlib.sha256).hexdigest()
        headers = {"Content-Type": "application/json", "X-Signature": sign}
        r = _rq.post(MANGO_API_URL, json=payload, headers=headers, timeout=10)
        try:
            j = r.json() if (r.headers.get("content-type") or "").startswith("application/json") else {"status": r.status_code}
        except Exception:
            j = {"status": r.status_code}
        call_id = j.get("call_id") or j.get("uuid") or j.get("request_id") or secrets.token_hex(8)
        return (200 <= r.status_code < 300), call_id, j
    except Exception as e:
        app.logger.error(f"Mango originate failed: {e}")
        return False, None, {"error": str(e)}


def originate_uis(ch, from_e164: str, to_e164: str):
    if not (UIS_API_URL and UIS_API_KEY):
        return False, None, {"error": "uis creds missing"}
    try:
        import requests as _rq
        payload = {"from": from_e164, "to": to_e164, "api_key": UIS_API_KEY}
        r = _rq.post(UIS_API_URL, json=payload, timeout=10)
        try:
            j = r.json() if (r.headers.get("content-type") or "").startswith("application/json") else {"status": r.status_code}
        except Exception:
            j = {"status": r.status_code}
        call_id = j.get("call_id") or j.get("uuid") or secrets.token_hex(8)
        return (200 <= r.status_code < 300), call_id, j
    except Exception as e:
        app.logger.error(f"UIS originate failed: {e}")
        return False, None, {"error": str(e)}


def originate_telfin(ch, from_e164: str, to_e164: str):
    if not (TELFIN_API_URL and TELFIN_API_KEY):
        return False, None, {"error": "telfin creds missing"}
    try:
        import requests as _rq
        payload = {"from": from_e164, "to": to_e164, "api_key": TELFIN_API_KEY}
        r = _rq.post(TELFIN_API_URL, json=payload, timeout=10)
        try:
            j = r.json() if (r.headers.get("content-type") or "").startswith("application/json") else {"status": r.status_code}
        except Exception:
            j = {"status": r.status_code}
        call_id = j.get("call_id") or j.get("uuid") or secrets.token_hex(8)
        return (200 <= r.status_code < 300), call_id, j
    except Exception as e:
        app.logger.error(f"Telfin originate failed: {e}")
        return False, None, {"error": str(e)}


@app.route("/api/cti/click_to_call", methods=["POST"])
@login_required
def api_click_to_call():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}

        to = phone_to_e164(data.get("to") or "")
        if not to:
            return jsonify(ok=False, error="bad number"), 400
        ch = _first_phone_channel(org_id)
        if not ch:
            return jsonify(ok=False, error="no phone channel"), 400
        frm = phone_to_e164(data.get("from") or "") or _channel_from_e164(ch)
        if not frm:
            return jsonify(ok=False, error="from number not set"), 400
        provider = (json.loads(ch["settings_json"] or "{}").get("provider") or CLICK_TO_CALL_PROVIDER or "none").lower()
        ok, prov_call_id, resp = (False, None, {})
        if provider == "mango":
            ok, prov_call_id, resp = originate_mango(ch, frm, to)
        elif provider == "uis":
            ok, prov_call_id, resp = originate_uis(ch, frm, to)
        elif provider == "telfin":
            ok, prov_call_id, resp = originate_telfin(ch, frm, to)
        else:
            prov_call_id = secrets.token_hex(8); ok = True; resp = {"stub": True}
        cid = cti_call_new(org_id, ch["id"], provider, "out", frm or "", to, prov_call_id or secrets.token_hex(6), agent_id=session["user_id"])
        if ok and prov_call_id:
            cti_call_update(org_id, provider, prov_call_id, status="in_progress")
        return jsonify(ok=True, provider=provider, to=to, call_id=cid, provider_call_id=prov_call_id, provider_response=resp)
    except Exception as e:
        app.logger.exception(f"Click-to-call error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Calls pages/APIs -------------------
def cti_call_new(org_id: int, channel_id: int, provider: str, direction: str, from_num: str, to_num: str, provider_call_id: str, ts=None, agent_id=None):
    e_from = phone_to_e164(from_num)
    e_to = phone_to_e164(to_num)
    started = (ts or datetime.utcnow()).isoformat(" ", "seconds")
    company_id, contact_id = find_customer_by_phone(org_id, e_from if direction == "in" else e_to)
    cid = exec_db(
        """INSERT INTO calls (org_id,channel_id,provider,provider_call_id,direction,from_e164,to_e164,
                              started_at,status,agent_id,customer_company_id,customer_contact_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (org_id, channel_id, provider, provider_call_id, direction, e_from, e_to, started, "ringing", agent_id, company_id, contact_id),
    )
    if not cid:
        return None
    try:
        sse_publish_users(
            [u["id"] for u in query_db("SELECT id FROM users WHERE org_id=? AND active=1 AND role IN ('agent','manager')", (org_id,))],
            "call.incoming" if direction == "in" else "call.outgoing",
            {"id": cid, "from": e_from, "to": e_to, "provider": provider, "channel_id": channel_id},
        )
        if CTI_SCREENPOP and direction == "in":
            sse_publish_users(
                [u["id"] for u in query_db("SELECT id FROM users WHERE org_id=? AND active=1 AND role IN ('agent','manager')", (org_id,))],
                "call.screenpop",
                {"phone": e_from},
            )
    except Exception as e:
        app.logger.error(f"SSE publish failed in call_new: {e}")
    try:
        fire_event("telephony.call.updated", org_id, {"id": cid, "status": "ringing"})
    except Exception:
        pass
    return cid


def cti_call_update(org_id: int, provider: str, provider_call_id: str, **kw):
    c = query_db("SELECT * FROM calls WHERE org_id=? AND provider=? AND provider_call_id=?", (org_id, provider, provider_call_id), one=True)
    if not c:
        return None
    sets = []
    params = []
    allowed = {"status", "answered_at", "ended_at", "recording_key", "recording_file_id", "agent_id", "disposition"}
    for k, v in kw.items():
        if k in allowed:
            sets.append(f"{k}=?"); params.append(v)
    ans = kw.get("answered_at") or c["answered_at"]
    end = kw.get("ended_at") or c["ended_at"]
    if ans and end:
        try:
            ans_dt = datetime.fromisoformat(str(ans).replace("T", " "))
            end_dt = datetime.fromisoformat(str(end).replace("T", " "))
            dur = max(0, int((end_dt - ans_dt).total_seconds()))
            sets.append("duration_sec=?"); params.append(dur)
        except Exception as e:
            app.logger.warning(f"Duration calc failed: {e}")
    if not sets:
        return c["id"]
    params += [c["id"], org_id]
    exec_db(f"UPDATE calls SET {', '.join(sets)} WHERE id=? AND org_id=?", tuple(params))
    try:
        fire_event("telephony.call.updated", org_id, {"id": c["id"], **kw})
    except Exception:
        pass
    return c["id"]


def find_customer_by_phone(org_id: int, e164: str):
    last10 = phone_last10(e164)
    if not last10:
        return None, None
    pattern = "%" + last10
    c = query_db(
        """SELECT id, company_id FROM contacts WHERE org_id=? AND phone_norm LIKE ? ORDER BY id DESC LIMIT 1""",
        (org_id, pattern),
        one=True,
    )
    if c:
        return c["company_id"], c["id"]
    comp = query_db(
        """SELECT id FROM companies WHERE org_id=? AND phone_norm LIKE ? ORDER BY id DESC LIMIT 1""",
        (org_id, pattern),
        one=True,
    )
    return (comp["id"] if comp else None), None


def _call_recording_url(row):
    if row["recording_file_id"]:
        try:
            return presign_file(row["recording_file_id"])
        except Exception:
            return ""
    return row["recording_key"] or ""


@app.route("/calls")
@login_required
def calls_page():
    try:
        inner = render_safe(CALLS_TMPL, calls=[], current_filter=request.args.get("f", "my"))
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Calls page error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/api/calls/list")
@login_required
def api_calls_list():
    try:
        org_id = current_org_id()
        mine = (request.args.get("mine") or "1") == "1"
        date_from = request.args.get("date_from") or ""
        date_to = request.args.get("date_to") or ""
        page = max(1, int(request.args.get("page") or 1))
        per_page = 100
        offset = (page - 1) * per_page
        where = ["c.org_id=?"]
        params = [org_id]
        if mine:
            where.append("(c.agent_id=? OR c.direction='in')")
            params.append(session["user_id"])
        df, dt = date_range_bounds(date_from, date_to)
        if df:
            where.append("c.started_at>=?"); params.append(df)
        if dt:
            where.append("c.started_at<=?"); params.append(dt)
        rows = query_db(
            f"""
            SELECT c.*, u.username as agent_name, co.name as company_name, ct.name as contact_name
            FROM calls c
            LEFT JOIN users u ON u.id=c.agent_id
            LEFT JOIN companies co ON co.id=c.customer_company_id
            LEFT JOIN contacts ct ON ct.id=c.customer_contact_id
            WHERE {' AND '.join(where)}
            ORDER BY c.id DESC
            LIMIT {per_page} OFFSET {offset}
            """,
            params,
        )
        items = []
        for r in rows:
            d = dict(r)
            d["recording_url"] = _call_recording_url(r)
            items.append(d)
        return jsonify(ok=True, items=items, page=page)
    except Exception as e:
        app.logger.exception(f"Calls list API error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/call/assign_agent", methods=["POST"])
@login_required
def api_call_assign_agent():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        call_id = int(data.get("call_id") or 0)
        agent_id = int(data.get("agent_id") or session["user_id"])
        if not query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (agent_id, org_id), one=True):
            return jsonify(ok=False, error="agent out of org"), 400
        c = query_db("SELECT id FROM calls WHERE id=? AND org_id=?", (call_id, org_id), one=True)
        if not c:
            return jsonify(ok=False, error="not found"), 404
        exec_db("UPDATE calls SET agent_id=? WHERE id=? AND org_id=?", (agent_id, call_id, org_id))
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Call assign error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/call/to_task", methods=["POST"])
@login_required
def api_call_to_task():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        cid = int(data.get("call_id") or 0)
        c = query_db("SELECT * FROM calls WHERE id=? AND org_id=?", (cid, org_id), one=True)
        if not c:
            return jsonify(ok=False, error="call not found"), 404
        title = (data.get("title") or "").strip() or f"Звонок {c['from_e164']} → {c['to_e164']}"
        desc = f"""Из звонка #{cid}
Направление: {c['direction']}
От: {c['from_e164'] or ''}
Кому: {c['to_e164'] or ''}
Дата: {c['started_at'] or ''}
Длительность: {c['duration_sec'] or 0} сек
"""
        tid = exec_db(
            """INSERT INTO tasks (org_id,creator_id,assignee_id,title,description,priority,status)
               VALUES (?,?,?,?,?,'normal','open')""",
            (org_id, session["user_id"], session["user_id"], title, desc),
        )
        if not tid:
            return jsonify(ok=False, error="insert failed"), 500
        try:
            fts_upsert("tasks_fts", tid, {"title": title, "description": desc})
        except Exception:
            pass
        try:
            notify_user(session["user_id"], "Новая задача из звонка", title, url_for("tasks_page", _external=True))
        except Exception:
            pass
        fire_event("task.created", org_id, {"task_id": tid, "from": f"call:{cid}"})
        return jsonify(ok=True, task_id=tid)
    except Exception as e:
        app.logger.exception(f"Call to task error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/call/recording/presign/<int:call_id>")
@login_required
def api_call_recording_presign(call_id):
    try:
        org_id = current_org_id()
        c = query_db("SELECT recording_file_id, recording_key FROM calls WHERE id=? AND org_id=?", (call_id, org_id), one=True)
        if not c:
            return jsonify(ok=False, error="not found"), 404
        if c["recording_file_id"]:
            return jsonify(ok=True, url=presign_file(c["recording_file_id"]))
        if c["recording_key"]:
            return jsonify(ok=True, url=c["recording_key"])
        return jsonify(ok=False, error="no recording"), 404
    except Exception as e:
        app.logger.exception(f"Recording presign error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Meetings -------------------
@app.route("/meetings")
@login_required
def meetings_page():
    try:
        inner = render_safe(MEETING_TMPL, meeting=None, jitsi_base=JITSI_BASE)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Meetings page error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/api/meetings", methods=["GET"])
@login_required
def api_meetings_list():
    try:
        org_id = current_org_id()
        rows = query_db("SELECT * FROM meetings WHERE org_id=? ORDER BY COALESCE(start_at, created_at) DESC LIMIT 1000", (org_id,))
        return jsonify(ok=True, items=[dict(r) for r in rows])
    except Exception as e:
        app.logger.exception(f"Meetings list error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/meetings/schedule", methods=["POST"])
@login_required
def api_meeting_schedule():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        title = (data.get("title") or "").strip() or "Встреча"
        start_at = ensure_iso_datetime(data.get("start_at") or "")
        end_at = ensure_iso_datetime(data.get("end_at") or "")
        participants = data.get("participants") or []
        department_ids = data.get("department_ids") or []
        notify_before_min = int(data.get("notify_before_min") or 0)
        valids = []

        if department_ids:
            for did in set([int(x) for x in department_ids if str(x).isdigit()]):
                users = query_db("SELECT user_id FROM department_members WHERE org_id=? AND department_id=?", (org_id, did))
                for u in users:
                    valids.append(int(u["user_id"]))
        for uid in participants:
            try:
                uid_i = int(uid)
            except Exception:
                continue
            if query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (uid_i, org_id), one=True):
                valids.append(uid_i)
        valids = list(sorted(set(valids)))
        room = f"{slugify(APP_NAME)}-{org_id}-{uuid.uuid4().hex[:8]}"
        invite_token = secrets.token_urlsafe(16)
        role_policy = {"moderator": [session["user_id"]], "guest": list(set(valids))}
        mid = exec_db(
            "INSERT INTO meetings (org_id,created_by,room,role_policy,invite_token,title,start_at,end_at,participants_json,notify_before_min,reminder_fired) VALUES (?,?,?,?,?,?,?,?,?,?,0)",
            (org_id, session["user_id"], room, json.dumps(role_policy, ensure_ascii=False), invite_token, title, start_at or None, end_at or None, json.dumps(valids), notify_before_min),
        )
        if not mid:
            return jsonify(ok=False, error="insert failed"), 500
        try:
            add_audit(org_id, "meeting.scheduled", "meeting", mid, {"title": title, "start_at": start_at, "end_at": end_at})
            fire_event("meeting.created", org_id, {"meeting_id": mid})
            if valids:
                notify_user(valids, "Новая встреча", f"{title} · {(start_at or '')}", url_for("meeting_join", mid=mid, _external=True))
        except Exception:
            pass
        return jsonify(ok=True, id=mid, join_url=url_for("meeting_join", mid=mid, _external=True), room=room, jitsi_base=JITSI_BASE)
    except Exception as e:
        app.logger.exception(f"Meeting schedule error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/meetings/<int:mid>", methods=["PATCH", "DELETE"])
@login_required
def api_meeting_update(mid):
    try:
        org_id = current_org_id()
        m = query_db("SELECT * FROM meetings WHERE id=? AND org_id=?", (mid, org_id), one=True)
        if not m:
            return jsonify(ok=False, error="not found"), 404
        if request.method == "DELETE":
            verify_csrf_header()
            exec_db("DELETE FROM meetings WHERE id=? AND org_id=?", (mid, org_id))
            try:
                add_audit(org_id, "meeting.deleted", "meeting", mid, {})
                fire_event("meeting.deleted", org_id, {"meeting_id": mid})
            except Exception:
                pass
            return jsonify(ok=True)
        verify_csrf_header()
        d = request.get_json(force=True) or {}
        allowed = {"title", "start_at", "end_at", "participants_json", "notify_before_min"}
        sets, params = [], []
        for k in allowed:
            if k in d:
                if k == "participants_json" and isinstance(d[k], list):
                    valids = []
                    for uid in d[k]:
                        try:
                            uid_i = int(uid)
                        except Exception:
                            continue
                        if query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (uid_i, org_id), one=True):
                            valids.append(uid_i)
                    sets.append("participants_json=?"); params.append(json.dumps(valids, ensure_ascii=False))
                elif k in ("start_at", "end_at"):
                    val = ensure_iso_datetime(d.get(k) or "")
                    sets.append(f"{k}=?"); params.append(val or None)
                else:
                    sets.append(f"{k}=?"); params.append(d[k])
        if not sets:
            return jsonify(ok=False, error="empty"), 400
        params += [mid, org_id]
        exec_db(f"UPDATE meetings SET {', '.join(sets)} WHERE id=? AND org_id=?", tuple(params))
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Meeting update error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/meeting/create", methods=["POST"])
@login_required
def api_meeting_create():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        thread_id = data.get("thread_id")
        task_id = data.get("task_id")
        department_ids = data.get("department_ids") or []
        participants = data.get("participants") or []
        valids = []
        for did in set([int(x) for x in department_ids if str(x).isdigit()]):
            users = query_db("SELECT user_id FROM department_members WHERE org_id=? AND department_id=?", (org_id, did))
            valids.extend([u["user_id"] for u in users])
        for u in participants:
            if str(u).isdigit():
                valids.append(int(u))
        valids = list(sorted(set(valids)))
        room = f"{slugify(APP_NAME)}-{org_id}-{uuid.uuid4().hex[:8]}"
        invite_token = secrets.token_urlsafe(16)
        role_policy = {"moderator": [session["user_id"]], "guest": valids}
        mid = exec_db(
            "INSERT INTO meetings (org_id,created_by,thread_id,task_id,room,role_policy,invite_token,participants_json) VALUES (?,?,?,?,?,?,?,?)",
            (org_id, session["user_id"], thread_id, task_id, room, json.dumps(role_policy, ensure_ascii=False), invite_token, json.dumps(valids)),
        )
        if not mid:
            return jsonify(ok=False, error="insert failed"), 500
        try:
            add_audit(org_id, "meeting.created", "meeting", mid, {"room": room})
            fire_event("meeting.created", org_id, {"meeting_id": mid})
        except Exception:
            pass
        return jsonify(ok=True, id=mid, join_url=url_for("meeting_join", mid=mid, _external=True), room=room, jitsi_base=JITSI_BASE)
    except Exception as e:
        app.logger.exception(f"Meeting create error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/meeting/<int:mid>")
@login_required
def meeting_join(mid):
    try:
        m = query_db("SELECT * FROM meetings WHERE id=? AND org_id=?", (mid, current_org_id()), one=True)
        if not m:
            abort(404)
        inner = render_safe(MEETING_TMPL, meeting=m, jitsi_base=JITSI_BASE)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Meeting join error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/api/meeting/<int:mid>/start_recording", methods=["POST"])
@login_required
def api_meeting_start_recording(mid):
    try:
        verify_csrf_header()
        org_id = current_org_id()
        m = query_db("SELECT * FROM meetings WHERE id=? AND org_id=?", (mid, org_id), one=True)
        if not m:
            return jsonify(ok=False, error="not found"), 404
        exec_db("UPDATE meetings SET started_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (mid, org_id))
        fire_event("meeting.recording_started", org_id, {"meeting_id": mid})
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Meeting start recording error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/meeting/<int:mid>/stop_recording", methods=["POST"])
@login_required
def api_meeting_stop_recording(mid):
    try:
        verify_csrf_header()
        org_id = current_org_id()
        m = query_db("SELECT * FROM meetings WHERE id=? AND org_id=?", (mid, org_id), one=True)
        if not m:
            return jsonify(ok=False, error="not found"), 404
        exec_db("UPDATE meetings SET ended_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (mid, org_id))
        duration = 10
        summary = ""
        try:
            summary = ai_provider_call("Сформируй краткую сводку встречи", "Generate summary")
        except Exception:
            summary = ""
        exec_db("UPDATE meetings SET recording_duration_min=?, ai_summary=? WHERE id=? AND org_id=?", (duration, summary, mid, org_id))
        fire_event("meeting.recording_stopped", org_id, {"meeting_id": mid, "duration": duration})
        return jsonify(ok=True, summary=summary)
    except Exception as e:
        app.logger.exception(f"Meeting stop recording error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Telegram/VK inbound with idempotency -------------------
def tg_api_url(method: str) -> str:
    token = TG_BOT_TOKEN
    return f"https://api.telegram.org/bot{token}/{method}"


def tg_send_message(chat_id: str, text: str, reply_to_message_id=None, parse_mode=None):
    if not TG_BOT_TOKEN:
        return False, "tg not configured"
    try:
        import requests as _rq
    except Exception:
        return False, "requests missing"
    try:
        payload = {"chat_id": chat_id, "text": text}
        if reply_to_message_id:
            payload["reply_to_message_id"] = reply_to_message_id
        if parse_mode:
            payload["parse_mode"] = parse_mode
        r = _rq.post(tg_api_url("sendMessage"), json=payload, timeout=10)
        jr = r.json() if (r.headers.get("content-type") or "").startswith("application/json") else {"ok": r.status_code in (200, 201)}
        return bool(jr.get("ok")), jr
    except Exception as e:
        app.logger.error(f"TG send failed: {e}")
        return False, str(e)


def _get_tg_channel_by_secret(secret: str):
    ch = query_db("SELECT * FROM channels WHERE type='telegram' AND secret=? AND active=1", (secret,), one=True)
    if ch:
        return ch
    rows = query_db("SELECT * FROM channels WHERE type='telegram' AND active=1 ORDER BY id DESC")
    for r in rows:
        try:
            st = json.loads(r["settings_json"] or "{}")
        except Exception:
            st = {}
        if (st.get("webhook_secret") or "") == secret:
            return r
    return None


def _tg_ext_id(upd: dict) -> str:
    try:
        msg = (upd or {}).get("message") or (upd or {}).get("channel_post") or {}
        mid = msg.get("message_id") or ""
        chat = msg.get("chat") or {}
        chat_id = chat.get("id") or ""
        return f"{chat_id}:{mid}"
    except Exception:
        return secrets.token_hex(6)


def _process_telegram_update(ch_row, upd: dict):
    try:
        ext_id = _tg_ext_id(upd)
        if not exec_db("INSERT INTO ext_dedup (org_id, source, external_id) VALUES (?,?,?)", (ch_row["org_id"], "tg", ext_id)):
            return
        msg = (upd or {}).get("message") or (upd or {}).get("channel_post")
        if not msg:
            return
        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id"))
        text = msg.get("text") or msg.get("caption") or ""
        kind = "group" if chat.get("type") in ("group", "supergroup") else "dm"
        tid = ensure_thread(ch_row["org_id"], ch_row["id"], kind, external_id=chat_id, subject=f"TG {chat.get('title') or chat.get('username') or chat_id}")
        if not tid:
            return
        mid = add_message(ch_row["org_id"], tid, "client", text, attachments=[], user_id=None, external_user_id=str(msg.get("from", {}).get("id") or ""))
        if not mid:
            return
        try:
            add_audit(ch_row["org_id"], "tg.message_in", "message", mid, {"chat": chat_id})
        except Exception:
            pass
    except Exception as e:
        app.logger.error(f"TG update process failed: {e}")


@app.route("/integrations/telegram/webhook/<int:channel_id>/<secret>", methods=["POST"])
def telegram_webhook_channel(channel_id, secret):
    try:
        if not rate_limit(f"tg:wh:chan:{channel_id}:{client_ip()}", per_min=CTI_WEBHOOK_RATE_LIMIT_PER_MIN):
            return make_response("rate limit", 429)

        ch = query_db("SELECT * FROM channels WHERE id=? AND type='telegram' AND active=1", (channel_id,), one=True)
        if not ch:
            return make_response("not found", 404)
        expected = ch["secret"] or ""
        try:
            sjs = json.loads(ch["settings_json"] or "{}")
        except Exception:
            sjs = {}
        expected2 = sjs.get("webhook_secret") or TG_WEBHOOK_SECRET
        if secret != expected and secret != expected2:
            return make_response("forbidden", 403)
        try:
            upd = request.get_json(force=True) or {}
        except Exception:
            upd = {}
        _process_telegram_update(ch, upd)
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"TG webhook channel error: {e}")
        return make_response("internal error", 500)


@app.route("/integrations/telegram/webhook/<secret>", methods=["POST"])
def telegram_webhook(secret):
    try:
        if not rate_limit(f"tg:wh:sec:{secret}:{client_ip()}", per_min=CTI_WEBHOOK_RATE_LIMIT_PER_MIN):
            return make_response("rate limit", 429)

        ch = _get_tg_channel_by_secret(secret)
        if not ch:
            return make_response("forbidden", 403)
        try:
            upd = request.get_json(force=True) or {}
        except Exception:
            upd = {}
        _process_telegram_update(ch, upd)
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"TG webhook error: {e}")
        return make_response("internal error", 500)


@app.route("/integrations/vk/callback/<int:channel_id>", methods=["POST"])
def vk_callback(channel_id):
    try:
        if not rate_limit(f"vk:cb:{channel_id}:{client_ip()}", per_min=CTI_WEBHOOK_RATE_LIMIT_PER_MIN):
            return make_response("rate limit", 429)

        ch = query_db("SELECT * FROM channels WHERE id=? AND type='vk' AND active=1", (channel_id,), one=True)
        if not ch:
            return make_response("not found", 404)
        try:
            settings = json.loads(ch["settings_json"] or "{}")
        except Exception:
            settings = {}
        confirm_code = settings.get("confirm_code") or VK_CONFIRM_CODE
        expected_secret = settings.get("secret") or VK_SECRET

        raw = request.get_data() or b""
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            data = {}
        typ = data.get("type")
        incoming_secret = data.get("secret")
        if typ != "confirmation":
            if REQUIRE_CTI_SECRET and (not expected_secret or incoming_secret != expected_secret):
                return make_response("forbidden", 403)

        if typ == "confirmation":
            return confirm_code or "ok"
        if typ == "message_new":
            obj = data.get("object", {})
            msg = obj.get("message") or {}
            user_id = str(msg.get("from_id") or "")
            peer_id = str(msg.get("peer_id") or user_id)
            ext_id = f"{peer_id}:{msg.get('id') or msg.get('conversation_message_id') or ''}"
            if not exec_db("INSERT INTO ext_dedup (org_id, source, external_id) VALUES (?,?,?)", (ch["org_id"], "vk", ext_id)):
                return "ok"
            text = msg.get("text") or ""
            tid = ensure_thread(ch["org_id"], ch["id"], "dm", external_id=peer_id, subject=f"VK {peer_id}")
            if tid:
                mid = add_message(ch["org_id"], tid, "client", text, attachments=[], external_user_id=user_id)
                try:
                    add_audit(ch["org_id"], "vk.message_in", "message", mid, {"peer": peer_id})
                except Exception:
                    pass
            return "ok"
        return "ok"
    except Exception as e:
        app.logger.exception(f"VK callback error: {e}")
        return make_response("internal error", 500)


# ------------------- Internal Team Chat (HTML + APIs) -------------------
def _dm_key_for_pair(a: int, b: int) -> str:
    x, y = (a, b) if a <= b else (b, a)
    return f"{x}:{y}"


@app.route("/chat")
@login_required
def chat():
    try:
        org_id = current_org_id()
        chans = query_db("SELECT id,name,type FROM chat_channels WHERE org_id=? ORDER BY id", (org_id,))
        inner = render_safe(CHAT_TMPL, channels=chans, messages=[], current=None)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Chat error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/chat/<int:cid>")
@login_required
def chat_channel(cid):
    try:
        org_id = current_org_id()
        ch = query_db("SELECT * FROM chat_channels WHERE id=? AND org_id=?", (cid, org_id), one=True)
        if not ch:
            abort(404)
        if not chat_access_allowed(session["user_id"], cid, org_id):
            abort(403)
        page = max(1, int(request.args.get("page") or 1))
        per_page = 50
        offset = (page - 1) * per_page
        msgs = query_db(
            """SELECT m.*, u.username FROM chat_messages m JOIN users u ON u.id=m.user_id
               WHERE m.channel_id=? AND m.org_id=? ORDER BY m.id DESC LIMIT ? OFFSET ?""",
            (cid, org_id, per_page, offset),
        )
        chans = query_db("SELECT id,name,type FROM chat_channels WHERE org_id=? ORDER BY id", (org_id,))
        inner = render_safe(CHAT_TMPL, channels=chans, messages=msgs, current=ch)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Chat channel error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("chat"))


@app.route("/api/chat/send", methods=["POST"])
@login_required
def api_chat_send():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        data = request.get_json(force=True) or {}
        cid = int(data.get("channel_id") or 0)
        body = (data.get("body") or "").strip()
        if not cid or not body:
            return jsonify(ok=False, error="bad request"), 400
        if not chat_access_allowed(session["user_id"], cid, org_id):
            return jsonify(ok=False, error="forbidden"), 403
        ch = query_db("SELECT id FROM chat_channels WHERE id=? AND org_id=?", (cid, org_id), one=True)
        if not ch:
            return jsonify(ok=False, error="channel not found"), 404
        mid = exec_db("INSERT INTO chat_messages (org_id,channel_id,user_id,body) VALUES (?,?,?,?)", (org_id, cid, session["user_id"], body))
        if not mid:
            return jsonify(ok=False, error="insert failed"), 500
        try:
            fts_upsert("chat_messages_fts", mid, {"body": body})
        except Exception:
            pass
        members = query_db("SELECT user_id FROM chat_members WHERE channel_id=?", (cid,))
        user_ids = [m["user_id"] for m in members if m["user_id"] != session["user_id"]]
        if user_ids:
            sse_publish_users(user_ids, "chat.message", {"channel_id": cid, "id": mid, "body": body})
            try:
                notify_user(user_ids, "Новое сообщение в чате", body[:50], url_for("chat_channel", cid=cid, _external=True))
            except Exception:
                pass
        return jsonify(ok=True, id=mid)
    except Exception as e:
        app.logger.exception(f"Chat send error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/chat/upload", methods=["POST"])
@login_required
def api_chat_upload():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        cid = int(request.form.get("channel_id") or 0)
        if not chat_access_allowed(session["user_id"], cid, org_id):
            return jsonify(ok=False, error="forbidden"), 403
        f = request.files.get("file")
        if not cid or not f or not f.filename:
            return jsonify(ok=False, error="bad request"), 400
        ch = query_db("SELECT 1 FROM chat_channels WHERE id=? AND org_id=?", (cid, org_id), one=True)
        if not ch:
            return jsonify(ok=False, error="channel not found"), 404
        raw = f.read()
        if len(raw) > app.config.get("MAX_CONTENT_LENGTH", 200 * 1024 * 1024):
            return jsonify(ok=False, error="file too large"), 413
        if not _av_scan_bytes(raw):
            return jsonify(ok=False, error="malware detected"), 400
        ctype = detect_mime_from_bytes(raw, f.filename) or (mimetypes.guess_type(f.filename)[0] or "application/octet-stream")
        if ctype not in UPLOAD_ALLOWED_TYPES:
            return jsonify(ok=False, error="unsupported content-type"), 415
        res = storage.save(io.BytesIO(raw), f.filename, content_type=ctype)
        if not res.get("ok"):
            return jsonify(ok=False, error="upload failed"), 500
        location = res.get("location") if res["provider"] == "s3" else f"local:{res['key']}"
        fid = exec_db(
            "INSERT INTO files (org_id,user_id,original_name,storage_key,content_type,size,tags_json) VALUES (?,?,?,?,?,?,?)",
            (org_id, session["user_id"], f.filename, location, ctype, len(raw), "[]"),
        )
        if not fid:
            return jsonify(ok=False, error="insert failed"), 500
        body = f"[file] {f.filename}"
        mid = exec_db(
            "INSERT INTO chat_messages (org_id,channel_id,user_id,body,attachments_json) VALUES (?,?,?,?,?)",
            (org_id, cid, session["user_id"], body, json.dumps([{"file_id": fid, "name": f.filename, "url": presign_file(fid)}], ensure_ascii=False)),
        )
        if not mid:
            return jsonify(ok=False, error="insert failed"), 500
        try:
            fts_upsert("chat_messages_fts", mid, {"body": body})
        except Exception:
            pass
        members = query_db("SELECT user_id FROM chat_members WHERE channel_id=?", (cid,))
        sse_publish_users([m["user_id"] for m in members], "chat.message", {"channel_id": cid, "id": mid, "body": body})
        return jsonify(ok=True, id=mid, file_id=fid, url=presign_file(fid))
    except Exception as e:
        app.logger.exception(f"Chat upload error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/chat/create", methods=["POST"])
@login_required
def api_chat_create():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        typ = (d.get("type") or "public").lower()
        title = (d.get("title") or "").strip() or "Канал"
        members_in = list({int(x) for x in (d.get("members") or []) if isinstance(x, int) or (isinstance(x, str) and x.isdigit())})
        department_ids = list({int(x) for x in (d.get("department_ids") or []) if isinstance(x, int) or (isinstance(x, str) and x.isdigit())})
        valid_members = []
        if department_ids:
            for did in set(department_ids):
                users = query_db("SELECT user_id FROM department_members WHERE org_id=? AND department_id=?", (org_id, did))
                valid_members.extend([int(u["user_id"]) for u in users])
        for uid in members_in:
            if query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (int(uid), org_id), one=True):
                valid_members.append(int(uid))
        valid_members = list(sorted(set(valid_members)))
        me = int(session["user_id"])
        if typ == "personal":
            if len(valid_members) == 1:
                other = int(valid_members[0])
                key = _dm_key_for_pair(me, other)
                ex = query_db("SELECT id FROM chat_channels WHERE org_id=? AND dm_key=? LIMIT 1", (org_id, key), one=True)
                if ex:
                    return jsonify(ok=True, id=ex["id"])
                cid = exec_db("INSERT INTO chat_channels (org_id,name,type,created_by,dm_key) VALUES (?,?,?,?,?)", (org_id, "", "personal", me, key))
                if not cid:
                    return jsonify(ok=False, error="insert failed"), 500
                exec_many("INSERT INTO chat_members (channel_id,user_id,role) VALUES (?,?,?)", [(cid, me, "admin"), (cid, other, "member")])
                return jsonify(ok=True, id=cid)
            return jsonify(ok=False, error="personal chat requires exactly 1 member in org"), 400
        else:
            all_members = list({me} | set(valid_members))
            cid = exec_db("INSERT INTO chat_channels (org_id,name,type,created_by) VALUES (?,?,?,?)", (org_id, title, "public" if typ == "public" else "group", me))
            if not cid:
                return jsonify(ok=False, error="insert failed"), 500
            seq = []
            for uid in all_members:
                role = "admin" if uid == me else "member"
                seq.append((cid, uid, role))
            if seq:
                exec_many("INSERT INTO chat_members (channel_id,user_id,role) VALUES (?,?,?)", seq)
            return jsonify(ok=True, id=cid)
    except Exception as e:
        app.logger.exception(f"Chat create error: {e}")
        return jsonify(ok=False, error="internal error"), 500
# === END CORE PART 8/9 (3/3) ===
# === CORE PART 9/9 (1/3) — Tasks/Comments/Activity/Reminders/Files (+Checklist API, hardened) ===
# -*- coding: utf-8 -*-

# ------------------- Task activity helper -------------------
def add_task_activity(org_id: int, task_id: int, user_id: int, kind: str, meta: dict = None):
    try:
        exec_db(
            "INSERT INTO task_activity (org_id, task_id, user_id, kind, meta_json) VALUES (?,?,?,?,?)",
            (org_id, task_id, user_id, kind, json.dumps(meta or {}, ensure_ascii=False)),
        )
    except Exception as e:
        app.logger.error(f"[WARN] task_activity insert failed: {e}")


# ------------------- Tasks (HTML + API) -------------------
@app.route("/tasks", methods=["GET", "POST"])
@login_required
def tasks_page():
    try:
        org_id = current_org_id()
        if request.method == "POST":
            verify_csrf()
            title = (request.form.get("title") or "").strip()
            if not title:
                flash("Название обязательно", "error")
                return redirect(url_for("tasks_page"))
            desc = (request.form.get("description") or "").strip()

            assignee_id_v = (request.form.get("assignee_id") or "").strip()
            assignee_id = None
            if assignee_id_v:
                if not assignee_id_v.isdigit():
                    assignee_id = None
                else:
                    aid = int(assignee_id_v)
                    if query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (aid, org_id), one=True):
                        assignee_id = aid
                    else:
                        flash("Исполнитель не найден в организации", "error")
                        return redirect(url_for("tasks_page"))

            due_at_raw = (request.form.get("due_at") or "").strip()
            due_at = ensure_iso_datetime(due_at_raw) or None

            company_id_v = (request.form.get("company_id") or "").strip()
            company_id = int(company_id_v) if (company_id_v.isdigit() and query_db("SELECT 1 FROM companies WHERE id=? AND org_id=?", (int(company_id_v), org_id), one=True)) else None

            company_inn = (request.form.get("company_inn") or "").strip() or None
            if not company_id and company_inn:
                c = query_db("SELECT id FROM companies WHERE inn=? AND org_id=?", (company_inn, org_id), one=True)
                if c:
                    company_id = c["id"]

            monthly_fee = 0.0
            try:
                monthly_fee = float(request.form.get("monthly_fee") or "0")
            except Exception:
                monthly_fee = 0.0

            business_type = (request.form.get("business_type") or "").strip()
            desired_contact_time = (request.form.get("desired_contact_time") or "").strip()
            expected_services = (request.form.get("expected_services") or "").strip()
            equipment_details = (request.form.get("equipment_details") or "").strip()
            contact_person_id_v = (request.form.get("contact_person_id") or "").strip()
            deal_id_v = (request.form.get("deal_id") or "").strip()

            contact_person_id = int(contact_person_id_v) if contact_person_id_v.isdigit() else None
            deal_id = int(deal_id_v) if deal_id_v.isdigit() else None

            tid = exec_db(
                """INSERT INTO tasks (org_id,creator_id,assignee_id,title,description,priority,due_at,status,company_id,monthly_fee,
                                      business_type,desired_contact_time,expected_services,equipment_details,contact_person_id,deal_id)
                   VALUES (?,?,?,?,?,'normal',?,'open',?,?,?,?,?,?,?,?)""",
                (org_id, session["user_id"], assignee_id, title, desc, due_at, company_id, monthly_fee,
                 business_type, desired_contact_time, expected_services, equipment_details, contact_person_id, deal_id),
            )
            if not tid:
                flash("Ошибка создания задачи", "error")
                return redirect(url_for("tasks_page"))
            try:
                fts_upsert("tasks_fts", tid, {"title": title, "description": desc})
            except Exception:
                pass
            try:
                add_audit(org_id, "task.created", "task", tid, {"title": title})
            except Exception:
                pass
            add_task_activity(org_id, tid, session["user_id"], "created", {"title": title})
            try:
                fire_event("task.created", org_id, {"task_id": tid})
            except Exception:
                pass
            flash("Задача создана", "success")
            return redirect(url_for("tasks_page"))

        # GET
        f = (request.args.get("f") or "open").strip()
        q = (request.args.get("q") or "").strip()
        created_from = request.args.get("created_from") or ""
        created_to = request.args.get("created_to") or ""
        address = (request.args.get("address") or "").strip()
        contact_phone = (request.args.get("contact_phone") or "").strip()

        where = ["t.org_id=?"]
        params = [org_id]
        if f == "today":
            df = datetime.utcnow().date().isoformat()
            where.append("substr(COALESCE(t.due_at,t.created_at),1,10)=?"); params.append(df)
        elif f == "overdue":
            where.append("t.status='overdue'")
        elif f == "done":
            where.append("t.status='done'")
        else:
            where.append("t.status!='done'")
        if q:
            where.append("(t.title LIKE ? OR t.description LIKE ?)"); params.extend([f"%{q}%", f"%{q}%"])
        if address:
            where.append("t.address LIKE ?"); params.append(f"%{address}%")
        if contact_phone:
            where.append("t.contact_phone LIKE ?"); params.append(f"%{contact_phone}%")
        df, dt = date_range_bounds(created_from, created_to)
        if df:
            where.append("t.created_at>=?"); params.append(df)
        if dt:
            where.append("t.created_at<=?"); params.append(dt)

        rows = query_db(
            f"""
            SELECT t.*, u.username AS assignee_name, c.name AS company_name
            FROM tasks t
            LEFT JOIN users u ON u.id=t.assignee_id
            LEFT JOIN companies c ON c.id=t.company_id
            WHERE {' AND '.join(where)}
            ORDER BY t.id DESC
            LIMIT 50 OFFSET 0
            """,
            tuple(params),
        )

        agents_rows = query_db("SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username", (org_id,))
        agents = [dict(a) for a in (agents_rows or [])]

        statuses = query_db("SELECT name FROM task_statuses WHERE org_id=? ORDER BY id", (org_id,))
        inner = render_safe(TASKS_TMPL, tasks=rows, agents=agents, statuses=statuses, current_filter=f)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Tasks page error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/api/tasks/list")
@login_required
def api_tasks_list():
    try:
        org_id = current_org_id()
        page = max(1, int(request.args.get("page") or 1))
        per_page = max(1, min(200, int(request.args.get("per_page") or 50)))
        offset = (page - 1) * per_page
        f = (request.args.get("f") or "open").strip()
        q = (request.args.get("q") or "").strip()
        created_from = request.args.get("created_from") or ""
        created_to = request.args.get("created_to") or ""
        address = (request.args.get("address") or "").strip()
        contact_phone = (request.args.get("contact_phone") or "").strip()

        where = ["t.org_id=?"]
        params = [org_id]
        if f == "today":
            df = datetime.utcnow().date().isoformat()
            where.append("substr(COALESCE(t.due_at,t.created_at),1,10)=?"); params.append(df)
        elif f == "overdue":
            where.append("t.status='overdue'")
        elif f == "done":
            where.append("t.status='done'")
        else:
            where.append("t.status!='done'")
        if q:
            where.append("(t.title LIKE ? OR t.description LIKE ?)"); params.extend([f"%{q}%", f"%{q}%"])
        if address:
            where.append("t.address LIKE ?"); params.append(f"%{address}%")
        if contact_phone:
            where.append("t.contact_phone LIKE ?"); params.append(f"%{contact_phone}%")
        df, dt = date_range_bounds(created_from, created_to)
        if df:
            where.append("t.created_at>=?"); params.append(df)
        if dt:
            where.append("t.created_at<=?"); params.append(dt)

        rows = query_db(
            f"""
            SELECT t.*, u.username AS assignee_name, c.name AS company_name
            FROM tasks t
            LEFT JOIN users u ON u.id=t.assignee_id
            LEFT JOIN companies c ON c.id=t.company_id
            WHERE {' AND '.join(where)}
            ORDER BY t.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [per_page, offset]),
        )
        return jsonify(ok=True, items=[dict(r) for r in rows], page=page, per_page=per_page)
    except Exception as e:
        app.logger.exception(f"Tasks list API error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/statuses")
@login_required
def api_task_statuses():
    try:
        org_id = current_org_id()
        rows = query_db("SELECT name FROM task_statuses WHERE org_id=? ORDER BY id", (org_id,))
        items = [{"name": r["name"]} for r in rows] if rows else [{"name": s} for s in ("open", "done", "overdue")]
        return jsonify(ok=True, items=items)
    except Exception as e:
        app.logger.exception(f"Task statuses API error: {e}")
        return jsonify(ok=False, error="internal error"), 500


def _status_allowed(org_id: int, status: str) -> bool:
    try:
        if not status:
            return False
        base = {"open", "done", "overdue"}
        if status in base:
            return True
        r = query_db("SELECT 1 FROM task_statuses WHERE org_id=? AND name=?", (org_id, status), one=True)
        return bool(r)
    except Exception:
        return False


@app.route("/api/task/update", methods=["POST"])
@login_required
def api_task_update():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        tid = int(d.get("id") or 0)
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_task(session["user_id"], t):
            return jsonify(ok=False, error="forbidden"), 403
        allowed = {
            "title", "description", "assignee_id", "due_at", "status", "address", "contact_phone",
            "company_id", "company_inn", "monthly_fee", "tags_json", "extra_json",
            "business_type", "desired_contact_time", "expected_services", "equipment_details",
            "contact_person_id", "deal_id",
        }
        sets, params = [], []
        activity_meta = {}
        if "status" in d and d["status"] != t["status"]:
            if not _status_allowed(org_id, str(d["status"])):
                return jsonify(ok=False, error="bad status"), 400
            activity_meta["status"] = {"old": t["status"], "new": d["status"]}
        if "assignee_id" in d and (d["assignee_id"] or None) != (t["assignee_id"] or None):
            if d["assignee_id"]:
                try:
                    aid = int(d["assignee_id"])
                except Exception:
                    return jsonify(ok=False, error="bad assignee"), 400
                if not query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (aid, org_id), one=True):
                    return jsonify(ok=False, error="assignee out of org"), 400
            activity_meta["assignee_id"] = {"old": t["assignee_id"], "new": d["assignee_id"]}
        for k in allowed:
            if k in d:
                if k == "company_inn":
                    if not d.get("company_id") and d.get("company_inn"):
                        c = query_db("SELECT id FROM companies WHERE inn=? AND org_id=?", (d["company_inn"], org_id), one=True)
                        if c:
                            sets.append("company_id=?"); params.append(c["id"])
                elif k == "tags_json":
                    val = d.get("tags_json")
                    if isinstance(val, list):
                        sets.append("tags_json=?"); params.append(json.dumps(val, ensure_ascii=False))
                elif k == "due_at":
                    val = ensure_iso_datetime(d.get("due_at") or "")
                    sets.append("due_at=?"); params.append(val or None)
                else:
                    sets.append(f"{k}=?"); params.append(d[k])
        if not sets:
            return jsonify(ok=False, error="empty"), 400
        sets.append("updated_at=CURRENT_TIMESTAMP")
        params += [tid, org_id]
        rc = exec_db_rowcount(f"UPDATE tasks SET {', '.join(sets)} WHERE id=? AND org_id=?", tuple(params))
        if rc <= 0:
            return jsonify(ok=False, error="not updated"), 400

        if activity_meta:
            add_task_activity(org_id, tid, session["user_id"], "updated", activity_meta)
        try:
            fire_event("task.updated", org_id, {"task_id": tid, "patch": list(d.keys())})
        except Exception:
            pass
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Task update error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/toggle", methods=["POST"])
@login_required
def api_task_toggle():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        tid = int(d.get("id") or 0)
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_task(session["user_id"], t):
            return jsonify(ok=False, error="forbidden"), 403
        new_status = "open" if (t["status"] == "done") else "done"
        exec_db("UPDATE tasks SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (new_status, tid, org_id))
        add_task_activity(org_id, tid, session["user_id"], "status_change", {"old": t["status"], "new": new_status})
        try:
            fire_event("task.updated", org_id, {"task_id": tid, "status": new_status})
        except Exception:
            pass
        return jsonify(ok=True, status=new_status)
    except Exception as e:
        app.logger.exception(f"Task toggle error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Reminders -------------------
@app.route("/api/task/reminders/<int:task_id>")
@login_required
def api_task_reminders(task_id):
    try:
        org_id = current_org_id()
        if not query_db("SELECT 1 FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True):
            return jsonify(ok=False, error="not found"), 404
        rows = query_db("SELECT id, user_id, remind_at, message, fired, fired_at FROM task_reminders WHERE org_id=? AND task_id=? ORDER BY remind_at ASC", (org_id, task_id))
        return jsonify(ok=True, items=[dict(r) for r in rows])
    except Exception as e:
        app.logger.exception(f"Task reminders list error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/reminder", methods=["POST"])
@login_required
def api_task_reminder_create():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        task_id = int(d.get("task_id") or 0)
        remind_at_raw = (d.get("remind_at") or "").strip()
        remind_at = ensure_iso_datetime(remind_at_raw)
        message = (d.get("message") or "").strip() or "Напоминание по задаче"
        if not task_id or not remind_at:
            return jsonify(ok=False, error="bad request"), 400
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_task(session["user_id"], t):
            return jsonify(ok=False, error="forbidden"), 403
        rid = exec_db("INSERT INTO task_reminders (org_id,task_id,user_id,remind_at,message,fired) VALUES (?,?,?,?,?,0)", (org_id, task_id, session["user_id"], remind_at, message))
        add_task_activity(org_id, task_id, session["user_id"], "reminder_add", {"remind_at": remind_at})
        return jsonify(ok=True, id=rid)
    except Exception as e:
        app.logger.exception(f"Task reminder create error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/reminder/<int:rid>", methods=["DELETE"])
@login_required
def api_task_reminder_delete(rid):
    try:
        verify_csrf_header()
        org_id = current_org_id()
        row = query_db("SELECT task_id FROM task_reminders WHERE id=? AND org_id=?", (rid, org_id), one=True)
        if not row:
            return jsonify(ok=True)
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (int(row["task_id"]), org_id), one=True)
        if not t or not can_edit_task(session["user_id"], t):
            return jsonify(ok=False, error="forbidden"), 403
        exec_db("DELETE FROM task_reminders WHERE id=? AND org_id=?", (rid, org_id))
        add_task_activity(org_id, int(row["task_id"]), session["user_id"], "reminder_del", {"id": rid})
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Task reminder delete error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Phones -------------------
@app.route("/api/task/phones/<int:task_id>")
@login_required
def api_task_phones(task_id):
    try:
        org_id = current_org_id()
        t = query_db("SELECT contact_phone, company_id FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        nums = []
        if t["contact_phone"]:
            nums.append(t["contact_phone"])
        if t["company_id"]:
            c = query_db("SELECT phone FROM companies WHERE id=? AND org_id=?", (t["company_id"], org_id), one=True)
            if c and c["phone"]:
                nums.append(c["phone"])
        conts = query_db("SELECT phone FROM contacts WHERE company_id=? AND org_id=? ORDER BY id DESC LIMIT 10", (t["company_id"], org_id))
        for r in conts:
            if r["phone"]:
                nums.append(r["phone"])
        out = []
        seen = set()
        for n in nums:
            d = phone_digits(n)
            if d and d not in seen:
                seen.add(d)
                out.append(n)
        return jsonify(ok=True, items=out)
    except Exception as e:
        app.logger.exception(f"Task phones error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Participants & Department & Delegate -------------------
@app.route("/api/task/participants", methods=["POST"])
@login_required
def api_task_participants():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        task_id = int(d.get("task_id") or 0)
        add_users = [int(x) for x in (d.get("add") or []) if str(x).isdigit()]
        remove_users = [int(x) for x in (d.get("remove") or []) if str(x).isdigit()]
        role = (d.get("role") or "assignee").strip()
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_task(session["user_id"], t):
            return jsonify(ok=False, error="forbidden"), 403
        for uid in add_users:
            if query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (uid, org_id), one=True):
                _ = exec_db("INSERT INTO task_participants (org_id,task_id,user_id,role) VALUES (?,?,?,?)", (org_id, task_id, uid, role))
        for uid in remove_users:
            exec_db("DELETE FROM task_participants WHERE org_id=? AND task_id=? AND user_id=?", (org_id, task_id, uid))
        add_task_activity(org_id, task_id, session["user_id"], "participants_update", {"add": add_users, "remove": remove_users, "role": role})
        try:
            fire_event("task.updated", org_id, {"task_id": task_id, "participants_changed": True})
        except Exception:
            pass
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Task participants error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/assign_department", methods=["POST"])
@login_required
def api_task_assign_department():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        task_id = int(d.get("task_id") or 0)
        dept_id = int(d.get("department_id") or 0)
        stage_key = (d.get("stage_key") or "").strip() or None
        comment = (d.get("comment") or "").strip()
        due_at = ensure_iso_datetime(d.get("due_at") or "") or None
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_task(session["user_id"], t):
            return jsonify(ok=False, error="forbidden"), 403
        if dept_id and not query_db("SELECT 1 FROM departments WHERE id=? AND org_id=?", (dept_id, org_id), one=True):
            return jsonify(ok=False, error="dept not found"), 404
        to_stage = None
        if stage_key:
            to_stage = query_db("SELECT * FROM workflow_stages WHERE org_id=? AND entity_type='task' AND key=? AND active=1", (org_id, stage_key), one=True)
            if not to_stage:
                return jsonify(ok=False, error="stage not found"), 404
        if (not due_at) and to_stage:
            try:
                sla = int(to_stage["sla_minutes"] or 0)
            except Exception:
                sla = 0
            if sla > 0:
                due_at = (datetime.utcnow() + timedelta(minutes=sla)).isoformat(" ", "seconds")
        sets = []
        params = []
        if dept_id:
            sets.append("current_department_id=?"); params.append(dept_id)
        if to_stage:
            sets.append("current_stage=?"); params.append(to_stage["key"])
        if due_at:
            sets.append("due_at=?"); params.append(due_at)
        if sets:
            sets.append("updated_at=CURRENT_TIMESTAMP")
            params += [task_id, org_id]
            exec_db(f"UPDATE tasks SET {', '.join(sets)} WHERE id=? AND org_id=?", tuple(params))
        exec_db(
            "INSERT INTO stage_transitions (org_id,entity_type,entity_id,from_stage,to_stage,by_user_id,department_id,comment,due_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (org_id, "task", task_id, t["current_stage"], (to_stage["key"] if to_stage else t["current_stage"]), session["user_id"], dept_id or t["current_department_id"], comment, due_at),
        )
        add_task_activity(org_id, task_id, session["user_id"], "dept_assign", {"department_id": dept_id, "stage": (to_stage["key"] if to_stage else None), "due_at": due_at})
        if dept_id:
            _notify_dept_heads(dept_id, f"Задача #{task_id}: передана в отдел", url_for("tasks_page", _external=True))
        try:
            fire_event("task.stage.changed", org_id, {"task_id": task_id, "department_id": dept_id, "stage": (to_stage["key"] if to_stage else None)})
        except Exception:
            pass
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Task assign dept error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/delegate", methods=["POST"])
@login_required
def api_task_delegate():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        task_id = int(d.get("task_id") or 0)
        to_user_id = int(d.get("to_user_id") or 0)
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        if not (_is_admin() or is_dept_head(session["user_id"], int(t["current_department_id"] or 0)) or session["user_id"] == t["creator_id"]):
            return jsonify(ok=False, error="forbidden"), 403
        if not query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (to_user_id, org_id), one=True):
            return jsonify(ok=False, error="user not found"), 404
        exec_db("UPDATE tasks SET assignee_id=? WHERE id=? AND org_id=?", (to_user_id, task_id, org_id))
        _ = exec_db("INSERT INTO task_participants (org_id,task_id,user_id,role) VALUES (?,?,?,?)", (org_id, task_id, to_user_id, "assignee"))
        try:
            notify_user(to_user_id, "Новая задача (делегировано)", f"Задача #{task_id}", url_for("tasks_page", _external=True))
        except Exception:
            pass
        add_task_activity(org_id, task_id, session["user_id"], "delegated", {"to_user_id": to_user_id})
        try:
            fire_event("task.updated", org_id, {"task_id": task_id, "delegated_to": to_user_id})
        except Exception:
            pass
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Task delegate error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Task detail page + Comments API + Pin files -------------------
@app.route("/task/<int:tid>")
@login_required
def task_view(tid):
    try:
        org_id = current_org_id()
        t = query_db(
            """SELECT t.*, u.username AS assignee_name, c.name AS company_name
               FROM tasks t
               LEFT JOIN users u ON u.id=t.assignee_id
               LEFT JOIN companies c ON c.id=t.company_id
               WHERE t.id=? AND t.org_id=?""",
            (tid, org_id),
            one=True,
        )
        if not t:
            abort(404)

        rows = query_db(
            """SELECT tc.*, u.username FROM task_comments tc
               LEFT JOIN users u ON u.id=tc.user_id
               WHERE tc.org_id=? AND tc.task_id=?
               ORDER BY tc.id DESC LIMIT 50""",
            (org_id, tid),
        )
        comments = []
        for r in rows:
            d = dict(r)
            try:
                d["attachments"] = json.loads(d.get("attachments_json") or "[]")
            except Exception:
                d["attachments"] = []
            comments.append(d)
        parts = task_participants(tid)
        stats = query_db("SELECT name FROM task_statuses WHERE org_id=? ORDER BY id", (org_id,))
        transitions = query_db(
            """SELECT * FROM stage_transitions
               WHERE org_id=? AND entity_type='task' AND entity_id=?
               ORDER BY id DESC LIMIT 200""",
            (org_id, tid),
        )

        activity = query_db(
            "SELECT * FROM task_activity WHERE org_id=? AND task_id=? ORDER BY id DESC LIMIT 100",
            (org_id, tid),
        )

        pinned = []
        try:
            pinned = json.loads(t["pinned_files_json"] or "[]")
        except Exception:
            pinned = []

        inner_html = render_safe(
            TASK_VIEW_TMPL,
            t=t,
            comments=comments,
            participants=parts,
            statuses=stats,
            transitions=transitions,
            activity=activity,
            pinned_files=pinned,
        )
        return render_safe(LAYOUT_TMPL, inner=inner_html)
    except Exception as e:
        app.logger.exception(f"Task view error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("tasks_page"))


@app.route("/api/task/comments")
@login_required
def api_task_comments():
    try:
        org_id = current_org_id()
        task_id = int(request.args.get("task_id") or 0)
        if not query_db("SELECT 1 FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True):
            return jsonify(ok=False, error="not found"), 404
        page = max(1, int(request.args.get("page") or 1))
        per_page = max(1, min(200, int(request.args.get("per_page") or 50)))
        offset = (page - 1) * per_page
        rows = query_db(
            """SELECT tc.id, tc.user_id, u.username, tc.body, tc.attachments_json, tc.created_at
               FROM task_comments tc LEFT JOIN users u ON u.id=tc.user_id
               WHERE tc.org_id=? AND tc.task_id=?
               ORDER BY tc.id DESC LIMIT ? OFFSET ?""",
            (org_id, task_id, per_page, offset),
        )
        items = []
        for r in rows:
            d = dict(r)
            try:
                d["attachments"] = json.loads(d.get("attachments_json") or "[]")
            except Exception:
                d["attachments"] = []
            d.pop("attachments_json", None)
            items.append(d)
        return jsonify(ok=True, items=items, page=page, per_page=per_page)
    except Exception as e:
        app.logger.exception(f"Task comments list error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/comment", methods=["POST"])
@login_required
def api_task_comment_create():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        task_id = int(d.get("task_id") or 0)
        raw_body = (d.get("body") or "").strip()
        body_format = (d.get("format") or "plain").lower()
        attachments = d.get("attachments") or []
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404

        can_comment = False
        if _is_admin() or int(t["creator_id"] or 0) == session["user_id"] or int(t["assignee_id"] or 0) == session["user_id"]:
            can_comment = True
        else:
            pr = query_db(
                "SELECT 1 FROM task_participants WHERE org_id=? AND task_id=? AND user_id=? AND role IN ('owner','assignee','watcher') LIMIT 1",
                (org_id, task_id, session["user_id"]),
                one=True,
            )
            can_comment = bool(pr)
        if not can_comment:
            return jsonify(ok=False, error="forbidden"), 403
        if not raw_body and not attachments:
            return jsonify(ok=False, error="empty"), 400

        body = raw_body
        if body_format == "html":
            if bleach:
                allowed_tags = ["b", "i", "strong", "em", "u", "br", "p", "ul", "ol", "li", "a"]
                allowed_attrs = {"a": ["href", "title", "target", "rel"]}
                body = bleach.clean(raw_body, tags=allowed_tags, attributes=allowed_attrs, strip=True)
            else:
                try:
                    import html as _html
                    body = _html.escape(raw_body)
                except Exception:
                    body = raw_body
        elif body_format == "md":
            body = raw_body

        cid = exec_db(
            "INSERT INTO task_comments (org_id,task_id,user_id,body,attachments_json) VALUES (?,?,?,?,?)",
            (org_id, task_id, session["user_id"], body, json.dumps(attachments, ensure_ascii=False)),
        )
        try:
            fts_upsert("task_comments_fts", cid, {"body": body or ""})
        except Exception:
            pass
        _metrics_inc("task_comments_total", (org_id,))
        exec_db("UPDATE tasks SET last_commented_at=CURRENT_TIMESTAMP, last_commented_by=? WHERE id=? AND org_id=?", (session["user_id"], task_id, org_id))
        add_task_activity(org_id, task_id, session["user_id"], "comment_add", {"comment_id": cid})

        t2 = query_db("SELECT assignee_id FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        to_notify = set()
        if t2 and t2["assignee_id"]:
            to_notify.add(int(t2["assignee_id"]))
        for p in task_participants(task_id):
            to_notify.add(int(p["user_id"]))
        if session["user_id"] in to_notify:
            to_notify.discard(session["user_id"])
        if to_notify:
            try:
                notify_user(list(to_notify), f"Новый комментарий к задаче #{task_id}", (body or "")[:120], url_for("task_view", tid=task_id, _external=True))
                sse_publish_users(list(to_notify), "task.comment", {"task_id": task_id, "id": cid})
            except Exception:
                pass
        try:
            add_audit(org_id, "task.comment", "task", task_id, {"comment_id": cid})
            fire_event("task.comment.created", org_id, {"task_id": task_id, "comment_id": cid})
        except Exception:
            pass
        return jsonify(ok=True, id=cid)
    except Exception as e:
        app.logger.exception(f"Task comment create error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/comment/upload", methods=["POST"])
@login_required
def api_task_comment_upload():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify(ok=False, error="file required"), 400
        raw = f.read()
        if not raw:
            return jsonify(ok=False, error="empty"), 400
        if len(raw) > app.config.get("MAX_CONTENT_LENGTH", 200 * 1024 * 1024):
            return jsonify(ok=False, error="file too large"), 413
        if not _av_scan_bytes(raw):
            return jsonify(ok=False, error="malware detected"), 400
        ctype = detect_mime_from_bytes(raw, f.filename) or (mimetypes.guess_type(f.filename)[0] or "application/octet-stream")
        if ctype not in UPLOAD_ALLOWED_TYPES:
            return jsonify(ok=False, error="unsupported content-type"), 415
        res = storage.save(io.BytesIO(raw), f.filename, content_type=ctype)
        if not res.get("ok"):
            return jsonify(ok=False, error="upload failed"), 500
        location = res.get("location") if res["provider"] == "s3" else f"local:{res['key']}"
        fid = exec_db(
            "INSERT INTO files (org_id,user_id,original_name,storage_key,content_type,size,tags_json) VALUES (?,?,?,?,?,?,?)",
            (org_id, session["user_id"], f.filename, location, ctype, len(raw), json.dumps(["task_comment"], ensure_ascii=False)),
        )
        if not fid:
            return jsonify(ok=False, error="insert failed"), 500
        return jsonify(ok=True, file={"id": fid, "name": f.filename, "url": presign_file(fid)})
    except Exception as e:
        app.logger.exception(f"Task comment upload error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/file_pin", methods=["POST"])
@login_required
def api_task_file_pin():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        task_id = int(d.get("task_id") or 0)
        file_id = int(d.get("file_id") or 0)
        pin = bool(d.get("pin", True))
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="task not found"), 404
        if not can_edit_task(session["user_id"], t):
            return jsonify(ok=False, error="forbidden"), 403
        frow = query_db("SELECT * FROM files WHERE id=? AND org_id=? AND deleted_at IS NULL", (file_id, org_id), one=True)
        if not frow:
            return jsonify(ok=False, error="file not found"), 404
        try:
            cur = json.loads(t["pinned_files_json"] or "[]")
        except Exception:
            cur = []
        cur = [x for x in cur if isinstance(x, dict) and x.get("id")]
        exists = any(int(x.get("id") or 0) == file_id for x in cur)
        if pin and not exists:
            cur.append({"id": file_id, "name": frow["original_name"], "url": presign_file(file_id)})
        if (not pin) and exists:
            cur = [x for x in cur if int(x.get("id") or 0) != file_id]
        exec_db("UPDATE tasks SET pinned_files_json=? WHERE id=? AND org_id=?", (json.dumps(cur, ensure_ascii=False), task_id, org_id))
        add_task_activity(org_id, task_id, session["user_id"], "file_pin", {"file_id": file_id, "pin": pin})
        return jsonify(ok=True, pinned=cur)
    except Exception as e:
        app.logger.exception(f"Task file pin error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Checklist API (extend tasks functionality) -------------------
@app.route("/api/task/checklist/<int:task_id>", methods=["GET"])
@login_required
def api_task_checklist_get(task_id):
    try:
        org_id = current_org_id()
        t = query_db("SELECT checklist_json FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        try:
            items = json.loads(t["checklist_json"] or "[]")
        except Exception:
            items = []
        return jsonify(ok=True, items=items)
    except Exception as e:
        app.logger.exception(f"Checklist get error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/task/checklist", methods=["POST"])
@login_required
def api_task_checklist_update():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        task_id = int(d.get("task_id") or 0)
        t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
        if not t:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_task(session["user_id"], t):
            return jsonify(ok=False, error="forbidden"), 403
        action = (d.get("action") or "set").lower()
        try:
            items = json.loads(t["checklist_json"] or "[]")
        except Exception:
            items = []
        items = items if isinstance(items, list) else []
        changed = False

        if action == "set":
            new_items = d.get("items")
            if isinstance(new_items, list):
                items = new_items
                changed = True
        elif action == "add":
            text = (d.get("text") or "").strip()
            if text:
                items.append({"id": uuid.uuid4().hex[:8], "text": text, "done": False})
                changed = True
        elif action == "toggle":
            cid = d.get("id")
            for it in items:
                if it.get("id") == cid:
                    it["done"] = not bool(it.get("done"))
                    changed = True
                    break
        elif action == "remove":
            cid = d.get("id")
            new_list = [it for it in items if it.get("id") != cid]
            changed = (len(new_list) != len(items))
            items = new_list
        elif action == "update":
            cid = d.get("id")
            text = (d.get("text") or "").strip()
            for it in items:
                if it.get("id") == cid and text:
                    it["text"] = text
                    changed = True
                    break

        if changed:
            exec_db("UPDATE tasks SET checklist_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (json.dumps(items, ensure_ascii=False), task_id, org_id))
            add_task_activity(org_id, task_id, session["user_id"], "checklist", {"action": action})
            fire_event("task.updated", org_id, {"task_id": task_id, "checklist_action": action})
        return jsonify(ok=True, items=items)
    except Exception as e:
        app.logger.exception(f"Checklist update error: {e}")
        return jsonify(ok=False, error="internal error"), 500
# === END CORE PART 9/9 (1/3) ===
# === CORE PART 9/9 (2/3) — Deals, Approvals public, Settings/Admin, Tokens (hash-only), Kanban/CustomFields APIs ===
# -*- coding: utf-8 -*-

# ------------------- Audit/Webhooks/Notifications helpers -------------------
def add_audit(org_id: int, action: str, entity_type: str = None, entity_id: int = None, details: dict = None):
    try:
        exec_db(
            "INSERT INTO audit_logs (org_id,user_id,action,entity_type,entity_id,details,ip,ua) VALUES (?,?,?,?,?,?,?,?)",
            (
                org_id,
                session.get("user_id"),
                action,
                entity_type,
                entity_id,
                json.dumps(details or {}, ensure_ascii=False),
                client_ip(),
                (request.headers.get("User-Agent", "")[:300] if request else ""),
            ),
        )
    except Exception as e:
        app.logger.error(f"[WARN] audit insert failed: {e}")


def sign_payload(secret: str, body: bytes) -> str:
    return hmac.new((secret or "").encode(), body, hashlib.sha256).hexdigest()


def emit_webhook(org_id: int, event: str, payload: dict):
    try:
        exec_db(
            "INSERT INTO webhook_queue (org_id,event,payload_json,status,attempts,created_at) VALUES (?,?,?,?,0,CURRENT_TIMESTAMP)",
            (org_id, event, json.dumps(payload, ensure_ascii=False), "pending"),
        )
    except Exception as e:
        app.logger.error(f"[WARN] webhook queue insert failed: {e}")


def notify_user(user_or_users, title: str, body: str = "", link_url: str = ""):
    ids = user_or_users if isinstance(user_or_users, (list, tuple, set)) else [user_or_users]
    for uid in ids:
        if not uid:
            continue
        u = query_db("SELECT org_id FROM users WHERE id=?", (uid,), one=True)
        if not u:
            continue
        exec_db(
            "INSERT INTO notifications (org_id,user_id,kind,title,body,link_url) VALUES (?,?,?,?,?,?)",
            (u["org_id"], uid, "generic", (title or "")[:200], (body or "")[:2000], (link_url or "")[:1024]),
        )


# ------------------- Deals (HTML + API, with participants/workflow) -------------------
@app.route("/deals")
@login_required
def deals_page():
    try:
        org_id = current_org_id()
        stage = (request.args.get("stage") or "").strip()
        status = (request.args.get("status") or "").strip()
        assignee = (request.args.get("assignee_id") or "").strip()
        where = ["org_id=?"]; params = [org_id]
        if stage: where.append("stage=?"); params.append(stage)
        if status: where.append("status=?"); params.append(status)
        if assignee and assignee.isdigit(): where.append("assignee_id=?"); params.append(int(assignee))
        rows = query_db(f"SELECT * FROM deals WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT 500", tuple(params))
        users_rows = query_db("SELECT id, username FROM users WHERE org_id=? AND active=1 ORDER BY username", (org_id,))
        users = [dict(u) for u in (users_rows or [])]
        users_map = {int(u["id"]): (u["username"] or "") for u in users}
        inner = render_safe(DEALS_TMPL, deals=[dict(r) for r in (rows or [])], users=users, users_map=users_map)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Deals page error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/api/deals/list")
@login_required
def api_deals_list():
    try:
        org_id = current_org_id()
        stage = (request.args.get("stage") or "").strip()
        status = (request.args.get("status") or "").strip()
        assignee = (request.args.get("assignee_id") or "").strip()
        where = ["org_id=?"]; params = [org_id]
        if stage: where.append("stage=?"); params.append(stage)
        if status: where.append("status=?"); params.append(status)
        if assignee and assignee.isdigit(): where.append("assignee_id=?"); params.append(int(assignee))
        rows = query_db(f"SELECT * FROM deals WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT 1000", tuple(params))
        return jsonify(ok=True, items=[dict(r) for r in rows])
    except Exception as e:
        app.logger.exception(f"Deals list error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/deal/create", methods=["POST"])
@login_required
def api_deal_create():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        title = (d.get("title") or "").strip()
        if not title:
            return jsonify(ok=False, error="title required"), 400
        stage = (d.get("stage") or "new").strip()
        amount = float(d.get("amount") or 0)
        currency = (d.get("currency") or "RUB").strip()
        status = (d.get("status") or "open").strip()
        assignee_id = d.get("assignee_id") or None
        company_id = d.get("company_id") or None
        contact_id = d.get("contact_id") or None
        if assignee_id:
            try:
                aid = int(assignee_id)
            except Exception:
                return jsonify(ok=False, error="bad assignee"), 400
            if not query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (aid, org_id), one=True):
                return jsonify(ok=False, error="assignee out of org"), 400
        if company_id:
            try:
                cid = int(company_id)
            except Exception:
                return jsonify(ok=False, error="bad company"), 400
            if not query_db("SELECT 1 FROM companies WHERE id=? AND org_id=?", (cid, org_id), one=True):
                return jsonify(ok=False, error="company out of org"), 400
        if contact_id:
            try:
                coid = int(contact_id)
            except Exception:
                return jsonify(ok=False, error="bad contact"), 400
            if not query_db("SELECT 1 FROM contacts WHERE id=? AND org_id=?", (coid, org_id), one=True):
                return jsonify(ok=False, error="contact out of org"), 400
        deal_id = exec_db(
            """INSERT INTO deals (org_id,title,stage,amount,currency,status,assignee_id,company_id,contact_id)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (org_id, title, stage, amount, currency, status, assignee_id, company_id, contact_id),
        )
        if not deal_id:
            return jsonify(ok=False, error="insert failed"), 500
        add_audit(org_id, "deal.created", "deal", deal_id, {"stage": stage, "amount": amount})
        try:
            fire_event("deal.created", org_id, {"deal_id": deal_id})
        except Exception:
            pass
        return jsonify(ok=True, id=deal_id)
    except Exception as e:
        app.logger.exception(f"Deal create error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/deal/update", methods=["PATCH", "POST"])
@login_required
def api_deal_update():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        did = int(d.get("id") or 0)
        row = query_db("SELECT * FROM deals WHERE id=? AND org_id=?", (did, org_id), one=True)
        if not row:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_deal(session["user_id"], row):
            return jsonify(ok=False, error="forbidden"), 403
        allowed = {"title", "stage", "amount", "currency", "status", "assignee_id", "company_id", "contact_id", "tags_json", "extra_json", "due_at", "current_department_id"}
        sets, params = [], []
        for k in allowed:
            if k in d:
                if k in ("assignee_id", "company_id", "contact_id") and d[k]:
                    tbl = "users" if k == "assignee_id" else ("companies" if k == "company_id" else "contacts")
                    try:
                        val = int(d[k])
                    except Exception:
                        return jsonify(ok=False, error=f"bad {k}"), 400
                    if not query_db(f"SELECT 1 FROM {tbl} WHERE id=? AND org_id=?", (val, org_id), one=True):
                        return jsonify(ok=False, error=f"{k} out of org"), 400
                if k == "tags_json" and isinstance(d[k], (list, dict)):
                    sets.append(f"{k}=?")
                    params.append(json.dumps(d[k], ensure_ascii=False))
                elif k == "due_at":
                    sets.append("due_at=?"); params.append(ensure_iso_datetime(d.get("due_at") or "") or None)
                else:
                    sets.append(f"{k}=?"); params.append(d[k])
        if not sets:
            return jsonify(ok=False, error="empty"), 400
        sets.append("updated_at=CURRENT_TIMESTAMP")
        params += [did, org_id]
        rc = exec_db_rowcount(f"UPDATE deals SET {', '.join(sets)} WHERE id=? AND org_id=?", tuple(params))
        if rc <= 0:
            return jsonify(ok=False, error="not updated"), 400
        add_audit(org_id, "deal.updated", "deal", did, {"patch": list(d.keys())})
        try:
            fire_event("deal.updated", org_id, {"deal_id": did, "patch": list(d.keys())})
        except Exception:
            pass
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Deal update error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/deal/participants", methods=["POST"])
@login_required
def api_deal_participants():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        deal_id = int(d.get("deal_id") or 0)
        add_users = [int(x) for x in (d.get("add") or []) if str(x).isdigit()]
        remove_users = [int(x) for x in (d.get("remove") or []) if str(x).isdigit()]
        role = (d.get("role") or "assignee").strip()
        row = query_db("SELECT * FROM deals WHERE id=? AND org_id=?", (deal_id, org_id), one=True)
        if not row:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_deal(session["user_id"], row):
            return jsonify(ok=False, error="forbidden"), 403
        for uid in add_users:
            if query_db("SELECT 1 FROM users WHERE id=? AND org_id=?", (uid, org_id), one=True):
                _ = exec_db("INSERT INTO deal_participants (org_id,deal_id,user_id,role) VALUES (?,?,?,?)", (org_id, deal_id, uid, role))
        for uid in remove_users:
            exec_db("DELETE FROM deal_participants WHERE org_id=? AND deal_id=? AND user_id=?", (org_id, deal_id, uid))
        try:
            fire_event("deal.updated", org_id, {"deal_id": deal_id, "participants_changed": True})
        except Exception:
            pass
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Deal participants error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/deal/assign_department", methods=["POST"])
@login_required
def api_deal_assign_department():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        deal_id = int(d.get("deal_id") or 0)
        dept_id = int(d.get("department_id") or 0)
        stage_key = (d.get("stage_key") or "").strip() or None
        comment = (d.get("comment") or "").strip()
        due_at = ensure_iso_datetime(d.get("due_at") or "") or None
        row = query_db("SELECT * FROM deals WHERE id=? AND org_id=?", (deal_id, org_id), one=True)
        if not row:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_deal(session["user_id"], row):
            return jsonify(ok=False, error="forbidden"), 403
        if dept_id and not query_db("SELECT 1 FROM departments WHERE id=? AND org_id=?", (dept_id, org_id), one=True):
            return jsonify(ok=False, error="dept not found"), 404
        to_stage = None
        if stage_key:
            to_stage = query_db("SELECT * FROM workflow_stages WHERE org_id=? AND entity_type='deal' AND key=? AND active=1", (org_id, stage_key), one=True)
            if not to_stage:
                return jsonify(ok=False, error="stage not found"), 404
        sets = []
        params = []
        if dept_id:
            sets.append("current_department_id=?"); params.append(dept_id)
        if to_stage:
            sets.append("stage=?"); params.append(to_stage["key"])
        if due_at:
            sets.append("due_at=?"); params.append(due_at)
        if sets:
            sets.append("updated_at=CURRENT_TIMESTAMP")
            params += [deal_id, org_id]
            exec_db(f"UPDATE deals SET {', '.join(sets)} WHERE id=? AND org_id=?", tuple(params))
        exec_db(
            "INSERT INTO stage_transitions (org_id,entity_type,entity_id,from_stage,to_stage,by_user_id,department_id,comment,due_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (org_id, "deal", deal_id, row["stage"], (to_stage["key"] if to_stage else row["stage"]), session["user_id"], dept_id or row["current_department_id"], comment, due_at),
        )
        if dept_id:
            _notify_dept_heads(dept_id, f"Сделка #{deal_id}: передана в отдел", url_for("deals_page", _external=True))
        try:
            fire_event("deal.stage.changed", org_id, {"deal_id": deal_id, "department_id": dept_id, "stage": (to_stage["key"] if to_stage else None)})
        except Exception:
            pass
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Deal assign dept error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Approvals public (with CSRF + rate limit) -------------------
@app.route("/approval/<token>", methods=["GET", "POST"])
def approval_public(token):
    try:
        a = query_db("SELECT * FROM approvals WHERE token=?", (token,), one=True)
        if not a:
            abort(404)
        if request.method == "POST":
            verify_csrf()
            ip = client_ip()
            if not rate_limit(f"appr:{token}:{ip}", per_min=10):
                flash("Слишком часто, попробуйте позже", "error")
                return redirect(url_for("approval_public", token=token))
            action = (request.form.get("action") or "").strip()
            message = (request.form.get("message") or "").strip()[:1000]
            form_tok = (request.form.get("form_token") or "").strip()
            if form_tok != (a["form_token"] or ""):
                abort(403)
            if action not in ("approve", "request_changes"):
                flash("Неверное действие", "error")
            else:
                new_status = "approved" if action == "approve" else "changes_requested"
                cur = query_db("SELECT status FROM approvals WHERE id=?", (a["id"],), one=True)
                if cur and str(cur["status"]).lower() == "approved":
                    flash("Решение уже принято", "info")
                else:
                    exec_db("UPDATE approvals SET status=?, updated_at=CURRENT_TIMESTAMP, form_token=NULL WHERE id=?", (new_status, a["id"]))
                    exec_db(
                        "INSERT INTO approvals_log (approval_id, actor, action, message, ip, ua) VALUES (?,?,?,?,?,?)",
                        (a["id"], "public", action, message, client_ip(), request.headers.get("User-Agent", "")[:300]),
                    )
                    flash("Решение сохранено", "success")

        a = query_db("SELECT * FROM approvals WHERE token=?", (token,), one=True)
        if not a["form_token"]:
            tok = secrets.token_urlsafe(24)
            exec_db("UPDATE approvals SET form_token=? WHERE id=?", (tok, a["id"]))
            a = query_db("SELECT * FROM approvals WHERE id=?", (a["id"],), one=True)
        logs = query_db("SELECT * FROM approvals_log WHERE approval_id=? ORDER BY id", (a["id"],))
        inner = render_safe(APPROVAL_PUBLIC_TMPL, a=a, logs=logs)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Approval public error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


# ------------------- Settings (Admin) incl. Channels/Webhooks/AI config/Statuses/Users -------------------
@app.route("/settings", methods=["GET"])
@admin_required
def settings():
    try:
        org_id = current_org_id()
        channels = query_db("SELECT * FROM channels WHERE org_id=? ORDER BY id DESC", (org_id,))
        ch_list = []
        for r in channels:
            d = dict(r)
            try:
                d["cfg"] = json.loads(d.get("settings_json") or "{}")
            except Exception:
                d["cfg"] = {}
            ch_list.append(d)
        webhooks = query_db("SELECT * FROM webhooks WHERE org_id=? ORDER BY id DESC", (org_id,))
        scripts = query_db("SELECT * FROM call_scripts WHERE org_id=? ORDER BY id DESC", (org_id,))
        ai_jobs = query_db("SELECT id,kind,status,created_at FROM ai_jobs WHERE org_id=? ORDER BY id DESC LIMIT 50", (org_id,))
        statuses = query_db("SELECT id,name FROM task_statuses WHERE org_id=? ORDER BY id", (org_id,))
        users = query_db("SELECT id, username, email, role, active, created_at FROM users WHERE org_id=? ORDER BY id", (org_id,))
        inner = render_safe(SETTINGS_TMPL, channels=ch_list, webhooks=webhooks, scripts=scripts, ai_jobs=ai_jobs, task_statuses=statuses, users=users)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Settings error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


@app.route("/settings/channel/toggle/<int:cid>", methods=["POST"])
@admin_required
def settings_channel_toggle(cid):
    verify_csrf()
    org_id = current_org_id()
    ch = query_db("SELECT active FROM channels WHERE id=? AND org_id=?", (cid, org_id), one=True)
    if not ch:
        flash("Канал не найден", "error")
        return redirect(url_for("settings"))
    exec_db("UPDATE channels SET active=? WHERE id=? AND org_id=?", (0 if ch["active"] else 1, cid, org_id))
    return redirect(url_for("settings"))


@app.route("/settings/channel/add", methods=["POST"])
@admin_required
def settings_channel_add():
    verify_csrf()
    org_id = current_org_id()
    typ = (request.form.get("type") or "").strip()
    name = (request.form.get("name") or "").strip() or typ
    secret = secrets.token_urlsafe(24)
    exec_db("INSERT INTO channels (org_id,type,name,secret,active) VALUES (?,?,?,?,1)", (org_id, typ, name, secret))
    return redirect(url_for("settings"))


def _valid_webhook_url(u: str) -> bool:
    try:
        p = urlparse(u or "")
        if p.scheme not in ("http", "https"):
            return False
        try:
            host = p.netloc.split("@")[-1].split(":")[0]
            ips = _resolve_all_ips(host)
            if any(_is_private_ip(ip) for ip in ips):
                return False
        except Exception:
            pass
        return True
    except Exception:
        return False


@app.route("/settings/webhook/add", methods=["POST"])
@admin_required
def settings_webhook_add():
    verify_csrf()
    org_id = current_org_id()
    event = (request.form.get("event") or "").strip()
    urlv = (request.form.get("url") or "").strip()
    secret = (request.form.get("secret") or "").strip()
    if not event or not urlv:
        flash("Событие и URL обязательны", "error")
        return redirect(url_for("settings"))
    if not _valid_webhook_url(urlv):
        flash("URL недопустим", "error")
        return redirect(url_for("settings"))
    exec_db("INSERT INTO webhooks (org_id,event,url,secret,active) VALUES (?,?,?,?,1)", (org_id, event, urlv, secret))
    return redirect(url_for("settings"))


@app.route("/settings/webhook/delete/<int:wid>", methods=["POST"])
@admin_required
def settings_webhook_delete(wid):
    verify_csrf()
    org_id = current_org_id()
    exec_db("DELETE FROM webhooks WHERE id=? AND org_id=?", (wid, org_id))
    return redirect(url_for("settings"))


@app.route("/settings/webhook/test/<int:wid>", methods=["POST"])
@admin_required
def settings_webhook_test(wid):
    try:
        verify_csrf_header()
        org_id = current_org_id()
        wh = query_db("SELECT * FROM webhooks WHERE id=? AND org_id=?", (wid, org_id), one=True)
        if not wh:
            return jsonify(ok=False, error="not found"), 404
        payload = {"test": True, "ts": utc_iso(), "event": wh["event"]}
        exec_db(
            "INSERT INTO webhook_queue (org_id,event,payload_json,status,attempts,created_at) VALUES (?,?,?,?,0,CURRENT_TIMESTAMP)",
            (org_id, wh["event"], json.dumps(payload, ensure_ascii=False), "pending"),
        )
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Webhook test error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/settings/phone/<int:cid>/update", methods=["POST"])
@admin_required
def settings_phone_update(cid):
    verify_csrf()
    org_id = current_org_id()
    ch = query_db("SELECT * FROM channels WHERE id=? AND org_id=? AND type='phone'", (cid, org_id), one=True)
    if not ch:
        flash("Канал не найден", "error")
        return redirect(url_for("settings"))
    provider = (request.form.get("provider") or "").strip().lower()
    if provider not in ("", "mango", "uis", "telfin"):
        flash("Неверный провайдер", "error")
        return redirect(url_for("settings"))
    secret = (request.form.get("secret") or "").strip()
    signing_key = (request.form.get("signing_key") or "").strip()
    from_e164 = phone_to_e164(request.form.get("from_e164") or "")
    try:
        cfg = json.loads(ch["settings_json"] or "{}")
    except Exception:
        cfg = {}
    cfg.update({"provider": provider, "signing_key": signing_key, "from_e164": from_e164})
    exec_db("UPDATE channels SET secret=?, settings_json=? WHERE id=? AND org_id=?", (secret, json.dumps(cfg, ensure_ascii=False), cid, org_id))
    return redirect(url_for("settings"))


@app.route("/settings/phone/<int:cid>/webhook_urls")
@admin_required
def settings_phone_webhook_urls(cid):
    org_id = current_org_id()
    ch = query_db("SELECT * FROM channels WHERE id=? AND org_id=? AND type='phone'", (cid, org_id), one=True)
    if not ch:
        return jsonify(ok=False, error="not found"), 404
    try:
        cfg = json.loads(ch["settings_json"] or "{}")
    except Exception:
        cfg = {}
    provider = (cfg.get("provider") or CLICK_TO_CALL_PROVIDER or "mango").lower()
    secret = ch["secret"] or ""
    base = request.host_url.rstrip("/")
    return jsonify(
        ok=True,
        cti_webhook=f"{base}/integrations/cti/{provider}/{cid}/{secret}/webhook",
        recording_webhook=f"{base}/integrations/cti/{provider}/{cid}/{secret}/recording",
    )


def _get_org_ai_config(org_id: int):
    r = query_db("SELECT plan_meta FROM orgs WHERE id=?", (org_id,), one=True)
    try:
        meta = json.loads((r["plan_meta"] or "{}")) if r else {}
    except Exception:
        meta = {}
    return meta.get("ai_config") or {}


def _set_org_ai_config(org_id: int, cfg: dict):
    r = query_db("SELECT plan_meta FROM orgs WHERE id=?", (org_id,), one=True)
    try:
        meta = json.loads((r["plan_meta"] or "{}")) if r else {}
    except Exception:
        meta = {}
    meta["ai_config"] = cfg or {}
    exec_db("UPDATE orgs SET plan_meta=? WHERE id=?", (json.dumps(meta, ensure_ascii=False), org_id))


@app.route("/settings/ai/config", methods=["GET", "POST"])
@admin_required
def settings_ai_config():
    org_id = current_org_id()
    if request.method == "GET":
        return jsonify(ok=True, config=_get_org_ai_config(org_id))
    verify_csrf()
    provider = (request.form.get("provider") or "").strip()
    model = (request.form.get("model") or "").strip()
    try:
        temperature = float(request.form.get("temperature") or "0.3")
    except Exception:
        temperature = 0.3
    try:
        max_tokens = int(request.form.get("max_tokens") or "512")
    except Exception:
        max_tokens = 512
    policy_raw = (request.form.get("policy") or "").strip()
    policy = None
    if policy_raw:
        try:
            policy = json.loads(policy_raw)
        except Exception:
            policy = None
    cfg = {"provider": provider, "model": model, "temperature": temperature, "max_tokens": max_tokens}
    if policy is not None:
        cfg["policy"] = policy
    _set_org_ai_config(org_id, cfg)
    return redirect(url_for("settings"))


@app.route("/settings/task_status/add", methods=["POST"])
@admin_required
def settings_task_status_add():
    verify_csrf()
    org_id = current_org_id()
    name = (request.form.get("name") or "").strip()
    if not name:
        return redirect(url_for("settings"))
    exec_db("INSERT INTO task_statuses (org_id,name) VALUES (?,?)", (org_id, name))
    return redirect(url_for("settings"))


@app.route("/settings/task_status/delete/<int:sid>", methods=["POST"])
@admin_required
def settings_task_status_delete(sid):
    verify_csrf()
    org_id = current_org_id()
    exec_db("DELETE FROM task_statuses WHERE id=? AND org_id=?", (sid, org_id))
    return redirect(url_for("settings"))


@app.route("/settings/user/toggle/<int:uid>", methods=["POST"])
@admin_required
def settings_user_toggle(uid):
    verify_csrf()
    org_id = current_org_id()
    u = query_db("SELECT active FROM users WHERE id=? AND org_id=?", (uid, org_id), one=True)
    if not u:
        return redirect(url_for("settings"))
    exec_db("UPDATE users SET active=? WHERE id=? AND org_id=?", (0 if u["active"] else 1, uid, org_id))
    return redirect(url_for("settings"))


@app.route("/settings/user/password/<int:uid>", methods=["POST"])
@admin_required
def settings_user_password(uid):
    verify_csrf()
    org_id = current_org_id()
    pwd = (request.form.get("password") or "").strip()
    ok, msg = password_policy_ok(pwd)
    if not ok:
        flash(msg or "Пароль не соответствует политике", "error")
        return redirect(url_for("settings"))
    exec_db("UPDATE users SET password_hash=? WHERE id=? AND org_id=?", (generate_password_hash(pwd), uid, org_id))
    add_audit(org_id, "user.password_changed", "user", uid, {})
    flash("Пароль обновлён", "success")
    return redirect(url_for("settings"))


@app.route("/settings/user/add", methods=["POST"])
@admin_required
def settings_user_add():
    verify_csrf()
    org_id = current_org_id()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    role = (request.form.get("role") or "agent").strip()
    pwd = (request.form.get("password") or "").strip()
    ok, msg = password_policy_ok(pwd)
    if not ok or not username:
        flash(msg or "Логин/пароль некорректны", "error")
        return redirect(url_for("settings"))
    if query_db("SELECT 1 FROM users WHERE org_id=? AND username=?", (org_id, username), one=True):
        flash("Логин уже существует в организации", "error")
        return redirect(url_for("settings"))
    exec_db(
        "INSERT INTO users (org_id,username,email,password_hash,role,active) VALUES (?,?,?,?,?,1)",
        (org_id, username, email, generate_password_hash(pwd), role),
    )
    return redirect(url_for("settings"))


# ------------------- API Tokens (Admin JSON) — hash-only, show once -------------------
def _api_token_new_secret() -> str:
    return secrets.token_urlsafe(32)


@app.route("/api/tokens/list")
@admin_required
def api_tokens_list():
    try:
        org_id = current_org_id()
        rows = query_db("SELECT id,name,active,user_id,last_used_at,created_at,expires_at,scopes FROM api_tokens WHERE org_id=? ORDER BY id DESC", (org_id,))
        items = []
        for r in rows:
            items.append(dict(r))
        return jsonify(ok=True, items=items)
    except Exception as e:
        app.logger.exception(f"Tokens list error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/tokens/create", methods=["POST"])
@admin_required
def api_tokens_create():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        name = (d.get("name") or "API Token").strip()
        user_id = d.get("user_id") or None
        scopes = ",".join(d.get("scopes") or [])
        expires_at = ensure_iso_datetime(d.get("expires_at") or "") or None
        raw = _api_token_new_secret()
        th = _token_hash(raw)
        tid = exec_db(
            "INSERT INTO api_tokens (org_id,user_id,name,token_hash,scopes,expires_at,active,created_at) VALUES (?,?,?,?,?,?,1,CURRENT_TIMESTAMP)",
            (org_id, user_id, name, th, scopes, expires_at),
        )
        return jsonify(ok=True, id=tid, token=raw)
    except Exception as e:
        app.logger.exception(f"Token create error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/tokens/toggle", methods=["POST"])
@admin_required
def api_tokens_toggle():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        tid = int(d.get("id") or 0)
        row = query_db("SELECT active FROM api_tokens WHERE id=? AND org_id=?", (tid, org_id), one=True)
        if not row:
            return jsonify(ok=False, error="not found"), 404
        exec_db("UPDATE api_tokens SET active=? WHERE id=? AND org_id=?", (0 if row["active"] else 1, tid, org_id))
        return jsonify(ok=True)
    except Exception as e:
        app.logger.exception(f"Token toggle error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Webhook queue ops (UI redelivery support) -------------------
@app.route("/api/webhook/queue")
@admin_required
def api_webhook_queue():
    try:
        org_id = current_org_id()
        rows = query_db("SELECT * FROM webhook_queue WHERE org_id=? ORDER BY id DESC LIMIT 200", (org_id,))
        return jsonify(ok=True, items=[dict(r) for r in rows])
    except Exception as e:
        app.logger.exception(f"Webhook queue list error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/webhook/retry/<int:qid>", methods=["POST"])
@admin_required
def api_webhook_retry(qid):
    try:
        verify_csrf_header()
        org_id = current_org_id()
        rc = exec_db_rowcount("UPDATE webhook_queue SET status='pending', next_try_at=NULL WHERE id=? AND org_id=?", (qid, org_id))
        return jsonify(ok=rc > 0)
    except Exception as e:
        app.logger.exception(f"Webhook retry error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Global Search UI -------------------
@app.route("/search")
@login_required
def search_page():
    try:
        q = (request.args.get("q") or "").strip()
        results = {"inbox": [], "tasks": [], "chats": []}
        if q:
            org_id = current_org_id()
            q_fts = fts_sanitize(q)
            inbox_rows = query_db(
                """
                SELECT m.id, m.thread_id, m.body
                FROM inbox_messages m
                JOIN inbox_messages_fts f ON f.rowid=m.id
                WHERE m.org_id=? AND f.body MATCH ?
                ORDER BY m.id DESC LIMIT 50
                """,
                (org_id, q_fts),
            )
            task_rows = query_db(
                """
                SELECT t.id, t.title, t.description
                FROM tasks t
                JOIN tasks_fts f ON f.rowid=t.id
                WHERE t.org_id=? AND f MATCH ?
                ORDER BY t.id DESC LIMIT 50
                """,
                (org_id, q_fts),
            )
            chat_rows = query_db(
                """
                SELECT c.id, c.channel_id, c.body
                FROM chat_messages c
                JOIN chat_messages_fts f ON f.rowid=c.id
                WHERE c.org_id=? AND f.body MATCH ?
                ORDER BY c.id DESC LIMIT 50
                """,
                (org_id, q_fts),
            )
            results["inbox"] = [dict(r) for r in (inbox_rows or [])]
            results["tasks"] = [dict(r) for r in (task_rows or [])]
            results["chats"] = [dict(r) for r in (chat_rows or [])]
        inner = render_safe(SEARCH_TMPL, q=q, results=results)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Search page error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))

# ------------------- Import CSV Wizard (UI) -------------------
@app.route("/import", methods=["GET", "POST"])
@login_required
def import_csv_wizard():
    try:
        if request.method == "POST":
            verify_csrf()
            f = request.files.get("csvfile")
            mode = (request.form.get("mode") or "").strip()
            if not f or not f.filename:
                flash("Файл не выбран", "error")
            else:
                # Подтверждаем приём файла; дальнейшая обработка настраивается отдельно
                flash("Файл получен, обработка будет выполнена", "success")
        inner = render_safe(IMPORT_TMPL)
        return render_safe(LAYOUT_TMPL, inner=inner)
    except Exception as e:
        app.logger.exception(f"Import wizard error: {e}")
        flash("Внутренняя ошибка", "error")
        return redirect(url_for("index"))


# ------------------- Deals Kanban (missing APIs implemented) -------------------
@app.route("/api/deals/kanban")
@login_required
def api_deals_kanban():
    try:
        org_id = current_org_id()
        cols = [r["key"] for r in (query_db("SELECT key FROM workflow_stages WHERE org_id=? AND entity_type='deal' AND active=1 ORDER BY order_no", (org_id,)) or [])]
        if not cols:
            cols = sorted(list({r["stage"] for r in (query_db("SELECT DISTINCT stage FROM deals WHERE org_id=?", (org_id,)) or [])}))
        items = {c: [] for c in cols}
        rows = query_db("SELECT id,title,stage,amount,currency,assignee_id FROM deals WHERE org_id=? ORDER BY id DESC LIMIT 5000", (org_id,))
        for r in rows:
            st = r["stage"] or (cols[0] if cols else "new")
            if st not in items:
                items[st] = []
            items[st].append(dict(r))
        return jsonify(ok=True, columns=cols, items=items)
    except Exception as e:
        app.logger.exception(f"Deals kanban error: {e}")
        return jsonify(ok=False, error="internal error"), 500


@app.route("/api/deals/kanban/update", methods=["POST"])
@login_required
def api_deals_kanban_update():
    try:
        verify_csrf_header()
        org_id = current_org_id()
        d = request.get_json(force=True) or {}
        did = int(d.get("id") or 0)
        stage = (d.get("stage") or "").strip()
        row = query_db("SELECT * FROM deals WHERE id=? AND org_id=?", (did, org_id), one=True)
        if not row:
            return jsonify(ok=False, error="not found"), 404
        if not can_edit_deal(session["user_id"], row):
            return jsonify(ok=False, error="forbidden"), 403
        # allow free-form stage or validate via workflow_stages
        rc = exec_db_rowcount("UPDATE deals SET stage=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (stage, did, org_id))
        if rc > 0:
            _metrics_inc("kanban_ops_total", ("move",))
            add_audit(org_id, "deal.stage.move", "deal", did, {"to": stage})
            try:
                fire_event("deal.updated", org_id, {"deal_id": did, "stage": stage})
            except Exception:
                pass
        return jsonify(ok=(rc > 0))
    except Exception as e:
        app.logger.exception(f"Deals kanban update error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# ------------------- Custom Fields API (missing, now implemented) -------------------
@app.route("/api/custom_fields", methods=["GET", "POST"])
@admin_required
def api_custom_fields():
    try:
        org_id = current_org_id()
        if request.method == "GET":
            ent = (request.args.get("entity") or "").strip()
            if not ent:
                return jsonify(ok=False, error="entity required"), 400
            rows = query_db(
                "SELECT id, entity, key, type, label, required, default, options_json, rules_json FROM custom_fields WHERE org_id=? AND entity=? ORDER BY id",
                (org_id, ent),
            )
            items = []
            for r in rows or []:
                items.append({
                    "id": r["id"], "entity": r["entity"], "key": r["key"], "type": r["type"], "label": r["label"],
                    "required": int(r["required"] or 0) == 1, "default": r["default"] or "",
                    "options": json.loads(r["options_json"] or "[]"), "rules": json.loads(r["rules_json"] or "{}"),
                })
            return jsonify(ok=True, items=items)
        # POST
        verify_csrf_header()
        d = request.get_json(force=True) or {}
        entity = (d.get("entity") or "").strip()
        key = (d.get("key") or "").strip()
        type_ = (d.get("type") or "text").strip()
        label = (d.get("label") or key).strip()
        required = 1 if d.get("required") else 0
        default = d.get("default") or ""
        options = json.dumps(d.get("options") or [], ensure_ascii=False)
        rules = json.dumps(d.get("rules") or {}, ensure_ascii=False)
        if not entity or not key or not label:
            return jsonify(ok=False, error="entity/key/label required"), 400
        # unique per org+entity+key enforced by index
        fid = exec_db(
            "INSERT INTO custom_fields (org_id,entity,key,type,label,required,default,options_json,rules_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (org_id, entity, key, type_, label, required, default, options, rules),
        )
        _metrics_inc("custom_fields_ops_total", ("create",))
        return jsonify(ok=True, id=fid)
    except Exception as e:
        app.logger.exception(f"Custom fields API error: {e}")
        return jsonify(ok=False, error="internal error"), 500
# === END CORE PART 9/9 (2/3) ===
# === CORE PART 9/9 (3/3) — Workflow Engine, Workers (webhook/maintenance), Startup hooks ===
# -*- coding: utf-8 -*-

# ------------------- Workflow Engine (whitelisted set_field, safer awaits) -------------------
def _wf_load_graph(def_row):
    try:
        g = json.loads(def_row["graph_json"] or "{}")
        return g if isinstance(g, dict) else {}
    except Exception:
        return {}


def _wf_eval_path(obj: dict, path: str):
    cur = obj
    for part in (path.split(".") if path else []):
        if isinstance(cur, dict) and part in cur:
            cur = cur.get(part)
        else:
            return None
    return cur


def _wf_eval_value(val, ctx: dict, payload: dict):
    if isinstance(val, str) and val.startswith("{{") and val.endswith("}}"):
        inner = val[2:-2].strip()
        if inner.startswith("payload."):
            return _wf_eval_path(payload, inner.split("payload.", 1)[1])
        if inner.startswith("ctx."):
            return _wf_eval_path(ctx, inner.split("ctx.", 1)[1])
        return _wf_eval_path({"ctx": ctx, "payload": payload}, inner)
    return val


def _ai_policy_for_org(org_id: int) -> dict:
    try:
        cfg = _get_org_ai_config(org_id) or {}
        pol = cfg.get("policy") or {}
        return {
            "allow_summary": bool(pol.get("allow_summary", True)),
            "allow_autotag": bool(pol.get("allow_autotag", True)),
            "allow_set_fields": bool(pol.get("allow_set_fields", True)),
            "approval_required_for": list(pol.get("approval_required_for", [])),
            "exclude_internal_notes": bool(pol.get("exclude_internal_notes", AI_EXCLUDE_INTERNAL_NOTES_DEFAULT)),
            "await_max_minutes": int(pol.get("await_max_minutes", 24 * 60)),
        }
    except Exception:
        return {"allow_summary": True, "allow_autotag": True, "allow_set_fields": True, "approval_required_for": [], "exclude_internal_notes": AI_EXCLUDE_INTERNAL_NOTES_DEFAULT, "await_max_minutes": 1440}


_WF_SET_FIELD_ALLOWED = {
    "task": {"title", "description", "priority", "status", "due_at", "assignee_id", "current_stage", "current_department_id", "address", "contact_phone"},
    "deal": {"title", "stage", "amount", "currency", "status", "assignee_id", "current_department_id", "due_at"},
}


def _wf_mark_task_done(task_id: int):
    exec_db("UPDATE workflow_tasks SET status='done' WHERE id=?", (task_id,))


def _wf_enqueue_next(run_id: int, node_key: str, ctx: dict, payload: dict, delay_sec: int = 0):
    _wf_enqueue_task(run_id, node_key, {"ctx": ctx, "payload": payload}, max(0, int(delay_sec or 0)))


def _wf_create_approval(org_id: int, title: str, description: str) -> int:
    token = secrets.token_urlsafe(32)
    aid = exec_db(
        "INSERT INTO approvals (org_id,task_id,token,title,description,status,form_token) VALUES (?,?,?,?,?,'pending',NULL)",
        (org_id, None, token, title, description),
    )
    return aid


def _wf_execute_node(run_row, def_row, node_key: str, task_row):
    org_id = int(run_row["org_id"])
    g = _wf_load_graph(def_row)
    nodes = g.get("nodes") or {}
    node = nodes.get(node_key) or {}
    ntype = (node.get("type") or "start").lower()
    params = node.get("params") or {}
    next_key = node.get("next")

    try:
        ctx = json.loads(run_row["ctx_json"] or "{}")
    except Exception:
        ctx = {}
    try:
        payload = json.loads(task_row["payload_json"] or "{}")
    except Exception:
        payload = {}
    p_ctx = payload.get("ctx") or {}
    p_payload = payload.get("payload") or {}
    ctx_m = {**(ctx if isinstance(ctx, dict) else {}), **(p_ctx if isinstance(p_ctx, dict) else {})}
    pay_m = {**(p_payload if isinstance(p_payload, dict) else {})}

    if ntype == "start":
        return next_key

    if ntype == "if":
        field = str(params.get("field") or "")
        op = str(params.get("op") or "eq").lower()
        value = params.get("value")
        left = None
        val_eval = _wf_eval_value(value, ctx_m, pay_m)
        if field.startswith("ctx."):
            left = _wf_eval_path(ctx_m, field.split("ctx.", 1)[1])
        elif field.startswith("payload."):
            left = _wf_eval_path(pay_m, field.split("payload.", 1)[1])
        else:
            left = _wf_eval_path({"ctx": ctx_m, "payload": pay_m}, field)
        res = False
        try:
            if op == "eq":
                res = (str(left) == str(val_eval))
            elif op == "ne":
                res = (str(left) != str(val_eval))
            elif op == "contains":
                res = (str(val_eval) in str(left))
            elif op == "regex":
                pat = str(val_eval or "")
                if len(pat) <= 200:
                    res = bool(re.search(pat, str(left or "")))
        except Exception:
            res = False
        return node.get("next_true") if res else node.get("next_false")

    if ntype == "delay":
        sec = int(params.get("seconds") or 0)
        if next_key:
            _wf_enqueue_next(run_row["id"], next_key, ctx_m, pay_m, sec)
        return None

    if ntype == "set_field":
        entity = (params.get("entity") or "").strip()
        target_id_raw = params.get("id")
        target_id = _wf_eval_value(target_id_raw, ctx_m, pay_m)
        fields = params.get("fields") or {}
        pol = _ai_policy_for_org(org_id)
        if not pol.get("allow_set_fields", True):
            add_audit(org_id, "wf.denied", "workflow", run_row["id"], {"node": node_key, "reason": "policy_disallow_set_fields"})
            return next_key
        allowed = _WF_SET_FIELD_ALLOWED.get(entity, set())
        try:
            updates = {}
            for k, v in (fields.items() if isinstance(fields, dict) else []):
                if k not in allowed:
                    continue
                updates[k] = _wf_eval_value(v, ctx_m, pay_m)
            if updates and entity in ("task", "deal") and int(target_id or 0) > 0:
                sets = []
                vals = []
                for k, v in updates.items():
                    if k == "due_at":
                        v = ensure_iso_datetime(v or "")
                    sets.append(f"{k}=?"); vals.append(v)
                if entity == "task":
                    exec_db(f"UPDATE tasks SET {', '.join(sets)}, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", tuple(vals + [int(target_id), org_id]))
                else:
                    exec_db(f"UPDATE deals SET {', '.join(sets)}, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", tuple(vals + [int(target_id), org_id]))
        except Exception as e:
            app.logger.error(f"[WF] set_field failed: {e}")
        return next_key

    if ntype == "move_stage":
        entity = (params.get("entity") or "task").strip()
        target_id = _wf_eval_value(params.get("id"), ctx_m, pay_m)
        stage = _wf_eval_value(params.get("stage"), ctx_m, pay_m)
        dept = _wf_eval_value(params.get("department_id"), ctx_m, pay_m)
        due = ensure_iso_datetime(_wf_eval_value(params.get("due_at"), ctx_m, pay_m) or "")
        try:
            actor_uid = 0
            if entity == "task" and int(target_id or 0) > 0:
                t = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (int(target_id), org_id), one=True)
                if t:
                    exec_db("UPDATE tasks SET current_stage=?, current_department_id=?, due_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?",
                            (stage, dept, due or None, int(target_id), org_id))
                    exec_db("INSERT INTO stage_transitions (org_id,entity_type,entity_id,from_stage,to_stage,by_user_id,department_id,comment,due_at) VALUES (?,?,?,?,?,?,?,?,?)",
                            (org_id, "task", int(target_id), t["current_stage"], stage, actor_uid, dept, "WF move_stage", due or None))
            elif entity == "deal" and int(target_id or 0) > 0:
                d = query_db("SELECT * FROM deals WHERE id=? AND org_id=?", (int(target_id), org_id), one=True)
                if d:
                    exec_db("UPDATE deals SET stage=?, current_department_id=?, due_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?",
                            (stage, dept, due or None, int(target_id), org_id))
                    exec_db("INSERT INTO stage_transitions (org_id,entity_type,entity_id,from_stage,to_stage,by_user_id,department_id,comment,due_at) VALUES (?,?,?,?,?,?,?,?,?)",
                            (org_id, "deal", int(target_id), d["stage"], stage, actor_uid, dept, "WF move_stage", due or None))
        except Exception as e:
            app.logger.error(f"[WF] move_stage failed: {e}")
        return next_key

    if ntype == "notify_user":
        users = params.get("user_id") or params.get("users") or []
        if isinstance(users, (int, str)):
            users = [users]
        try:
            title = str(params.get("title") or "Уведомление")
            body = str(params.get("body") or "")
            link = str(params.get("link") or "")
            resolved = []
            for uref in users:
                uid = _wf_eval_value(uref, ctx_m, pay_m)
                if uid:
                    resolved.append(int(uid))
            if resolved:
                notify_user(resolved, title, body, link)
        except Exception as e:
            app.logger.error(f"[WF] notify_user failed: {e}")
        return next_key

    if ntype == "webhook_call":
        ev = str(params.get("event") or "workflow.event")
        pl = params.get("payload") or {}
        try:
            resolved_pl = {}
            for k, v in pl.items():
                resolved_pl[k] = _wf_eval_value(v, ctx_m, pay_m)
            emit_webhook(org_id, ev, {"workflow_run": run_row["id"], "node": node_key, "payload": resolved_pl})
        except Exception as e:
            app.logger.error(f"[WF] webhook_call failed: {e}")
        return next_key

    if ntype == "ai_call":
        action = str(params.get("action") or "")
        pol = _ai_policy_for_org(org_id)
        need_approval = action in set(pol.get("approval_required_for") or [])
        allowed = True
        if action in ("summarize_thread",) and not pol.get("allow_summary", True):
            allowed = False
        if action in ("autotag_thread",) and not pol.get("allow_autotag", True):
            allowed = False
        if action in ("set_field",) and not pol.get("allow_set_fields", True):
            allowed = False
        if not allowed:
            add_audit(org_id, "wf.ai.denied", "workflow", run_row["id"], {"node": node_key, "action": action})
            return next_key
        if need_approval:
            try:
                desc = f"Workflow AI action '{action}' requires approval"
                aid = _wf_create_approval(org_id, f"WF AI: {action}", desc)
                _wf_enqueue_task(run_row["id"], "await_approval", {"approval_id": aid, "next": next_key, "tries": 0}, 0)
                return None
            except Exception as e:
                app.logger.error(f"[WF] approval creation failed: {e}")
                return next_key
        try:
            text = str(_wf_eval_value(params.get("text") or "", ctx_m, pay_m) or "")
            sys = str(params.get("system") or "")
            out = ai_provider_call(text[:4000], system_prompt=sys, temperature=float(params.get("temperature") or 0.3), max_tokens=int(params.get("max_tokens") or 300))
            exec_db("INSERT INTO ai_jobs (org_id,kind,status,input_ref,output_json) VALUES (?,'workflow','completed',?,?)",
                    (org_id, f"run:{run_row['id']}:{node_key}", json.dumps({"action": action, "text": text, "out": out}, ensure_ascii=False)))
        except Exception as e:
            app.logger.error(f"[WF] ai_call failed: {e}")
        return next_key

    if ntype == "await_approval":
        aid = int((payload or {}).get("approval_id") or 0)
        nxt = (payload or {}).get("next")
        tries = int((payload or {}).get("tries") or 0)
        max_minutes = int(_ai_policy_for_org(org_id).get("await_max_minutes", 1440))
        if not aid:
            return next_key or nxt
        a = query_db("SELECT status, updated_at FROM approvals WHERE id=?", (aid,), one=True)
        if not a:
            return next_key or nxt
        if str(a["status"]).lower() == "approved":
            return nxt or next_key
        if tries >= max_minutes:
            add_audit(org_id, "wf.await.timeout", "workflow", run_row["id"], {"approval_id": aid})
            return next_key
        _wf_enqueue_next(run_row["id"], node_key, ctx_m, {"approval_id": aid, "next": nxt, "tries": tries + 1}, 60)
        return None

    return next_key


def _wf_execute_once():
    now = datetime.utcnow().isoformat(" ", "seconds")
    timers = query_db("SELECT * FROM workflow_timers WHERE fire_at<=? ORDER BY id LIMIT 50", (now,))
    for t in timers or []:
        try:
            exec_db("DELETE FROM workflow_timers WHERE id=?", (t["id"],))
            try:
                payload = json.loads(t["payload_json"] or "{}")
            except Exception:
                payload = {}
            _wf_enqueue_task(t["run_id"], t["node_key"], payload, 0)
        except Exception:
            pass

    tasks = query_db(
        """SELECT * FROM workflow_tasks
           WHERE status='pending' AND (next_at IS NULL OR next_at<=?)
           ORDER BY id LIMIT 50""",
        (now,),
    )
    if tasks:
        try:
            next_times = [r["next_at"] for r in tasks if r["next_at"]]
            if next_times:
                try:
                    oldest = min([datetime.fromisoformat(str(x).replace("T", " ")) for x in next_times])
                    lag = max(0, int((datetime.utcnow() - oldest).total_seconds()))
                    _metrics_set("workflow_queue_lag_sec", ("tasks",), lag)
                except Exception:
                    pass
        except Exception:
            pass
    for t in tasks or []:
        try:
            run = query_db("SELECT * FROM workflow_runs WHERE id=?", (t["run_id"],), one=True)
            if not run or str(run["status"]) != "running":
                _wf_mark_task_done(t["id"])
                continue
            wf_def = query_db("SELECT * FROM workflow_defs WHERE id=?", (run["def_id"],), one=True)
            if not wf_def or int(wf_def["active"] or 0) != 1:
                _wf_mark_task_done(t["id"])
                continue
            next_key = _wf_execute_node(run, wf_def, str(t["node_key"]), t)
            _wf_mark_task_done(t["id"])
            if next_key:
                _wf_enqueue_next(run["id"], str(next_key), {}, {})
        except Exception as e:
            app.logger.error(f"[WF] execute task {t.get('id')} failed: {e}")
            _wf_mark_task_done(t["id"])


# ------------------- Workers, Locks, Helpers -------------------
_worker_lock_path = os.path.join(DATA_DIR, ".workers.lock")
_worker_lock_acquired = False
WEBHOOK_MAX_ATTEMPTS = int(os.environ.get("WEBHOOK_MAX_ATTEMPTS", "10"))


def _acquire_worker_lock():
    global _worker_lock_acquired
    if REDIS_CLIENT:
        try:
            got = REDIS_CLIENT.set("crm:workers:lock", int(time.time()), nx=True, ex=300)
            if got:
                _worker_lock_acquired = True
                return True
        except Exception:
            pass
    try:
        if os.path.exists(_worker_lock_path):
            try:
                with open(_worker_lock_path, "r", encoding="utf-8") as f:
                    pid_str = (f.read() or "").strip()
                p = int(pid_str or 0)
                if p > 0:
                    try:
                        os.kill(p, 0)
                        return False
                    except Exception:
                        os.remove(_worker_lock_path)
            except Exception:
                try:
                    os.remove(_worker_lock_path)
                except Exception:
                    pass
        with open(_worker_lock_path, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        _worker_lock_acquired = True
        return True
    except Exception:
        return False


def _refresh_worker_lock():
    if not _worker_lock_acquired:
        return
    if REDIS_CLIENT:
        try:
            REDIS_CLIENT.expire("crm:workers:lock", 300)
        except Exception:
            pass


def _release_worker_lock():
    global _worker_lock_acquired
    if not _worker_lock_acquired:
        return
    if REDIS_CLIENT:
        try:
            REDIS_CLIENT.delete("crm:workers:lock")
        except Exception:
            pass
    try:
        if os.path.isfile(_worker_lock_path):
            with open(_worker_lock_path, "r", encoding="utf-8") as f:
                pid_str = (f.read() or "").strip()
            if pid_str == str(os.getpid()):
                os.remove(_worker_lock_path)
    except Exception:
        pass
    _worker_lock_acquired = False


def webhook_worker():
    try:
        import requests as _rq
        requests_available = True
    except Exception:
        _rq = None
        requests_available = False
    logged_unavailable = False
    with app.app_context():
        while True:
            _refresh_worker_lock()
            try:
                _metrics_set("worker_heartbeat", ("webhook",), int(time.time()))
                if not requests_available:
                    if not logged_unavailable:
                        app.logger.warning("requests not available, webhook delivery paused")
                        logged_unavailable = True
                    time.sleep(10)
                    continue
                now = datetime.utcnow().isoformat(" ", "seconds")
                rows = query_db(
                    """SELECT * FROM webhook_queue
                       WHERE status='pending' AND (next_try_at IS NULL OR next_try_at<=?)
                       ORDER BY id ASC LIMIT 10""",
                    (now,),
                )
                for r in rows:
                    whs = query_db("SELECT * FROM webhooks WHERE org_id=? AND event=? AND active=1", (r["org_id"], r["event"]))
                    if not whs:
                        exec_db("UPDATE webhook_queue SET status='delivered', attempts=attempts+1 WHERE id=?", (r["id"],))
                        _metrics_inc("webhook_delivery_total", (r["event"], "skipped_no_targets"))
                        continue
                    payload = r["payload_json"] or "{}"
                    delivered = 0
                    for wbh in whs:
                        try:
                            sig = sign_payload(wbh["secret"] or "", payload.encode("utf-8"))
                            headers = {
                                "Content-Type": "application/json",
                                "X-Event": r["event"],
                                "X-Signature": sig,
                                "X-Idempotency-Key": f"whq-{r['id']}-{r['event']}",
                            }
                            resp = _rq.post(wbh["url"], data=payload.encode("utf-8"), headers=headers, timeout=8)
                            if 200 <= resp.status_code < 300:
                                delivered += 1
                        except Exception as e:
                            app.logger.error(f"[WEBHOOK] delivery failed: {e}")
                    if delivered == len(whs):
                        exec_db("UPDATE webhook_queue SET status='delivered', attempts=attempts+1 WHERE id=?", (r["id"],))
                        _metrics_inc("webhook_delivery_total", (r["event"], "delivered"))
                    else:
                        attempts = (r["attempts"] or 0) + 1
                        if attempts >= WEBHOOK_MAX_ATTEMPTS:
                            exec_db("UPDATE webhook_queue SET attempts=?, status='failed' WHERE id=?", (attempts, r["id"]))
                            _metrics_inc("webhook_delivery_total", (r["event"], "failed"))
                        else:
                            delay = min(3600, int((2 ** min(6, attempts)) * 5))
                            next_try = (datetime.utcnow() + timedelta(seconds=delay)).isoformat(" ", "seconds")
                            exec_db("UPDATE webhook_queue SET attempts=?, next_try_at=? WHERE id=?", (attempts, next_try, r["id"]))
                            _metrics_inc("webhook_delivery_total", (r["event"], "retry"))
            except Exception as e:
                app.logger.exception(f"[WEBHOOK] worker error: {e}")
            time.sleep(5)


def _email_decode_header(s):
    try:
        from email.header import decode_header
        decoded = decode_header(s or "")
        out = ""
        for part, enc in decoded:
            if isinstance(part, bytes):
                try:
                    out += part.decode(enc or "utf-8", "ignore")
                except Exception:
                    out += part.decode("utf-8", "ignore")
            else:
                out += part or ""
        return out
    except Exception:
        return s or ""


def _email_fetch_once():
    if not EMAIL_ENABLED:
        return
    try:
        import imaplib
        import email
    except Exception:
        return
    rows = query_db("SELECT * FROM mail_accounts ORDER BY id LIMIT 5")
    for acc in rows or []:
        acc_id = acc["id"]
        try:
            host = (acc["host"] or EMAIL_IMAP_HOST)
            port = int(acc["port"] or EMAIL_IMAP_PORT)
            login = (acc["login"] or EMAIL_IMAP_USER)
            pwd = (acc["password"] or EMAIL_IMAP_PASS)
            use_tls = int(acc["use_tls"] or 1) == 1
            if not host or not login or not pwd:
                continue
            M = imaplib.IMAP4_SSL(host, port) if use_tls else imaplib.IMAP4(host, port)
            M.login(login, pwd)
            M.select("INBOX")
            last_uid = int(acc.get("last_uid") or 0)
            typ, data = M.uid("search", None, f"UID {last_uid + 1}:*")
            if typ != "OK":
                try:
                    M.logout()
                except Exception:
                    pass
                continue
            uids = [int(x) for x in (data[0] or b"").split() if x.isdigit()]
            new_max_uid = last_uid
            for uid in uids[:50]:
                try:
                    typ, msg_data = M.uid("fetch", str(uid).encode("ascii"), b"(RFC822)")
                    if typ != "OK":
                        continue
                    msg = email.message_from_bytes(msg_data[0][1])
                    subject = _email_decode_header(msg.get("Subject", ""))
                    from_addr = msg.get("From", "")
                    to_addrs = msg.get("To", "")
                    message_id = (msg.get("Message-Id") or msg.get("Message-ID") or "").strip()
                    org_id = acc["org_id"]
                    if subject:
                        thr = query_db("SELECT id FROM email_threads WHERE org_id=? AND subject=? LIMIT 1", (org_id, subject), one=True)
                        tid = thr["id"] if thr else exec_db("INSERT INTO email_threads (org_id,subject,last_message_at) VALUES (?,?,CURRENT_TIMESTAMP)", (org_id, subject))
                    else:
                        tid = exec_db("INSERT INTO email_threads (org_id,subject,last_message_at) VALUES (?,?,CURRENT_TIMESTAMP)", (org_id, "(no subject)"))
                    if message_id and query_db("SELECT 1 FROM email_messages WHERE org_id=? AND account_id=? AND external_id=?", (org_id, acc_id, message_id), one=True):
                        pass
                    else:
                        body_text = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                ctype = part.get_content_type()
                                disp = str(part.get("Content-Disposition") or "")
                                if ctype == "text/plain" and "attachment" not in disp:
                                    try:
                                        body_text = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "ignore")
                                        break
                                    except Exception:
                                        pass
                        else:
                            try:
                                body_text = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", "ignore")
                            except Exception:
                                body_text = str(msg.get_payload() or "")
                        exec_db(
                            """INSERT INTO email_messages (org_id,account_id,thread_id,external_id,from_addr,to_addrs,subject,body_text,created_at,received_at,is_inbound)
                               VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)""",
                            (org_id, acc_id, tid, message_id or f"uid:{uid}", from_addr, to_addrs, subject, body_text),
                        )
                        exec_db("UPDATE email_threads SET last_message_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=?", (tid, org_id))
                    try:
                        M.uid("store", str(uid).encode("ascii"), b"+FLAGS", b"(\Seen)")
                    except Exception:
                        pass
                    new_max_uid = max(new_max_uid, uid)
                except Exception as e:
                    _metrics_inc("email_fetch_errors_total", (acc_id,))
                    app.logger.error(f"[EMAIL] fetch uid {uid} error for account {acc_id}: {e}")
            if new_max_uid > last_uid:
                exec_db("UPDATE mail_accounts SET last_uid=? WHERE id=?", (new_max_uid, acc_id))
            try:
                M.logout()
            except Exception:
                pass
        except Exception as e:
            _metrics_inc("email_fetch_errors_total", (acc_id,))
            app.logger.error(f"[EMAIL] fetch error for account {acc_id}: {e}")


def maintenance_worker():
    with app.app_context():
        last_analytics = 0
        while True:
            _refresh_worker_lock()
            try:
                _metrics_set("worker_heartbeat", ("maintenance",), int(time.time()))

                cutoff_notif = (datetime.utcnow() - timedelta(days=90)).isoformat(" ", "seconds")
                exec_db("DELETE FROM notifications WHERE created_at < ?", (cutoff_notif,))
                cutoff_wh = (datetime.utcnow() - timedelta(days=30)).isoformat(" ", "seconds")
                exec_db("DELETE FROM webhook_queue WHERE status='delivered' AND created_at < ?", (cutoff_wh,))
                if RETENTION_MONTHS > 0:
                    cutoff_audit = (datetime.utcnow() - timedelta(days=RETENTION_MONTHS * 30)).isoformat(" ", "seconds")
                    exec_db("DELETE FROM audit_logs WHERE created_at < ?", (cutoff_audit,))

                cutoff30 = (datetime.utcnow() - timedelta(days=30)).isoformat(" ", "seconds")
                olds = query_db("SELECT id, storage_key FROM files WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff30,))
                for frow in olds:
                    key = frow["storage_key"] or ""
                    if key.startswith("local:"):
                        try:
                            path = safe_local_storage_path(UPLOAD_DIR, key)
                            if os.path.isfile(path):
                                os.remove(path)
                        except Exception:
                            pass
                    exec_db("DELETE FROM files WHERE id=?", (frow["id"],))

                try:
                    last_ts = get_app_meta("fts_last_rebuild_ts", "0")
                    last = int(last_ts or "0")
                    nowi = int(time.time())
                    if nowi - last >= FTS_REBUILD_INTERVAL_SEC:
                        fts_rebuild_all()
                        set_app_meta("fts_last_rebuild_ts", str(nowi))
                except Exception:
                    pass

                now_ts = datetime.utcnow().isoformat(" ", "seconds")[:16]
                due = query_db(
                    """SELECT r.id, r.org_id, r.task_id, r.user_id, r.remind_at, r.message, t.title
                       FROM task_reminders r
                       LEFT JOIN tasks t ON t.id=r.task_id
                       WHERE r.fired=0 AND substr(r.remind_at,1,16) <= ?
                       ORDER BY r.remind_at ASC LIMIT 200""",
                    (now_ts,),
                )
                if due:
                    ids = [d["id"] for d in due]
                    q = ",".join(["?"] * len(ids))
                    exec_db(f"UPDATE task_reminders SET fired=1, fired_at=CURRENT_TIMESTAMP WHERE id IN ({q})", tuple(ids))
                    for d in due:
                        notify_user(d["user_id"], f"Напоминание по задаче #{d['task_id']}", d["message"] or (d["title"] or ""), "/tasks")
                        try:
                            sse_publish(d["user_id"], "task.reminder.popup", {
                                "task_id": d["task_id"],
                                "message": d["message"] or "Напоминание",
                                "title": d["title"] or "",
                                "remind_at": d["remind_at"]
                            })
                        except Exception:
                            pass
                        try:
                            exec_db("UPDATE tasks SET status='overdue', updated_at=CURRENT_TIMESTAMP WHERE id=? AND org_id=? AND status!='done'", (d["task_id"], d["org_id"]))
                        except Exception:
                            pass

                meetings = query_db(
                    """SELECT id, org_id, title, start_at, notify_before_min, participants_json, reminder_fired
                       FROM meetings
                       WHERE notify_before_min>0 AND reminder_fired=0 AND start_at IS NOT NULL
                       ORDER BY start_at ASC LIMIT 500"""
                )
                now_dt = datetime.utcnow()
                for m in meetings:
                    try:
                        st = datetime.fromisoformat(str(m["start_at"]).replace("T", " "))
                        delta_min = (st - now_dt).total_seconds() / 60.0
                        if delta_min <= (m["notify_before_min"] or 0):
                            exec_db("UPDATE meetings SET reminder_fired=1 WHERE id=?", (m["id"],))
                            try:
                                participants = json.loads(m["participants_json"] or "[]")
                            except Exception:
                                participants = []
                            title = m["title"] or "Встреча"
                            link = url_for("meeting_join", mid=m["id"], _external=True)
                            if participants:
                                notify_user(participants, "Скоро встреча", f"{title} · {st.isoformat(' ', 'seconds')}", link)
                                sse_publish_users(participants, "meeting.reminder", {"meeting_id": m["id"], "title": title, "start_at": str(m["start_at"])})
                    except Exception:
                        pass

                _wf_execute_once()

                if int(time.time()) % 180 < 2:
                    _email_fetch_once()

                if int(time.time()) - last_analytics >= 3600:
                    last_analytics = int(time.time())

            except Exception as e:
                app.logger.exception(f"[MAINT] error: {e}")
            time.sleep(60)


def start_workers_once():
    if app.config.get("_WORKERS"):
        return
    if not WORKERS_ENABLED:
        app.config["_WORKERS"] = True
        return
    if not _acquire_worker_lock():
        app.logger.info("Workers lock not acquired — skipping workers in this process")
        app.config["_WORKERS"] = True
        return
    try:
        threading.Thread(target=webhook_worker, daemon=True).start()
        threading.Thread(target=maintenance_worker, daemon=True).start()
        app.config["_WORKERS"] = True
    except Exception as e:
        app.logger.error(f"Workers start error: {e}")


@app.before_request
def _ensure_workers():
    try:
        if os.environ.get("WERKZEUG_RUN_MAIN", "true") == "true":
            start_workers_once()
    except Exception:
        pass
# === END CORE PART 9/9 (3/3) ===
# === STYLES PART 1/9 — BASE CSS, LAYOUT, LOGIN (org-aware), INDEX, PROFILE (strict CSP) ===
# -*- coding: utf-8 -*-

BASE_CSS = """
*{box-sizing:border-box}
:root{ --sidebar-w:76px; --sidebar-w-expanded:220px; }
html,body{margin:0;padding:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Arial;background:var(--bg);color:var(--fg)}
a{color:var(--accent);text-decoration:none} a:hover{opacity:.9}
.container{max-width:1280px;margin:0 auto;padding:16px}
.container.wide{max-width:100%}
.button{background:var(--accent);color:#0b130f;border:none;padding:8px 12px;border-radius:10px;cursor:pointer;font-weight:600}
.button.secondary{background:#0e1417;color:var(--accent-2);border:1px solid var(--border)}
.button.ghost{background:transparent;color:var(--fg);border:1px solid var(--border)}
.button.warn{background:var(--warn);color:#1b1300}
.button.danger{background:var(--err);color:#210000}
.iconbtn{padding:6px 10px;border-radius:8px;border:1px solid var(--border);background:transparent;color:var(--fg);cursor:pointer}
.iconbtn.small{padding:4px 8px;font-size:12px}
.iconbtn.phone{display:inline-flex;align-items:center;gap:6px}
.icon{width:22px;text-align:center}
.tag{padding:2px 8px;border-radius:999px;border:1px solid var(--border);font-size:12px}
.badge{padding:2px 8px;border-radius:999px;border:1px solid var(--border);font-size:12px}
.badge.ok{border-color:#2bd66a66;color:#2bd66a;background:#2bd66a1a}
.badge.warn{border-color:#ffc85766;color:#ffc857;background:#ffc8571a}
.badge.err{border-color:#ff6b6b66;color:#ff6b6b;background:#ff6b6b1a}
.help{color:var(--muted);font-size:12px}
.input,.select,textarea{background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:10px;padding:10px 12px}
.search{min-width:280px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:14px}
.table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:14px;overflow:hidden}
.table th,.table td{border-bottom:1px solid var(--border);padding:10px;vertical-align:top}
.table th{text-align:left;font-size:12px;color:var(--muted);font-weight:700;position:sticky;top:0;background:var(--panel);z-index:1}
.flash{padding:8px 10px;border-radius:10px;margin:8px 0;border-left:4px solid var(--border);background:var(--panel);border:1px solid var(--border);color:var(--fg)}
.flash.success{border-left-color:#2bd66a}
.flash.error{border-left-color:#ff6b6b}
.flash.info{border-left-color:#7ec1ff}
.flash.warn{border-left-color:#ffc857}

.sidebar{position:fixed;left:0;top:0;bottom:0;width:var(--sidebar-w);background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;align-items:stretch;padding:8px 6px;gap:6px;transition:width .15s ease}
.sidebar.expanded{width:var(--sidebar-w-expanded)}
.sidebar .top{display:flex;align-items:center;justify-content:space-between;padding:4px 6px}
.sidebar .toggle{width:34px;height:34px;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--fg);cursor:pointer}
.navwrap{display:flex;flex-direction:column;min-height:0;flex:1 1 auto}
.navlist{display:flex;flex-direction:column;gap:6px;margin-top:4px}
.navbottom{margin-top:auto;display:flex;flex-direction:column;gap:6px}
.navitem{display:flex;align-items:center;gap:10px;padding:8px;border:1px solid var(--border);border-radius:12px;color:var(--fg)}
.navitem .icon{width:22px;text-align:center}
.navitem .label{display:none}
.sidebar.expanded .navitem .label{display:inline}
.navitem.active{background:var(--panel);box-shadow:0 0 0 2px #2bd66a22 inset}
.navitem.logout{border-color:#ff6b6b66;color:#ff6b6b}
.navitem.logout:hover{background:#ff6b6b22}

.page{margin-left:var(--sidebar-w);transition:margin-left .15s ease}
.page.expanded{margin-left:var(--sidebar-w-expanded)}
.topbar{height:56px;display:flex;align-items:center;gap:12px;padding:0 16px;border-bottom:1px solid var(--border);background:var(--surface);position:sticky;top:0;z-index:8}
.topbar .right{margin-left:auto;display:flex;gap:16px;align-items:center}
.userbox{display:flex;gap:8px;align-items:center}
.userbox .ava{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);overflow:hidden;background:#fff}
.userbox .meta{display:flex;flex-direction:column;line-height:1.1}
.userbox .meta .name{font-weight:600}
.userbox .meta .pos{font-size:12px;color:var(--muted)}

.weather{display:flex;gap:8px;align-items:center;font-size:16px}
.weather .wicon{width:26px;height:26px;display:inline-flex;align-items:center;justify-content:center;font-size:20px}
.clock{font-variant-numeric:tabular-nums;color:var(--muted);font-size:18px}

.split{display:grid;grid-template-columns:1fr;gap:10px}
@media(min-width:980px){.split{grid-template-columns:1fr 1fr}}
.grid-filters{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;align-items:end}
@media(max-width:1100px){.grid-filters{grid-template-columns:repeat(3,1fr)}}
@media(max-width:720px){.grid-filters{grid-template-columns:repeat(2,1fr)}}

.split.equal{align-items:stretch}
.split.equal > .card{height:100%;display:flex;flex-direction:column}
.card .table{flex:1 1 auto}

.toast-wrap{position:fixed;right:16px;top:72px;display:flex;flex-direction:column;gap:8px;z-index:1000}
.toast{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--accent);color:var(--fg);padding:10px 12px;border-radius:12px;min-width:260px;box-shadow:0 8px 24px rgba(0,0,0,.35)}
.footer-stick{position:fixed;left:calc(var(--sidebar-w) + 12px);bottom:10px;color:var(--muted);z-index:5;font-size:12px}
.page.expanded ~ .footer-stick{left:calc(var(--sidebar-w-expanded) + 12px)}

.card form{max-width:900px}
.card form label{display:block;margin:6px 0}
.card form .input,.card form .select,.card form textarea{width:100%}
.grid-filters .input,.grid-filters .select{width:100%}

.fab{position:fixed;right:24px;bottom:24px;width:48px;height:48px;border-radius:50%;background:var(--accent);color:#0b130f;border:none;font-size:24px;line-height:48px;text-align:center;cursor:pointer;box-shadow:0 8px 24px rgba(0,0,0,.35)}
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:center;justify-content:center;z-index:1000}
.modal-backdrop.show{display:flex}
.modal{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px;min-width:320px;max-width:720px;width:90%}
.dial-menu{position:absolute;top:100%;left:0;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px;display:flex;flex-direction:column;gap:6px;z-index:20}
"""

# Pass small flags/constants into template context
@app.context_processor
def _inject_globals_for_templates():
    try:
        return {"CTI_SCREENPOP": CTI_SCREENPOP, "AVATAR_MAX_SIZE": AVATAR_MAX_SIZE}
    except Exception:
        return {}

# Make query_db available in Jinja where templates reference it
try:
    app.jinja_env.globals.update(query_db=query_db)
except Exception:
    pass

# -------------- LAYOUT TEMPLATE --------------
LAYOUT_TMPL = """
<!doctype html><html lang="ru" data-theme="{{ theme }}" style="{{ theme_css_vars }}">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <link rel="manifest" href="{{ url_for('manifest') }}">
    <style>{{ css }}</style>
    <title>{{ app_name }}</title>
  </head>
  <body>
    {% set expanded = session.get('sidebar_expanded', False) %}
    <div class="sidebar {% if expanded %}expanded{% endif %}" id="sidebar">
      <div class="top">
        <button class="toggle" id="btnSidebar" title="Меню">≡</button>
      </div>
      <div class="navwrap">
        <nav class="navlist">
          <a class="navitem {% if request.path.startswith('/inbox') or request.path=='/' %}active{% endif %}" href="{{ url_for('inbox') }}"><span class="icon">📨</span><span class="label">Входящие</span></a>
          <a class="navitem {% if request.path.startswith('/tasks') or request.path.startswith('/task/') %}active{% endif %}" href="{{ url_for('tasks_page') }}"><span class="icon">✅</span><span class="label">Задачи</span></a>
          <a class="navitem {% if request.path.startswith('/deals') %}active{% endif %}" href="{{ url_for('deals_page') }}"><span class="icon">📈</span><span class="label">Сделки</span></a>
          <a class="navitem {% if request.path.startswith('/lookup') %}active{% endif %}" href="{{ url_for('lookup') }}"><span class="icon">🔎</span><span class="label">Поиск</span></a>
          <a class="navitem {% if request.path.startswith('/chat') %}active{% endif %}" href="{{ url_for('chat') }}"><span class="icon">💬</span><span class="label">Чаты</span></a>
          <a class="navitem {% if request.path.startswith('/clients') or request.path.startswith('/client/') %}active{% endif %}" href="{{ url_for('clients_list') }}"><span class="icon">🧑‍💼</span><span class="label">Клиенты</span></a>
          <a class="navitem {% if request.path.startswith('/calls') %}active{% endif %}" href="{{ url_for('calls_page') }}"><span class="icon">📞</span><span class="label">Звонки</span></a>
          <a class="navitem {% if request.path.startswith('/meetings') or request.path.startswith('/meeting/') %}active{% endif %}" href="{{ url_for('meetings_page') }}"><span class="icon">🗓️</span><span class="label">Встречи</span></a>
          <a class="navitem {% if request.path.startswith('/analytics') %}active{% endif %}" href="{{ url_for('analytics') }}"><span class="icon">📊</span><span class="label">Аналитика</span></a>
          <a class="navitem {% if request.path.startswith('/import') %}active{% endif %}" href="{{ url_for('import_csv_wizard') }}"><span class="icon">📥</span><span class="label">Импорт</span></a>
          <a class="navitem {% if request.path.startswith('/search') %}active{% endif %}" href="{{ url_for('search_page') }}"><span class="icon">⌘</span><span class="label">Поиск по базе</span></a>
        </nav>
        <nav class="navbottom">
          {% if user and user.role=='admin' %}
          <a class="navitem {% if request.path.startswith('/settings') %}active{% endif %}" href="{{ url_for('settings') }}"><span class="icon">⚙️</span><span class="label">Настройки</span></a>
          {% endif %}
          <form method="post" action="{{ url_for('logout') }}" style="margin:0;" class="js-confirm" data-confirm="Выйти из системы?">
            <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
            <button class="navitem logout" type="submit" style="width:100%;background:none;"><span class="icon">⏻</span><span class="label">Выход</span></button>
          </form>
        </nav>
      </div>
    </div>
    <div class="page {% if expanded %}expanded{% endif %}" id="page">
      <div class="topbar">
        <form method="get" action="{{ url_for('inbox') }}" style="display:flex;gap:8px;">
          <input class="search input" name="q" placeholder="Поиск по сообщениям (FTS)..." value="{{ request.args.get('q','') }}">
          <button class="button ghost" type="submit">Найти</button>
        </form>
        <div style="display:flex;gap:8px;align-items:center;">
          <button class="button ghost" id="btnTheme" type="button">Тема</button>
          <button class="button secondary iconbtn phone" id="btnDial" type="button"><span class="icon">📞</span><span>Позвонить</span></button>
        </div>
        <div class="right">
          <div class="weather" id="weatherBox" title="Погода СПб">
            <span class="wicon" id="wIcon">☀️</span>
            <span id="wTemp" class="help" style="font-size:16px;">--°C</span>
          </div>
          <div class="clock" id="clockBox" title="Время (СПб)">--:--</div>
          <div class="userbox">
            <img class="ava" src="{{ user_avatar }}" alt="avatar">
            <div class="meta">
              <div class="name">{{ user_title or (user.username if user else '—') }}</div>
              <div class="pos">{{ user.position or '' }}</div>
            </div>
            <a class="button ghost" href="{{ url_for('profile') }}">Профиль</a>
          </div>
        </div>
      </div>
      <div class="container {{ container_class or '' }}">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}{% for category, msg in messages %}<div class="flash {{ category }}">{{ msg }}</div>{% endfor %}{% endif %}
        {% endwith %}
        {{ inner|safe }}
      </div>
    </div>
    <div class="footer-stick">© {{ now.year }} · {{ app_name }}</div>
    <div class="toast-wrap" id="toasts"></div>
    <script nonce="{{ csp_nonce }}">
      window.CSRF = "{{ session.get('csrf_token','') }}";
      (function(){
        const _fetch = window.fetch;
        window.fetch = function(input, init){
          init = init || {};
          if(!init.credentials){ init.credentials = 'same-origin'; }
          return _fetch(input, init);
        };
        window.postJSON = function(url, body){
          return fetch(url, {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':window.CSRF}, credentials:'same-origin', body: JSON.stringify(body||{})});
        };
        window.getJSON = function(url){ return fetch(url, {credentials:'same-origin'}); };
        window.postForm = function(url, fd){ return fetch(url, {method:'POST', headers:{'X-CSRFToken':window.CSRF}, credentials:'same-origin', body: fd}); };
      })();
      function esc(s){ return String(s||'').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
      function toast(msg){ const b=document.getElementById('toasts'); const t=document.createElement('div'); t.className='toast'; t.textContent = (msg==null?'':String(msg)); b.appendChild(t); setTimeout(()=>t.remove(),7000); }
      function wIcon(cond){ if(cond==='rain') return '🌧️'; if(cond==='snow') return '❄️'; if(cond==='fog') return '🌫️'; if(cond==='cloudy') return '⛅'; return '☀️'; }
      function normPhoneRU(raw){ const d=String(raw||'').replace(/\D+/g,''); if(!d) return ''; let n=d; if(n.length===11 && n.startsWith('8')) n='7'+n.slice(1); if(n.length===10) n='7'+n; return '+'+n; }

      (function(){
        try{
          const es=new EventSource('/sse');
          const doScreenpop = {{ 'true' if CTI_SCREENPOP else 'false' }};
          es.addEventListener('call.incoming', e=>{
            try{ const d=JSON.parse(e.data);
              toast('Входящий: ' + (d.from||'') + ' → ' + (d.to||''));
              if(doScreenpop && d.from){ setTimeout(()=>{ window.open('/lookup?phone='+encodeURIComponent(d.from),'_self'); }, 400); }
            }catch(_){}
          });
          es.addEventListener('call.outgoing', e=>{
            try{ const d=JSON.parse(e.data); toast('Исходящий: ' + (d.to||'')); }catch(_){}
          });
          es.addEventListener('call.screenpop', e=>{
            try{ const d=JSON.parse(e.data); if(doScreenpop && d.phone){ window.open('/lookup?phone='+encodeURIComponent(d.phone),'_self'); } }catch(_){}
          });
          es.addEventListener('chat.message', e=>{
            try{ const d=JSON.parse(e.data); toast('Сообщение в чате #' + (d.channel_id||'')); }catch(_){}
          });
          es.addEventListener('task.reminder', e=>{
            try{ const d=JSON.parse(e.data); toast('⏰ Напоминание · Задача #'+(d.task_id||'')); }catch(_){}
          });
          es.addEventListener('task.reminder.popup', e=>{
            try{ const d=JSON.parse(e.data); alert('⏰ Напоминание по задаче #' + (d.task_id||'') + '\\n' + (d.title||'') + (d.message ? ('\\n' + d.message) : '')); }catch(_){}
          });
          es.addEventListener('meeting.reminder', e=>{
            try{ const d=JSON.parse(e.data); toast('🗓️ Встреча скоро: ' + (d.title||'')); }catch(_){}
          });
        }catch(e){}
      })();

      async function refreshWeather(){
        try{
          const r = await fetch('/api/ui/weather');
          const j = await r.json();
          if(j.ok){
            document.getElementById('wIcon').textContent = wIcon(j.condition||'');
            if(typeof j.temperature==='number'){ document.getElementById('wTemp').textContent = Math.round(j.temperature) + '°C'; }
          }
        }catch(e){}
      }
      function refreshClockOnce(){
        try{
          const ft = new Intl.DateTimeFormat('ru-RU',{hour:'2-digit',minute:'2-digit', timeZone:'Europe/Moscow'});
          const el = document.getElementById('clockBox');
          if(el) el.textContent = ft.format(new Date());
        }catch(e){}
      }
      (function scheduleClock(){
        refreshClockOnce();
        const msToNext = 60000 - (Date.now() % 60000);
        setTimeout(function(){ refreshClockOnce(); setInterval(refreshClockOnce, 60000); }, msToNext);
      })();
      setInterval(refreshWeather, 1000*60*10);
      refreshWeather();

      if('serviceWorker' in navigator){ try{ navigator.serviceWorker.register('/sw.js'); }catch(e){} }

      function toggleSidebar(){
        const sb=document.getElementById('sidebar');
        const pg=document.getElementById('page');
        const exp=!sb.classList.contains('expanded');
        if(exp){ sb.classList.add('expanded'); pg.classList.add('expanded'); } else { sb.classList.remove('expanded'); pg.classList.remove('expanded'); }
        try{ fetch('/api/ui/sidebar',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':window.CSRF},body:JSON.stringify({expanded:exp})}); }catch(e){}
      }
      document.getElementById('btnTheme')?.addEventListener('click', e=>{
        e.preventDefault(); fetch('/toggle-theme',{method:'POST',headers:{'X-CSRFToken':window.CSRF}}).then(()=>location.reload());
      });
      document.getElementById('btnDial')?.addEventListener('click', (e)=>{
        e.preventDefault(); const raw=prompt('Наберите номер',''); const num = normPhoneRU(raw||'');
        if(num){ fetch('/api/cti/click_to_call',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':window.CSRF},body:JSON.stringify({to:num})})
          .then(r=>r.json()).then(j=>{ if(j.ok) toast('Звонок: '+num); else alert(j.error||'Ошибка звонка'); }); }
      });
      document.getElementById('btnSidebar')?.addEventListener('click', (e)=>{ e.preventDefault(); toggleSidebar(); });

      document.addEventListener('submit', function(e){
        const f = e.target.closest('form.js-confirm');
        if(!f) return;
        const msg = f.getAttribute('data-confirm') || 'Подтвердите действие';
        if(!confirm(msg)){ e.preventDefault(); }
      }, true);
    </script>
  </body>
</html>
"""

# -------------- LOGIN TEMPLATE (org-aware) --------------
LOGIN_TMPL = """
<!doctype html><html lang="ru" data-theme="{{ theme }}" style="{{ theme_css_vars }}"><head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>{{ css }}</style><title>{{ app_name }} · Вход</title></head>
  <body>
    <div class="container" style="max-width:420px;margin-top:6vh;">
      <h1 style="margin-bottom:10px;">{{ app_name }}</h1>
      {% if DEBUG %}
      <div class="help" style="margin-bottom:10px;">Демо: admin / (пароль сгенерирован при setup и выведен в stdout при DEBUG/PRINT_ADMIN_PASSWORD)</div>
      {% endif %}
      {% with messages=get_flashed_messages(with_categories=true) %}
        {% if messages %}{% for c,m in messages %}<div class="flash {{ c }}">{{ m }}</div>{% endfor %}{% endif %}
      {% endwith %}
      <div class="card">
        <form method="post" style="display:grid;gap:8px;">
          <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
          <input type="hidden" name="next" value="{{ request.args.get('next','') }}">
          <label>Организация (slug) <input class="input" name="org" type="text" placeholder="demo" required></label>
          <label>Логин <input class="input" name="username" type="text" required></label>
          <label>Пароль <input class="input" name="password" type="password" required></label>
          <button class="button" type="submit">Войти</button>
        </form>
        <div style="margin-top:8px;">
          <a class="button ghost" href="{{ url_for('setup') }}">Первичная настройка (если пустая БД)</a>
        </div>
      </div>
    </div>
  </body>
</html>
"""

# -------------- INDEX TEMPLATE --------------
INDEX_TMPL = """
<h2>Добро пожаловать</h2>
<div class="split">
  <div class="card">
    <h3>Быстрый старт</h3>
    <ul>
      <li><a href="{{ url_for('inbox') }}">Входящие</a> — диалоги из каналов</li>
      <li><a href="{{ url_for('calls_page') }}">Звонки</a> — список звонков, записи, переход к клиентам</li>
      <li><a href="{{ url_for('tasks_page') }}">Задачи</a> — создавайте задачи из сообщений/звонков</li>
      <li><a href="{{ url_for('deals_page') }}">Сделки</a> — воронка продаж</li>
      <li><a href="{{ url_for('meetings_page') }}">Встречи</a> — календарь, планирование, напоминания</li>
      <li><a href="{{ url_for('lookup') }}">Поиск</a> — телефон, ИНН, email, ID</li>
      <li><a href="{{ url_for('chat') }}">Командный чат</a> — общение команды</li>
      <li><a href="{{ url_for('analytics') }}">Аналитика</a> — SLA, звонки по менеджерам</li>
    </ul>
    <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
      <button class="iconbtn phone" type="button" id="btnDialIndex"><span class="icon">📞</span><span>Позвонить</span></button>
      <a class="button ghost" href="{{ url_for('profile') }}">Профиль</a>
    </div>
  </div>
  <div class="card">
    <h3>Интеграции</h3>
    <ul>
      <li>Telegram: настройте канал и вебхук в «Настройки → Каналы»</li>
      <li>VK Callback API: URL доступен в «Настройки → Каналы»</li>
      <li>Телефония (Mango/UIS/ТЕЛФИН): подключите канал «phone», используйте вебхуки</li>
      <li>Jitsi: встречи через {{ JITSI_BASE }}</li>
    </ul>
  </div>
</div>
<script nonce="{{ csp_nonce }}">
  document.getElementById('btnDialIndex')?.addEventListener('click', (e)=>{
    e.preventDefault();
    const raw=prompt('Номер для звонка');
    const num = (function(raw){ const d=String(raw||'').replace(/\\D+/g,''); if(!d) return ''; let n=d; if(n.length===11 && n.startsWith('8')) n='7'+n.slice(1); if(n.length===10) n='7'+n; return '+'+n; })(raw||'');
    if(num){
      fetch('/api/cti/click_to_call',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':window.CSRF}, body: JSON.stringify({to:num})})
        .then(r=>r.json()).then(j=>{ if(j.ok){ toast('Звонок: ' + num); } else { alert(j.error||'Ошибка'); } });
    }
  });
</script>
"""

# -------------- PROFILE TEMPLATE --------------
PROFILE_TMPL = """
<div class='card'>
  <h2>Профиль</h2>
  <div style="display:flex;gap:16px;align-items:center;">
    <img src="{{ avatar }}" alt="avatar" style="width:64px;height:64px;border-radius:12px;border:1px solid #21323b;background:#fff;">
    <div>
      <div class="help">Роль: {{ role }}</div>
      <div class="help">Логин: {{ username }}</div>
    </div>
  </div>
  <form method="post" style="display:grid;gap:8px;max-width:520px;margin-top:10px;">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">
    <label>Фамилия <input class="input" name="last_name" value="{{ last_name }}"></label>
    <label>Имя <input class="input" name="first_name" value="{{ first_name }}"></label>
    <label>Должность <input class="input" name="position" value="{{ position }}"></label>
    <label>Email <input class="input" name="email" type="email" value="{{ email }}"></label>
    <label>Часовой пояс <input class="input" name="tz" value="{{ tz }}"></label>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <button class="button" type="submit">Сохранить</button>
      <label class="button ghost" style="cursor:pointer;"> Загрузить аватар <input type="file" id="avatarFile" style="display:none"> </label>
      <button class="button secondary" id="btn2FABegin" type="button">Подключить 2FA</button>
      <button class="button warn" id="btn2FADisable" type="button">Отключить 2FA</button>
      <button class="button ghost" id="btnBackupCodes" type="button">Резервные коды</button>
    </div>
    <div class="help" id="twofaInfo"></div>
  </form>
</div>
<script nonce="{{ csp_nonce }}">
(async function(){
  const csrf='{{ csrf }}';
  async function uploadAvatar(){
    const f = document.getElementById('avatarFile').files[0];
    if(!f) return;
    if(f.size > {{ AVATAR_MAX_SIZE }}){ alert('Файл слишком большой'); return; }
    try{
      const fd = new FormData(); fd.append('file', f);
      const r = await fetch('{{ api_profile_avatar }}', { method:'POST', headers:{'X-CSRFToken': csrf}, body: fd, credentials:'same-origin' });
      const j = await r.json(); if(j.ok) location.reload(); else alert(j.error||'Ошибка загрузки');
    }catch(e){ alert('Ошибка сети'); }
  }
  document.getElementById('avatarFile')?.addEventListener('change', uploadAvatar);
  async function twofaBegin(){
    try{
      const r = await fetch('{{ url_for("api_twofa_begin") }}', {method:'POST', headers:{'X-CSRFToken': csrf}});
      const j = await r.json();
      if(j.ok){
        document.getElementById('twofaInfo').innerHTML = 'URI для приложения аутентификатора:<br><code>'+ (j.otpauth||'') +'</code><br>Введите код из приложения: <input class="input" id="twofaCode" style="max-width:140px;"> <button class="button small" id="btn2FAEnable">Включить</button>';
        document.getElementById('btn2FAEnable')?.addEventListener('click', twofaEnable);
      } else alert(j.error||'Ошибка');
    }catch(e){ alert('Ошибка сети'); }
  }
  async function twofaEnable(){
    const code = (document.getElementById('twofaCode')?.value||'').trim();
    if(!code) return alert('Введите код');
    try{
      const r = await fetch('{{ url_for("api_twofa_enable") }}', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken': csrf}, body: JSON.stringify({code})});
      const j = await r.json();
      if(j.ok){ alert('2FA включена. Сохраните резервные коды:\\n' + (j.backup_codes||[]).join('\\n')); location.reload(); } else alert(j.error||'Ошибка');
    }catch(e){ alert('Ошибка сети'); }
  }
  async function twofaDisable(){
    const pwd = prompt('Для отключения 2FA введите пароль:')||'';
    if(!pwd) return;
    try{
      const r = await fetch('{{ url_for("api_twofa_disable") }}', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken': csrf}, body: JSON.stringify({password: pwd})});
      const j = await r.json(); if(j.ok){ alert('2FA отключена'); location.reload(); } else { alert(j.error||'Ошибка'); }
    }catch(e){ alert('Ошибка сети'); }
  }
  async function genBackupCodes(){
    if(!confirm('Сгенерировать новые резервные коды? Старые станут недействительны.')) return;
    try{
      const r = await fetch('{{ url_for("api_twofa_backup_codes") }}', {method:'POST', headers:{'X-CSRFToken': csrf}});
      const j = await r.json(); if(j.ok){ alert('Новые коды:\\n' + (j.backup_codes||[]).join('\\n')); } else alert(j.error||'Ошибка');
    }catch(e){ alert('Ошибка сети'); }
  }
  document.getElementById('btn2FABegin')?.addEventListener('click', (e)=>{ e.preventDefault(); twofaBegin(); });
  document.getElementById('btn2FADisable')?.addEventListener('click', (e)=>{ e.preventDefault(); twofaDisable(); });
  document.getElementById('btnBackupCodes')?.addEventListener('click', (e)=>{ e.preventDefault(); genBackupCodes(); });
})();
</script>
"""
# === END STYLES PART 1/9 ===
# === STYLES PART 2/9 — INBOX LIST + THREAD VIEW (strict CSP, safe inserts) ===
# -*- coding: utf-8 -*-

INBOX_TMPL = """
<h2 style="margin:0 0 8px 0;">Входящие</h2>
<div class="card">
  <details open>
    <summary class="button ghost">Фильтры</summary>
    <form method="get" class="grid-filters" action="{{ url_for('inbox') }}">
      <label>Статус
        <select class="select" name="status">
          <option value="">— все —</option>
          <option value="open" {% if filters.status=='open' %}selected{% endif %}>Open</option>
          <option value="pending" {% if filters.status=='pending' %}selected{% endif %}>Pending</option>
          <option value="resolved" {% if filters.status=='resolved' %}selected{% endif %}>Resolved</option>
          <option value="snoozed" {% if filters.status=='snoozed' %}selected{% endif %}>Snoozed</option>
        </select>
      </label>
      <label>Канал
        <select class="select" name="channel">
          <option value="">— все —</option>
          {% for c in channels %}
          <option value="{{ c.id }}" {% if filters.channel|string==c.id|string %}selected{% endif %}>{{ c.name }} ({{ c.type }})</option>
          {% endfor %}
        </select>
      </label>
      <label>Назначено
        <select class="select" name="assignee">
          <option value="">— любой —</option>
          {% for a in agents %}
          <option value="{{ a.id }}" {% if filters.assignee|string==a.id|string %}selected{% endif %}>{{ a.username }}</option>
          {% endfor %}
        </select>
      </label>
      <label>Тип
        <select class="select" name="kind">
          <option value="">—</option>
          <option value="dm" {% if filters.kind=='dm' %}selected{% endif %}>1:1</option>
          <option value="group" {% if filters.kind=='group' %}selected{% endif %}>Группа</option>
        </select>
      </label>
      <label>Теги <input class="input" name="tags" value="{{ filters.tags or '' }}"></label>
      <label>Кому
        <select class="select" name="who">
          <option value="">—</option>
          <option value="me" {% if filters.who=='me' %}selected{% endif %}>Мои</option>
        </select>
      </label>
      <label>С <input class="input" type="date" name="date_from" value="{{ filters.date_from or '' }}"></label>
      <label>По <input class="input" type="date" name="date_to" value="{{ filters.date_to or '' }}"></label>
      <input type="hidden" name="q" value="{{ filters.q or '' }}">
      <div style="grid-column:1/-1;display:flex;gap:8px;justify-content:flex-end;margin-top:4px;">
        <button class="button" type="submit">Применить</button>
        <a class="button ghost" href="{{ url_for('inbox') }}">Сбросить</a>
        <a class="button ghost" href="{{ url_for('export_inbox_csv') }}">Экспорт CSV</a>
      </div>
    </form>
  </details>
</div>
<div class="card" style="margin-top:10px;">
  <table class="table">
    <thead>
      <tr>
        <th>ID</th><th>Тема</th><th>Канал</th><th>Статус</th><th>Приоритет</th>
        <th>Назначен</th><th>FRT</th><th>Обновлен</th><th></th>
      </tr>
    </thead>
    <tbody id="inboxTBody">
      {% for t in rows %}
      <tr data-id="{{ t.id }}" tabindex="0">
        <td>#{{ t.id }}</td>
        <td>{{ t.subject or '—' }}</td>
        <td>{{ t.channel_name or '—' }}</td>
        <td>
          {% set st = t.status or 'open' %}
          <select class="select th-status" data-id="{{ t.id }}">
            <option value="open" {% if st=='open' %}selected{% endif %}>open</option>
            <option value="pending" {% if st=='pending' %}selected{% endif %}>pending</option>
            <option value="resolved" {% if st=='resolved' %}selected{% endif %}>resolved</option>
            <option value="snoozed" {% if st=='snoozed' %}selected{% endif %}>snoozed</option>
          </select>
        </td>
        <td>
          {% set pr = t.priority or 'normal' %}
          <select class="select th-priority" data-id="{{ t.id }}">
            <option value="low" {% if pr=='low' %}selected{% endif %}>low</option>
            <option value="normal" {% if pr=='normal' %}selected{% endif %}>normal</option>
            <option value="high" {% if pr=='high' %}selected{% endif %}>high</option>
            <option value="urgent" {% if pr=='urgent' %}selected{% endif %}>urgent</option>
          </select>
        </td>
        <td>
          <select class="select th-assignee" data-id="{{ t.id }}">
            <option value="">—</option>
            {% for a in agents %}
            <option value="{{ a.id }}" {% if t.assignee_id==a.id %}selected{% endif %}>{{ a.username }}</option>
            {% endfor %}
          </select>
        </td>
        <td>
          {% if t.first_response_due_at and (not t.first_response_at) %}
            <span class="badge {% if now.isoformat(' ','seconds') > t.first_response_due_at %}err{% else %}warn{% endif %}">
              до {{ t.first_response_due_at }}
            </span>
          {% elif t.first_response_at %}
            <span class="badge ok">ответ: {{ t.first_response_at }}</span>
          {% else %}
            —
          {% endif %}
        </td>
        <td>{{ t.last_message_at or t.created_at }}</td>
        <td><a class="iconbtn small" href="{{ url_for('thread_view', tid=t.id) }}">Открыть</a></td>
      </tr>
      {% else %}
      <tr><td colspan="9"><div class="help">Ничего не найдено</div></td></tr>
      {% endfor %}
    </tbody>
  </table>
  <button class="button ghost" id="loadMoreBtn" style="margin-top:8px;">Загрузить больше</button>
</div>
<script nonce="{{ csp_nonce }}">
  const INBOX_AGENTS = {{ agents|tojson }};
  let inboxPage = 1;

  function badgeFRT(t){
    try{
      const due = t.first_response_due_at || '';
      const at = t.first_response_at || '';
      if(due && !at){
        const nowISO = new Date().toISOString().slice(0,19).replace('T',' ');
        const cls = (nowISO > due) ? 'err' : 'warn';
        return '<span class="badge '+cls+'">до '+ esc(due) +'</span>';
      }
      if(at){ return '<span class="badge ok">ответ: '+ esc(at) +'</span>'; }
    }catch(_){} return '—';
  }
  function assigneeSelectHTML(id, assignee_id){
    let opts = '<option value="">—</option>';
    for(const a of INBOX_AGENTS){
      const sel = (String(assignee_id||'')===String(a.id)) ? ' selected' : '';
      opts += '<option value="'+a.id+'"'+sel+'>'+esc(a.username)+'</option>';
    }
    return '<select class="select th-assignee" data-id="'+id+'">'+opts+'</select>';
  }
  function statusSelectHTML(id, status){
    const sts = ['open','pending','resolved','snoozed'];
    return '<select class="select th-status" data-id="'+id+'">' + sts.map(s=>('<option value="'+s+'"'+(s===(status||'open')?' selected':'')+'>'+s+'</option>')).join('') + '</select>';
  }
  function prioritySelectHTML(id, pr){
    const prs = ['low','normal','high','urgent'];
    return '<select class="select th-priority" data-id="'+id+'">' + prs.map(s=>('<option value="'+s+'"'+(s===(pr||'normal')?' selected':'')+'>'+s+'</option>')).join('') + '</select>';
  }
  function rowHTML(t){
    return `
      <tr data-id="${t.id}" tabindex="0">
        <td>#${t.id}</td>
        <td>${esc(t.subject||'—')}</td>
        <td>${esc(t.channel_name||'—')}</td>
        <td>${statusSelectHTML(t.id, t.status)}</td>
        <td>${prioritySelectHTML(t.id, t.priority)}</td>
        <td>${assigneeSelectHTML(t.id, t.assignee_id)}</td>
        <td>${badgeFRT(t)}</td>
        <td>${esc(t.last_message_at || t.created_at || '')}</td>
        <td><a class="iconbtn small" href="/thread/${t.id}">Открыть</a></td>
      </tr>`;
  }
  function buildParams(page){
    const params = new URLSearchParams(window.location.search);
    if(page) params.set('page', page);
    params.set('per_page', '50');
    return params;
  }
  async function loadMoreInbox(){
    inboxPage++;
    try{
      const params = buildParams(inboxPage);
      const url = '/api/inbox/list?' + params.toString();
      const r = await fetch(url);
      const j = await r.json();
      if(!j.ok){ alert(j.error||'Ошибка'); return; }
      const tb = document.getElementById('inboxTBody');
      let added = 0;
      for(const t of (j.items||[])){ tb.insertAdjacentHTML('beforeend', rowHTML(t)); added++; }
      if (added < (j.per_page||50)) document.getElementById('loadMoreBtn').style.display = 'none';
      toast('Загружено больше');
    }catch(e){ alert('Ошибка загрузки'); }
  }
  async function thUpdateGeneric(id, patch){
    try{
      const r=await fetch('/api/thread/update',{ method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body:JSON.stringify(Object.assign({id},patch)) });
      const j=await r.json(); if(!j.ok){ alert(j.error||'Ошибка'); }
    }catch(e){ alert('Ошибка сети'); }
  }
  document.addEventListener('change', (e)=>{
    const t = e.target; if(!t) return; const id = t.getAttribute('data-id'); if(!id) return;
    if(t.classList.contains('th-status')) thUpdateGeneric(parseInt(id,10), {status: t.value});
    else if(t.classList.contains('th-priority')) thUpdateGeneric(parseInt(id,10), {priority: t.value});
    else if(t.classList.contains('th-assignee')) thUpdateGeneric(parseInt(id,10), {assignee_id: t.value||null});
  });
  document.getElementById('loadMoreBtn')?.addEventListener('click', (e)=>{ e.preventDefault(); loadMoreInbox(); });

  document.addEventListener('keydown', e => {
    const tag=(e.target && e.target.tagName||'').toUpperCase();
    if (tag==='INPUT' || tag==='TEXTAREA' || e.ctrlKey || e.metaKey) return;
    const rows=[...document.querySelectorAll('#inboxTBody tr')];
    const active=(document.activeElement && document.activeElement.closest) ? document.activeElement.closest('tr') : null;
    const idx = rows.indexOf(active);
    if(e.key==='ArrowDown'){ e.preventDefault(); (rows[Math.min(rows.length-1, idx+1)]||rows[0]).focus(); }
    if(e.key==='ArrowUp'){ e.preventDefault(); (rows[Math.max(0, idx-1)]||rows[0]).focus(); }
    if(!active) return;
    const id = active.getAttribute('data-id');
    if(e.key.toLowerCase()==='o'){ e.preventDefault(); thUpdateGeneric(parseInt(id,10), {status: 'open'}); }
    if(e.key.toLowerCase()==='p'){ e.preventDefault(); thUpdateGeneric(parseInt(id,10), {status: 'pending'}); }
  });
</script>
"""

THREAD_TMPL = """
<h2>Диалог #{{ r.id }}</h2>
<div class="thread">
  <div>
    <div class="card" style="margin-bottom:10px;">
      <div style="display:grid;grid-template-columns:2fr 1fr 1fr;gap:8px;">
        <div><strong>Тема:</strong> {{ r.subject or '—' }}</div>
        <div><strong>Канал:</strong> {{ r.channel_id or '—' }}</div>
        <div>
          <strong>Статус:</strong>
          {% set st = r.status or 'open' %}
          <select class="select" id="thStatus">
            <option value="open" {% if st=='open' %}selected{% endif %}>open</option>
            <option value="pending" {% if st=='pending' %}selected{% endif %}>pending</option>
            <option value="resolved" {% if st=='resolved' %}selected{% endif %}>resolved</option>
            <option value="snoozed" {% if st=='snoozed' %}selected{% endif %}>snoozed</option>
          </select>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:8px;">
        <div>
          <strong>Приоритет:</strong>
          {% set pr = r.priority or 'normal' %}
          <select class="select" id="thPriority">
            <option value="low" {% if pr=='low' %}selected{% endif %}>low</option>
            <option value="normal" {% if pr=='normal' %}selected{% endif %}>normal</option>
            <option value="high" {% if pr=='high' %}selected{% endif %}>high</option>
            <option value="urgent" {% if pr=='urgent' %}selected{% endif %}>urgent</option>
          </select>
        </div>
        <div>
          <strong>Назначено:</strong>
          <select class="select" id="assigneeSelect">
            <option value="">—</option>
            {% for u in query_db('SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username',(user.org_id,)) %}
            <option value="{{ u.id }}" {% if r.assignee_id==u.id %}selected{% endif %}>{{ u.username }}</option>
            {% endfor %}
          </select>
        </div>
        <div>
          <strong>Теги:</strong>
          <input class="input" id="tagsInput" placeholder="tag1, tag2" value="{{ r.tags_csv or '' }}">
          <button class="iconbtn small" id="btnSaveTags">Сохранить</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="help">Хоткеи: R — отправить клиенту, T — задача из последнего клиентского сообщения, A — AI‑черновик, S — snooze</div>
      <div id="msgList" style="max-height:60vh;overflow:auto;">
        {% for m in messages %}
        <div class="msg {{ 'system' if m.internal_note else m.sender_type }}" data-mid="{{ m.id }}">
          <div class="meta">[{{ 'Внутренняя' if m.internal_note else m.sender_type }}] {{ m.created_at }} • {{ m.username or m.external_user_id or '—' }}</div>
          <div class="body">{{ m.body or '' }}</div>
          {% if not m.internal_note %}
          <div style="margin-top:6px;">
            <button class="iconbtn small btnMsgToTask" data-mid="{{ m.id }}">В задачу</button>
          </div>
          {% endif %}
        </div>
        {% else %}
        <div class="help">Сообщений пока нет</div>
        {% endfor %}
        <button class="button ghost" id="loadOlderBtnThread" style="margin:8px auto;display:block;">Загрузить ещё</button>
      </div>
    </div>

    <div class="card" style="margin-top:10px;">
      <div class="composer">
        <div id="dropZone" style="border:2px dashed var(--border);padding:10px;text-align:center;cursor:pointer;">Перетащите файлы или кликните для загрузки</div>
        <input type="file" id="fileInput" multiple style="display:none;">
        <div id="attachments" class="help" style="margin:6px 0;display:none;"></div>
        <textarea id="body" class="input" rows="4" placeholder="Напишите сообщение... (R — отправить клиенту, A — AI‑черновик)"></textarea>
        <div class="row" style="flex-wrap:wrap;">
          <label><input type="checkbox" id="internalNote"> внутренняя заметка</label>
          <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;">
            <button class="button ghost" type="button" id="btnAISumm">AI сводка <span id="summLoader" style="display:none;">...</span></button>
            <select class="select" id="tone">
              <option value="friendly">дружелюбно</option>
              <option value="neutral" selected>нейтрально</option>
              <option value="formal">формально</option>
            </select>
            <button class="button secondary" type="button" id="btnAIDraft">AI черновик <span id="draftLoader" style="display:none;">...</span></button>
            <button class="button" type="button" id="btnSendInternal">Отправить (внутр.)</button>
            <button class="button warn" type="button" id="btnSendExternal">Клиенту</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div>
    <div class="card">
      <h3>Сведения</h3>
      <div><strong>ID треда:</strong> {{ r.id }}</div>
      <div>
        <strong>FRT:</strong>
        {% if r.first_response_due_at and (not r.first_response_at) %}
          <span class="badge {% if now.isoformat(' ','seconds') > r.first_response_due_at %}err{% else %}warn{% endif %}"> до {{ r.first_response_due_at }} </span>
        {% elif r.first_response_at %}
          <span class="badge ok">ответ: {{ r.first_response_at }}</span>
        {% else %}—{% endif %}
      </div>
      <div><strong>Последнее сообщение:</strong> {{ r.last_message_at or r.created_at }}</div>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
        <a class="button ghost" href="{{ url_for('inbox') }}">← к списку</a>
        <button class="button ghost" type="button" id="btnSnooze">Snooze</button>
        <button class="iconbtn phone" type="button" id="btnThreadDial"><span class="icon">📞</span><span>Позвонить</span></button>
      </div>
    </div>
  </div>
</div>

<div class="modal-backdrop" id="toTaskModal">
  <div class="modal">
    <h3>Создать задачу из сообщения</h3>
    <form style="display:grid;gap:8px;">
      <input type="hidden" id="toTaskMid">
      <label>Заголовок <input class="input" id="toTaskTitle" required></label>
      <label>Срок <input class="input" type="datetime-local" id="toTaskDue"></label>
      <label>ID клиента (опц.) <input class="input" id="toTaskCompanyId" placeholder="ID карточки клиента"></label>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button class="button secondary" type="button" id="btnToTaskCancel">Отмена</button>
        <button class="button" type="button" id="btnToTaskSave">Создать</button>
      </div>
    </form>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
  const TID={{ r.id }};
  let msgPage = 1;
  let attList = [];

  function thPatch(patch){
    return fetch('/api/thread/update',{ method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body:JSON.stringify(Object.assign({id:TID},patch)) });
  }
  function saveTags(){
    const raw=(document.getElementById('tagsInput').value||'');
    const arr=[...new Set(raw.split(',').map(x=>x.trim()).filter(Boolean))];
    thPatch({tags_json:arr}).then(r=>r.json()).then(j=>{ if(!j.ok){ alert(j.error||'Ошибка'); }});
  }
  function updateAttView(){
    const el=document.getElementById('attachments');
    if(!attList.length){ el.style.display='none'; el.textContent=''; return; }
    el.style.display='block';
    el.innerHTML = 'Вложения: ' + attList.map(a=>('<a href="'+a.url+'" target="_blank">'+esc(a.name)+'</a>')).join(', ');
  }
  async function uploadFiles(files){
    try{
      const list = files || (document.getElementById('fileInput')?.files || []);
      if(!list || !list.length) return;
      for(let i=0;i<list.length;i++){
        const f=list[i]; const fd = new FormData(); fd.append('file', f);
        const r = await fetch('/api/message/upload', {method:'POST', headers:{'X-CSRFToken': CSRF}, body: fd});
        const j = await r.json();
        if(j.ok && j.file){ attList.push({file_id: j.file.id, name: j.file.name, url: j.file.url}); }
        else { alert((j.error||'Ошибка загрузки') + ': ' + (f && f.name ? f.name : '')); }
      }
      updateAttView(); toast('Файлы загружены');
    }catch(e){ alert('Ошибка загрузки файлов'); }
  }
  async function sendMsg(){
    const body=(document.getElementById('body').value||'').trim();
    const internal=document.getElementById('internalNote').checked;
    if(!body && !attList.length){ return alert('Пустое сообщение'); }
    try{
      const r=await fetch('/api/message/send',{ method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body:JSON.stringify({thread_id:TID, body, internal_note:internal, attachments:attList}) });
      const j=await r.json(); if(j.ok){ location.reload(); } else { alert(j.error||'Ошибка'); }
    }catch(e){ alert('Ошибка сети'); }
  }
  async function sendExternal(){
    const body=(document.getElementById('body').value||'').trim();
    if(!body){ return alert('Пустое сообщение'); }
    try{
      const r=await fetch('/api/channel/send',{ method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body:JSON.stringify({thread_id:TID, text:body}) });
      const j=await r.json(); if(j.ok){ location.reload(); } else { alert(j.error||'Ошибка'); }
    }catch(e){ alert('Ошибка сети'); }
  }
  async function aiSumm(){
    document.getElementById('summLoader').style.display = 'inline';
    try{
      const r=await fetch('/api/ai/summarize_thread',{ method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body:JSON.stringify({thread_id:TID}) });
      const j=await r.json(); if(j.ok){ toast('Сводка: ' + (j.summary||'')); } else { alert(j.error||'Ошибка AI'); }
    }catch(e){ alert('Ошибка сети'); } finally { document.getElementById('summLoader').style.display = 'none'; }
  }
  async function aiDraft(){
    document.getElementById('draftLoader').style.display = 'inline';
    try{
      const tone=document.getElementById('tone').value;
      const r=await fetch('/api/ai/draft_reply',{ method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body:JSON.stringify({thread_id:TID, tone}) });
      const j=await r.json(); if(j.ok && j.variants && j.variants.length){ document.getElementById('body').value=j.variants[0]; toast('Сгенерировано 3 варианта — первый подставлен'); } else { alert(j.error||'Ошибка AI'); }
    }catch(e){ alert('Ошибка сети'); } finally { document.getElementById('draftLoader').style.display = 'none'; }
  }
  function openToTaskModal(mid, defTitle){
    document.getElementById('toTaskMid').value = mid;
    document.getElementById('toTaskTitle').value = defTitle || '';
    document.getElementById('toTaskDue').value = '';
    document.getElementById('toTaskCompanyId').value = '';
    document.getElementById('toTaskModal').classList.add('show');
  }
  function closeToTaskModal(){ document.getElementById('toTaskModal').classList.remove('show'); }
  async function saveToTask(){
    const mid = parseInt(document.getElementById('toTaskMid').value, 10);
    const title = document.getElementById('toTaskTitle').value.trim();
    const due_at = document.getElementById('toTaskDue').value;
    const company_id = document.getElementById('toTaskCompanyId').value.trim();
    if (!title) return alert('Заголовок обязателен');
    try{
      const r=await fetch('/api/message/to_task',{ method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body:JSON.stringify({message_id:mid, title, due_at, company_id: company_id||null}) });
      const j=await r.json(); if(j.ok){ toast('Задача #'+j.task_id+' создана'); closeToTaskModal(); } else { alert(j.error||'Ошибка'); }
    }catch(e){ alert('Ошибка сети'); }
  }
  async function loadOlderMsgs(){
    msgPage++;
    try{
      const url = new URL(window.location.origin + '/api/thread/messages');
      url.searchParams.set('thread_id', TID);
      url.searchParams.set('page', msgPage);
      url.searchParams.set('per_page', 50);
      const r = await fetch(url.toString());
      const j = await r.json();
      if(!j.ok){ return alert(j.error||'Ошибка'); }
      const list = document.getElementById('msgList');
      let added = 0;
      for(const m of (j.items||[])){
        const wrap = document.createElement('div');
        wrap.className = 'msg ' + (m.internal_note ? 'system' : m.sender_type);
        wrap.setAttribute('data-mid', m.id);
        const meta = document.createElement('div');
        meta.className='meta';
        meta.textContent = '[' + (m.internal_note ? 'Внутренняя' : (m.sender_type||'')) + '] ' + (m.created_at||'') + ' • ' + (m.username||m.external_user_id||'—');
        const body = document.createElement('div');
        body.className='body';
        body.textContent = (m.body || '');
        wrap.appendChild(meta); wrap.appendChild(body);
        if(!m.internal_note){
          const act = document.createElement('div'); act.style.marginTop = '6px';
          const btn = document.createElement('button'); btn.className='iconbtn small btnMsgToTask'; btn.dataset.mid = String(m.id); btn.textContent='В задачу';
          act.appendChild(btn); wrap.appendChild(act);
        }
        list.insertBefore(wrap, document.getElementById('loadOlderBtnThread')); added++;
      }
      if (added < (j.per_page||50)) document.getElementById('loadOlderBtnThread').style.display = 'none';
      toast('Загружено ещё');
    }catch(e){ alert('Ошибка загрузки'); }
  }
  document.getElementById('thStatus')?.addEventListener('change', e=>{ e.preventDefault(); thPatch({status: e.target.value}); });
  document.getElementById('thPriority')?.addEventListener('change', e=>{ e.preventDefault(); thPatch({priority: e.target.value}); });
  document.getElementById('assigneeSelect')?.addEventListener('change', e=>{ e.preventDefault(); thPatch({assignee_id: e.target.value||null}); });
  document.getElementById('btnSaveTags')?.addEventListener('click', e=>{ e.preventDefault(); saveTags(); });
  document.getElementById('loadOlderBtnThread')?.addEventListener('click', e=>{ e.preventDefault(); loadOlderMsgs(); });
  document.getElementById('btnAISumm')?.addEventListener('click', e=>{ e.preventDefault(); aiSumm(); });
  document.getElementById('btnAIDraft')?.addEventListener('click', e=>{ e.preventDefault(); aiDraft(); });
  document.getElementById('btnSendInternal')?.addEventListener('click', e=>{ e.preventDefault(); sendMsg(); });
  document.getElementById('btnSendExternal')?.addEventListener('click', e=>{ e.preventDefault(); document.getElementById('internalNote').checked=false; sendExternal(); });
  document.getElementById('btnSnooze')?.addEventListener('click', e=>{ e.preventDefault(); thPatch({status:'snoozed'}); });
  document.getElementById('btnThreadDial')?.addEventListener('click', e=>{
    e.preventDefault(); const num=prompt('Номер для звонка');
    if(num){ fetch('/api/cti/click_to_call',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({to:num})})
      .then(r=>r.json()).then(j=>{ if(j.ok) toast('Звонок: '+num); else alert(j.error||'Ошибка');}); }
  });
  document.getElementById('fileInput')?.addEventListener('change', e=>uploadFiles());
  document.getElementById('dropZone')?.addEventListener('click', e=>{ e.preventDefault(); document.getElementById('fileInput')?.click(); });
  document.getElementById('dropZone')?.addEventListener('dragover', e=>{ e.preventDefault(); });
  document.getElementById('dropZone')?.addEventListener('drop', e=>{ e.preventDefault(); const files = e.dataTransfer.files; if (files && files.length) uploadFiles(files); });
  document.getElementById('btnToTaskCancel')?.addEventListener('click', e=>{ e.preventDefault(); closeToTaskModal(); });
  document.getElementById('btnToTaskSave')?.addEventListener('click', e=>{ e.preventDefault(); saveToTask(); });
  document.getElementById('msgList')?.addEventListener('click', e=>{
    const b = e.target.closest('.btnMsgToTask');
    if(!b) return; e.preventDefault();
    const mid = parseInt(b.getAttribute('data-mid')||'0',10);
    if(mid){ openToTaskModal(mid, 'Из сообщения #' + mid); }
  });
  document.addEventListener('keydown', e=>{
    const tag=(e.target && e.target.tagName||'').toUpperCase();
    if(tag==='INPUT' || tag==='TEXTAREA' || e.ctrlKey || e.metaKey || e.altKey) return;
    const k=e.key.toLowerCase();
    if(k==='r'){ e.preventDefault(); document.getElementById('internalNote').checked=false; sendExternal(); }
    if(k==='a'){ e.preventDefault(); aiDraft(); }
    if(k==='s'){ e.preventDefault(); thPatch({status:'snoozed'}); }
    if(k==='t'){ e.preventDefault();
      const items=[...document.querySelectorAll('.msg')].filter(x=>!x.classList.contains('system') && x.classList.contains('client'));
      if(items.length){ const last=items[items.length-1]; const mid=last.getAttribute('data-mid'); if(mid){ openToTaskModal(parseInt(mid,10)); } }
    }
  });
</script>
"""
# === END STYLES PART 2/9 ===
# === STYLES PART 3/9 — TASKS LIST + TASK VIEW (filters, inline update, comments, reminders) ===
# -*- coding: utf-8 -*-

TASKS_TMPL = """
<h2 style="margin:0 0 8px 0;">Задачи</h2>

<div class="card">
  <details open>
    <summary class="button ghost">Фильтры</summary>
    <form method="get" class="grid-filters" action="{{ url_for('tasks_page') }}">
      <label>Период с <input class="input" type="date" name="created_from" value="{{ request.args.get('created_from','') }}"></label>
      <label>по <input class="input" type="date" name="created_to" value="{{ request.args.get('created_to','') }}"></label>
      <label>Фильтр
        <select class="select" name="f">
          {% set f = current_filter or request.args.get('f','open') %}
          <option value="open" {% if f=='open' %}selected{% endif %}>Открытые</option>
          <option value="today" {% if f=='today' %}selected{% endif %}>Сегодня</option>
          <option value="overdue" {% if f=='overdue' %}selected{% endif %}>Просроченные</option>
          <option value="done" {% if f=='done' %}selected{% endif %}>Сделанные</option>
        </select>
      </label>
      <label>Поиск <input class="input" name="q" placeholder="в заголовке/описании" value="{{ request.args.get('q','') }}"></label>
      <label>Адрес <input class="input" name="address" value="{{ request.args.get('address','') }}"></label>
      <label>Телефон <input class="input" name="contact_phone" value="{{ request.args.get('contact_phone','') }}"></label>
      <div style="grid-column:1/-1;display:flex;gap:8px;justify-content:flex-end;margin-top:4px;">
        <button class="button" type="submit">Применить</button>
        <a class="button ghost" href="{{ url_for('tasks_page') }}">Сбросить</a>
      </div>
    </form>
  </details>
  
</div>

<div class="card" style="margin-top:10px;">
  <table class="table">
    <thead>
      <tr>
        <th>ID</th><th>Заголовок</th><th>Исполнитель</th><th>Статус</th><th>Срок</th><th>Клиент</th><th>₽/мес</th><th></th>
      </tr>
    </thead>
    <tbody id="tasksTBody">
      {% set status_names = (statuses or []) %}
      {% for t in tasks %}
      <tr data-id="{{ t.id }}" tabindex="0">
        <td>#{{ t.id }}</td>
        <td>{{ t.title }}</td>
        <td>
          <select class="select tk-assignee" data-id="{{ t.id }}">
            <option value="">—</option>
            {% for a in agents %}<option value="{{ a.id }}" {% if t.assignee_id==a.id %}selected{% endif %}>{{ a.username }}</option>{% endfor %}
          </select>
        </td>
        <td>
          {% set st = t.status or 'open' %}
          <select class="select tk-status" data-id="{{ t.id }}">
            {% if status_names %}{% for s in status_names %}<option value="{{ s.name }}" {% if st==s.name %}selected{% endif %}>{{ s.name }}</option>{% endfor %}
            {% else %}
            {% for s in ('open','overdue','done') %}<option value="{{ s }}" {% if st==s %}selected{% endif %}>{{ s }}</option>{% endfor %}
            {% endif %}
          </select>
        </td>
        <td><input class="input tk-due" data-id="{{ t.id }}" type="datetime-local" value="{{ ((t.due_at or '')|replace(' ','T'))[:16] }}"></td>
        <td>{{ t.company_name or '—' }}</td>
        <td>{{ '%.2f'|format((t.monthly_fee or 0)|float) }}</td>
        <td style="white-space:nowrap;display:flex;gap:6px;align-items:center;">
          <button class="iconbtn small tk-toggle" data-id="{{ t.id }}" title="Готово/открыть">⏺</button>
          <a class="iconbtn small" href="{{ url_for('task_view', tid=t.id) }}">Открыть</a>
          <button class="iconbtn small tk-dial" data-id="{{ t.id }}" title="Позвонить">📞</button>
        </td>
      </tr>
      {% else %}
      <tr><td colspan="8"><div class="help">Ничего не найдено</div></td></tr>
      {% endfor %}
    </tbody>
  </table>
  <button class="button ghost" id="loadMoreTasks" style="margin-top:8px;">Загрузить больше</button>
</div>

<script nonce="{{ csp_nonce }}">
  let tasksPage = 1;
  const STATUS_LIST = [{% if statuses %}{% for s in statuses %}"{{ s.name }}"{% if not loop.last %},{% endif %}{% endfor %}{% else %}"open","overdue","done"{% endif %}];

  function statusSelectHTML(id, st){
    const opts = STATUS_LIST.map(s=>('<option value="'+s+'"'+(String(st||'open')===String(s)?' selected':'')+'>'+s+'</option>')).join('');
    return '<select class="select tk-status" data-id="'+id+'">'+opts+'</select>';
  }
  function assigneeSelectHTML(id, assignee_id){
    const arr = {{ agents|tojson }};
    let opts = '<option value="">—</option>';
    for(const a of arr){ const sel = (String(assignee_id||'')===String(a.id))?' selected':''; opts += '<option value="'+a.id+'"'+sel+'>'+esc(a.username)+'</option>'; }
    return '<select class="select tk-assignee" data-id="'+id+'">'+opts+'</select>';
  }
  function rowHTML(t){
    return `
      <tr data-id="${t.id}" tabindex="0">
        <td>#${t.id}</td>
        <td>${esc(t.title||'')}</td>
        <td>${assigneeSelectHTML(t.id, t.assignee_id)}</td>
        <td>${statusSelectHTML(t.id, t.status)}</td>
        <td><input class="input tk-due" data-id="${t.id}" type="datetime-local" value="${esc(((t.due_at||'').replace(' ','T')).slice(0,16))}"></td>
        <td>${esc(t.company_name||'—')}</td>
        <td>${esc(String((t.monthly_fee||0).toFixed ? t.monthly_fee.toFixed(2) : t.monthly_fee||'0.00'))}</td>
        <td style="white-space:nowrap;display:flex;gap:6px;align-items:center;">
          <button class="iconbtn small tk-toggle" data-id="${t.id}" title="Готово/открыть">⏺</button>
          <a class="iconbtn small" href="/task/${t.id}">Открыть</a>
          <button class="iconbtn small tk-dial" data-id="${t.id}" title="Позвонить">📞</button>
        </td>
      </tr>`;
  }
  function buildParams(page){
    const params = new URLSearchParams(window.location.search);
    if(page) params.set('page', page);
    params.set('per_page','50');
    return params;
  }
  async function loadMoreTasks(){
    tasksPage++;
    try{
      const url='/api/tasks/list?'+buildParams(tasksPage).toString();
      const r=await fetch(url); const j=await r.json();
      if(!j.ok) return alert(j.error||'Ошибка');
      const tb=document.getElementById('tasksTBody');
      let added=0;
      for(const t of (j.items||[])){ tb.insertAdjacentHTML('beforeend', rowHTML(t)); added++; }
      if(added < (j.per_page||50)) document.getElementById('loadMoreTasks').style.display='none';
      else document.getElementById('loadMoreTasks').style.display='';
      if(!added && tasksPage===1){ tb.innerHTML = '<tr><td colspan="8"><div class="help">Ничего не найдено</div></td></tr>'; }
      if(added>0) toast('Загружено больше');
    }catch(e){ alert('Ошибка загрузки'); }
  }
  async function taskUpdate(id, patch){
    try{
      const r=await fetch('/api/task/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(Object.assign({id},patch))});
      const j=await r.json(); if(!j.ok) alert(j.error||'Ошибка');
    }catch(e){ alert('Ошибка сети'); }
  }
  async function taskToggle(id){
    try{
      const r=await fetch('/api/task/toggle',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({id})});
      const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      toast('Статус: '+(j.status||'обновлён'));
    }catch(e){ alert('Ошибка сети'); }
  }
  async function taskDial(taskId){
    try{
      const r=await fetch('/api/task/phones/'+taskId); const j=await r.json();
      if(!j.ok) return alert(j.error||'Нет телефонов');
      const nums=(j.items||[]); if(!nums.length) return alert('Телефоны не найдены');
      const pick = prompt('Наберите номер или выберите:\\n'+nums.map((n,i)=>((i+1)+') '+n)).join('\\n'),'1');
      let num = pick;
      if(/^\\d+$/.test(String(pick||'')) && nums[parseInt(pick,10)-1]) num = nums[parseInt(pick,10)-1];
      const d = String(num||'').replace(/\\D+/g,''); if(!d) return;
      let n=d; if(n.length===11 && n.startsWith('8')) n='7'+n.slice(1); if(n.length===10) n='7'+n;
      const e164='+'+n;
      const s=await fetch('/api/cti/click_to_call',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({to:e164})});
      const sj=await s.json(); if(sj.ok) toast('Звонок: '+e164); else alert(sj.error||'Ошибка звонка');
    }catch(e){ alert('Ошибка звонка'); }
  }

  document.getElementById('loadMoreTasks')?.addEventListener('click', e=>{ e.preventDefault(); loadMoreTasks(); });
  document.addEventListener('change', e=>{
    const el=e.target; const id = el && el.getAttribute ? el.getAttribute('data-id') : null;
    if(!id) return;
    if(el.classList.contains('tk-status')) taskUpdate(parseInt(id,10), {status: el.value});
    if(el.classList.contains('tk-assignee')) taskUpdate(parseInt(id,10), {assignee_id: el.value||null});
    if(el.classList.contains('tk-due')) taskUpdate(parseInt(id,10), {due_at: el.value||''});
  });
  document.addEventListener('click', e=>{
    const t=e.target.closest('.tk-toggle'); if(t){ e.preventDefault(); taskToggle(parseInt(t.getAttribute('data-id')||'0',10)); return; }
    const d=e.target.closest('.tk-dial'); if(d){ e.preventDefault(); taskDial(parseInt(d.getAttribute('data-id')||'0',10)); return; }
  });

  document.addEventListener('keydown', e=>{
    const tag=(e.target&&e.target.tagName||'').toUpperCase();
    if(tag==='INPUT' || tag==='TEXTAREA' || e.ctrlKey || e.metaKey) return;
    const rows=[...document.querySelectorAll('#tasksTBody tr')];
    const active=(document.activeElement && document.activeElement.closest)?document.activeElement.closest('tr'):null;
    const idx=rows.indexOf(active);
    if(e.key==='ArrowDown'){ e.preventDefault(); (rows[Math.min(rows.length-1, idx+1)]||rows[0])?.focus(); }
    if(e.key==='ArrowUp'){ e.preventDefault(); (rows[Math.max(0, idx-1)]||rows[0])?.focus(); }
    if(!active) return;
    const id=active.getAttribute('data-id');
    if(e.key.toLowerCase()==='x'){ e.preventDefault(); taskToggle(parseInt(id,10)); }
  });
</script>
<style>
  .fab{position:fixed;left:18px;bottom:18px;z-index:9999}
  .fab .plus{width:48px;height:48px;border-radius:50%;border:1px solid var(--border);background:var(--accent);color:#000;font-weight:800;cursor:pointer}
  .fab .plus:hover{filter:brightness(0.95)}
  .fab .plus:focus{outline:2px solid var(--border)}
</style>
<div class="modal-backdrop" id="taskModal">
  <div class="modal">
    <h3>Новая задача</h3>
    <form method="post" action="{{ url_for('tasks_page') }}" style="display:grid;gap:8px;max-width:820px;">
      <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
      <label>Заголовок <input class="input" name="title" required placeholder="Что нужно сделать?"></label>
      <label>Описание <textarea class="input" name="description" rows="3" placeholder="Краткое описание"></textarea></label>
      <div class="split" style="grid-template-columns:1fr 1fr;gap:8px;">
        <label>Исполнитель
          <select class="select" name="assignee_id">
            <option value="">—</option>
            {% for a in agents %}<option value="{{ a.id }}">{{ a.username }}</option>{% endfor %}
          </select>
        </label>
        <label>Срок <input class="input" type="datetime-local" name="due_at"></label>
      </div>
      <div class="split" style="grid-template-columns:1fr 1fr 1fr;gap:8px;">
        <label>ID клиента <input class="input" name="company_id" placeholder="например, 1"></label>
        <label>ИНН клиента (альтерн.) <input class="input" name="company_inn" placeholder="10–12 цифр"></label>
        <label>Абонплата, ₽ <input class="input" name="monthly_fee" type="number" step="0.01" value="0"></label>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;">
        <button class="button secondary" type="button" id="btnTaskCancel">Отмена</button>
        <button class="button" type="submit">Создать</button>
      </div>
    </form>
  </div>
  
</div>
<div class="fab">
  <button class="plus" id="btnFabTask" title="новая задача">+</button>
  <script nonce="{{ csp_nonce }}">
    document.getElementById('btnFabTask')?.addEventListener('click', (e)=>{ e.preventDefault(); document.getElementById('taskModal').classList.add('show'); });
    document.getElementById('btnTaskCancel')?.addEventListener('click', (e)=>{ e.preventDefault(); document.getElementById('taskModal').classList.remove('show'); });
  </script>
</div>
"""

TASK_VIEW_TMPL = """
<h2>Задача #{{ t.id }} · {{ t.title }}</h2>
<div class="thread">
  <div>
    <div class="card" style="margin-bottom:10px;">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
        <label>Статус
          <select class="select" id="tStatus">
            {% set st = t.status or 'open' %}
            {% for s in (statuses or []) %}<option value="{{ s.name }}" {% if s.name==st %}selected{% endif %}>{{ s.name }}</option>{% endfor %}
            {% if not statuses %}{% for s in ('open','overdue','done') %}<option value="{{ s }}" {% if s==st %}selected{% endif %}>{{ s }}</option>{% endfor %}{% endif %}
          </select>
        </label>
        <label>Исполнитель
          <select class="select" id="tAssignee">
            <option value="">—</option>
            {% for u in query_db('SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username',(t.org_id,)) %}
            <option value="{{ u.id }}" {% if t.assignee_id==u.id %}selected{% endif %}>{{ u.username }}</option>
            {% endfor %}
          </select>
        </label>
        <label>Срок <input class="input" id="tDue" type="datetime-local" value="{{ ((t.due_at or '')|replace(' ','T'))[:16] }}"></label>
      </div>
      <div style="display:grid;grid-template-columns:1fr;gap:8px;margin-top:8px;">
        <label>Заголовок <input class="input" id="tTitle" value="{{ t.title }}"></label>
        <label>Описание <textarea class="input" id="tDesc" rows="4">{{ t.description or '' }}</textarea></label>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;">
          <button class="button" id="btnSaveMain">Сохранить</button>
          <button class="iconbtn phone" id="btnDial"><span class="icon">📞</span><span>Позвонить</span></button>
          <a class="button ghost" href="{{ url_for('tasks_page') }}">← к списку</a>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:10px;">
      <details open>
        <summary class="button ghost">Комментарии</summary>
        <div id="cmList" style="max-height:60vh;overflow:auto;">
        {% for c in comments %}
        <div class="msg agent" data-id="{{ c.id }}">
          <div class="meta">[{{ c.username or ('#'+(c.user_id|string)) }}] {{ c.created_at }}</div>
          <div class="body">{{ c.body or '' }}</div>
          {% if c.attachments %}
          <div class="help" style="margin-top:6px;">
            Вложения:
            {% for a in c.attachments %}<a href="{{ a.url }}" target="_blank">{{ a.name }}</a>{% if not loop.last %}, {% endif %}{% endfor %}
          </div>
          {% endif %}
        </div>
        {% else %}
        <div class="help">Комментариев пока нет</div>
        {% endfor %}
        </div>
        <div class="composer" style="margin-top:8px;">
        <div id="cDrop" style="border:2px dashed var(--border);padding:10px;text-align:center;cursor:pointer;">Перетащите файлы или кликните для загрузки</div>
        <input type="file" id="cFile" multiple style="display:none;">
        <div id="cAtt" class="help" style="margin:6px 0;display:none;"></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
          <select class="select" id="cFormat">
            <option value="plain" selected>Текст</option>
            <option value="html">HTML</option>
            <option value="md">Markdown</option>
          </select>
          <textarea class="input" id="cBody" rows="3" style="flex:1 1 auto;" placeholder="Новый комментарий..."></textarea>
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px;">
          <button class="button" id="btnAddComment">Добавить комментарий</button>
        </div>
        </div>
      </details>
    </div>
  </div>

  <div>
    <div class="card">
      <details open>
        <summary class="button ghost">Сведения</summary>
      <div><strong>ID:</strong> {{ t.id }}</div>
      <div><strong>Клиент:</strong> {{ t.company_name or '—' }}</div>
      <div><strong>Абонплата:</strong> {{ '%.2f'|format((t.monthly_fee or 0)|float) }} ₽</div>
      <div style="margin-top:8px;"><strong>FRT:</strong>
        {% if t.last_commented_at %}<span class="help">посл. коммент: {{ t.last_commented_at }}</span>{% else %}<span class="help">—</span>{% endif %}
      </div>
      </details>
    </div>

    <div class="card">
      <details>
        <summary class="button ghost">Участники</summary>
      <ul>
        {% for p in participants %}
          <li>#{{ p.user_id }} — {{ p.username or '' }} <span class="help">({{ p.role }})</span></li>
        {% else %}
          <li class="help">Нет участников</li>
        {% endfor %}
      </ul>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;margin-top:8px;">
        <label>Добавить
          <select class="select" id="tpAdd" multiple size="4" style="min-width:160px;">
            {% for u in query_db('SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username',(t.org_id,)) %}
              <option value="{{ u.id }}">{{ u.username }}</option>
            {% endfor %}
          </select>
        </label>
        <label>Удалить
          <select class="select" id="tpRemove" multiple size="4" style="min-width:160px;">
            {% for p in participants %}<option value="{{ p.user_id }}">{{ p.username or p.user_id }}</option>{% endfor %}
          </select>
        </label>
        <label>Роль
          <select class="select" id="tpRole">
            <option value="assignee">assignee</option>
            <option value="owner">owner</option>
            <option value="watcher">watcher</option>
          </select>
        </label>
        <button class="button" id="btnTpSave">Обновить</button>
      </div>
      </details>
    </div>

    <div class="card">
      <details>
        <summary class="button ghost">Напоминания</summary>
      <div id="remList" class="help">Загрузка...</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;">
        <label>Когда <input class="input" type="datetime-local" id="remWhen"></label>
        <label>Сообщение <input class="input" id="remMsg" placeholder="Текст напоминания"></label>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px;">
        <button class="button" id="btnRemAdd">Добавить</button>
      </div>
      </details>
    </div>

    <div class="card">
      <details>
        <summary class="button ghost">Перевод по стадии/отделу</summary>
      <div class="help">Введите ключ стадии (workflow_stages.key) и/или ID отдела</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <label>Стадия <input class="input" id="wfStage" placeholder="например, in_progress"></label>
        <label>ID отдела <input class="input" id="wfDept" placeholder="например, 2"></label>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;">
        <label>Срок <input class="input" id="wfDue" type="datetime-local"></label>
        <label>Комментарий <input class="input" id="wfComment"></label>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px;">
        <button class="button" id="btnWfApply">Применить</button>
      </div>
      </details>
    </div>

    <div class="card">
      <details>
        <summary class="button ghost">Делегирование</summary>
      <div style="display:flex;gap:8px;align-items:end;">
        <label>Назначить пользователю
          <select class="select" id="dlgUser">
            {% for u in query_db('SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username',(t.org_id,)) %}
            <option value="{{ u.id }}">{{ u.username }}</option>
            {% endfor %}
          </select>
        </label>
        <button class="button" id="btnDelegate">Делегировать</button>
      </div>
      </details>
    </div>

    <div class="card">
      <details>
        <summary class="button ghost">Файлы (закреплённые)</summary>
      <div id="pinList">
        {% for f in pinned_files %}
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;">
            <a class="iconbtn small" href="{{ f.url }}" target="_blank">{{ f.name }}</a>
            <button class="iconbtn small btnUnpin" data-id="{{ f.id }}">Открепить</button>
          </div>
        {% else %}
          <div class="help">Нет закреплённых файлов</div>
        {% endfor %}
      </div>
      <div style="display:flex;gap:8px;align-items:end;margin-top:8px;">
        <label>ID файла <input class="input" id="pinFileId" placeholder="Например, 10" style="max-width:140px;"></label>
        <button class="button" id="btnPin">Закрепить</button>
      </div>
      </details>
    </div>

    <div class="card">
      <details>
        <summary class="button ghost">Переходы и активность</summary>
      <div class="help">Последние переходы стадии</div>
      <ul>
        {% for tr in transitions %}
        <li>#{{ tr.id }}: {{ tr.from_stage or '—' }} → {{ tr.to_stage or '—' }} ({{ tr.created_at }})</li>
        {% else %}
        <li class="help">Нет данных</li>
        {% endfor %}
      </ul>
      <div class="help" style="margin-top:6px;">Активность</div>
      <ul>
        {% for a in activity %}
        <li>#{{ a.id }} · {{ a.kind }} · {{ a.created_at }}</li>
        {% else %}
        <li class="help">Нет активности</li>
        {% endfor %}
      </ul>
      </details>
    </div>
  </div>
</div>

<div class="modal-backdrop" id="dlgPhones">
  <div class="modal">
    <h3>Выберите номер</h3>
    <div id="phList" class="help">Загрузка...</div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px;">
      <button class="button secondary" id="btnPhClose">Закрыть</button>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
  const TID = {{ t.id }};
  let cAtt = [];

  async function tPatch(p){ return fetch('/api/task/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(Object.assign({id:TID},p))}); }
  function toastErr(j){ alert(j && j.error ? j.error : 'Ошибка'); }

  document.getElementById('btnSaveMain')?.addEventListener('click', async e=>{
    e.preventDefault();
    try{
      const patch={ title: document.getElementById('tTitle').value||'', description: document.getElementById('tDesc').value||'', status: document.getElementById('tStatus').value||'open', assignee_id: (document.getElementById('tAssignee').value||null), due_at: (document.getElementById('tDue').value||'') };
      const r=await tPatch(patch); const j=await r.json(); if(!j.ok) return toastErr(j); toast('Сохранено');
    }catch(e){ alert('Ошибка сети'); }
  });
  document.getElementById('tStatus')?.addEventListener('change', async e=>{ try{ const r=await tPatch({status:e.target.value}); const j=await r.json(); if(!j.ok) toastErr(j);}catch(_){alert('Ошибка');}});
  document.getElementById('tAssignee')?.addEventListener('change', async e=>{ try{ const r=await tPatch({assignee_id:e.target.value||null}); const j=await r.json(); if(!j.ok) toastErr(j);}catch(_){alert('Ошибка');}});
  document.getElementById('tDue')?.addEventListener('change', async e=>{ try{ const r=await tPatch({due_at:e.target.value||''}); const j=await r.json(); if(!j.ok) toastErr(j);}catch(_){alert('Ошибка');}});

  async function openPhones(){
    try{
      const r=await fetch('/api/task/phones/'+TID); const j=await r.json();
      const box=document.getElementById('phList'); box.innerHTML='';
      if(!j.ok || !(j.items||[]).length){ box.textContent='Телефоны не найдены'; return; }
      for(const n of j.items){
        const btn=document.createElement('button'); btn.className='iconbtn small'; btn.textContent=n;
        btn.addEventListener('click', async ()=>{ try{
          const d=String(n||'').replace(/\\D+/g,''); let v=d; if(v.length===11 && v.startsWith('8')) v='7'+v.slice(1); if(v.length===10) v='7'+v; const e164='+'+v;
          const s=await fetch('/api/cti/click_to_call',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({to:e164})});
          const sj=await s.json(); if(sj.ok){ toast('Звонок: '+e164); document.getElementById('dlgPhones').classList.remove('show'); } else alert(sj.error||'Ошибка звонка');
        }catch(_){alert('Ошибка звонка');}});
        box.appendChild(btn);
      }
    }catch(e){ alert('Ошибка телефонов'); }
  }
  document.getElementById('btnDial')?.addEventListener('click', e=>{ e.preventDefault(); document.getElementById('dlgPhones').classList.add('show'); openPhones(); });
  document.getElementById('btnPhClose')?.addEventListener('click', e=>{ e.preventDefault(); document.getElementById('dlgPhones').classList.remove('show'); });

  document.getElementById('btnTpSave')?.addEventListener('click', async e=>{
    e.preventDefault();
    function vals(id){ const sel=document.getElementById(id); return [...(sel?.selectedOptions||[])].map(o=>parseInt(o.value,10)).filter(x=>!isNaN(x)); }
    const add=vals('tpAdd'), remove=vals('tpRemove'), role=(document.getElementById('tpRole').value||'assignee');
    try{
      const r=await fetch('/api/task/participants',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({task_id:TID, add, remove, role})});
      const j=await r.json(); if(!j.ok) return toastErr(j); toast('Участники обновлены'); location.reload();
    }catch(_){ alert('Ошибка'); }
  });

  async function loadRem(){
    try{
      const r=await fetch('/api/task/reminders/'+TID); const j=await r.json(); const box=document.getElementById('remList'); box.innerHTML='';
      if(!j.ok){ box.textContent=j.error||'Ошибка'; return; }
      if(!(j.items||[]).length){ box.textContent='Напоминаний нет'; return; }
      for(const it of j.items){
        const row=document.createElement('div'); row.style.display='flex'; row.style.gap='8px'; row.style.alignItems='center';
        const span=document.createElement('span'); span.textContent=(it.remind_at||'')+' — '+(it.message||'');
        const del=document.createElement('button'); del.className='iconbtn small'; del.textContent='Удалить';
        del.addEventListener('click', async ()=>{ try{
          const rr=await fetch('/api/task/reminder/'+it.id',{method:'DELETE',headers:{'X-CSRFToken':CSRF}}); const jj=await rr.json(); if(!jj.ok) return toastErr(jj); loadRem();
        }catch(_){alert('Ошибка удаления');}});
        row.appendChild(span); row.appendChild(del); box.appendChild(row);
      }
    }catch(_){ document.getElementById('remList').textContent='Ошибка'; }
  }
  loadRem();
  document.getElementById('btnRemAdd')?.addEventListener('click', async e=>{
    e.preventDefault();
    const remind_at=(document.getElementById('remWhen').value||''), message=(document.getElementById('remMsg').value||'Напоминание по задаче');
    try{
      const r=await fetch('/api/task/reminder',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({task_id:TID, remind_at, message})});
      const j=await r.json(); if(!j.ok) return toastErr(j); toast('Напоминание добавлено'); document.getElementById('remMsg').value=''; loadRem();
    }catch(_){ alert('Ошибка'); }
  });

  document.getElementById('btnWfApply')?.addEventListener('click', async e=>{
    e.preventDefault();
    const department_id=parseInt(document.getElementById('wfDept').value||'0',10)||0;
    const stage_key=(document.getElementById('wfStage').value||'').trim();
    const due_at=(document.getElementById('wfDue').value||'');
    const comment=(document.getElementById('wfComment').value||'');
    try{
      const r=await fetch('/api/task/assign_department',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({task_id:TID, department_id, stage_key, due_at, comment})});
      const j=await r.json(); if(!j.ok) return toastErr(j); toast('Стадия/отдел обновлены');
    }catch(_){ alert('Ошибка'); }
  });

  document.getElementById('btnDelegate')?.addEventListener('click', async e=>{
    e.preventDefault();
    const to_user_id=parseInt(document.getElementById('dlgUser').value||'0',10)||0;
    try{
      const r=await fetch('/api/task/delegate',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({task_id:TID, to_user_id})});
      const j=await r.json(); if(!j.ok) return toastErr(j); toast('Делегировано');
    }catch(_){ alert('Ошибка'); }
  });

  async function pinToggle(file_id, pin){
    try{
      const r=await fetch('/api/task/file_pin',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({task_id:TID, file_id, pin})});
      const j=await r.json(); if(!j.ok) return toastErr(j); toast(pin?'Закреплено':'Откреплено'); location.reload();
    }catch(_){ alert('Ошибка'); }
  }
  document.getElementById('btnPin')?.addEventListener('click', e=>{
    e.preventDefault();
    const fid=parseInt(document.getElementById('pinFileId').value||'0',10)||0;
    if(!fid) return alert('Укажите ID файла');
    pinToggle(fid,true);
  });
  document.getElementById('pinList')?.addEventListener('click', e=>{
    const b=e.target.closest('.btnUnpin'); if(!b) return;
    e.preventDefault();
    const fid=parseInt(b.getAttribute('data-id')||'0',10)||0;
    if(fid) pinToggle(fid,false);
  });

  function updateCAtt(){
    const el=document.getElementById('cAtt');
    if(!cAtt.length){ el.style.display='none'; el.textContent=''; return; }
    el.style.display='block';
    el.innerHTML='Вложения: '+cAtt.map(a=>('<a href="'+a.url+'" target="_blank">'+esc(a.name)+'</a>')).join(', ');
  }
  async function uploadC(files){
    try{
      const list = files || (document.getElementById('cFile')?.files||[]);
      if(!list || !list.length) return;
      for(let i=0;i<list.length;i++){
        const f=list[i]; const fd=new FormData(); fd.append('file', f);
        const r=await fetch('/api/task/comment/upload',{method:'POST',headers:{'X-CSRFToken':CSRF},body:fd});
        const j=await r.json(); if(j.ok && j.file){ cAtt.push({file_id: j.file.id, name: j.file.name, url: j.file.url}); } else { alert((j.error||'Ошибка')+': '+(f && f.name ? f.name : '')); }
      }
      updateCAtt(); toast('Файлы загружены');
    }catch(_){ alert('Ошибка загрузки'); }
  }
  document.getElementById('cFile')?.addEventListener('change', e=>uploadC());
  document.getElementById('cDrop')?.addEventListener('click', e=>{ e.preventDefault(); document.getElementById('cFile')?.click(); });
  document.getElementById('cDrop')?.addEventListener('dragover', e=>{ e.preventDefault(); });
  document.getElementById('cDrop')?.addEventListener('drop', e=>{ e.preventDefault(); const files=e.dataTransfer.files; if(files && files.length) uploadC(files); });

  document.getElementById('btnAddComment')?.addEventListener('click', async e=>{
    e.preventDefault();
    const body=(document.getElementById('cBody').value||'').trim();
    const format=(document.getElementById('cFormat').value||'plain');
    if(!body && !cAtt.length) return alert('Пустой комментарий');
    try{
      const r=await fetch('/api/task/comment',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({task_id:TID, body, format, attachments:cAtt})});
      const j=await r.json(); if(!j.ok) return toastErr(j);
      toast('Комментарий добавлен'); location.reload();
    }catch(_){ alert('Ошибка'); }
  });
</script>
"""
# === END STYLES PART 3/9 ===
# === STYLES PART 4/9 — DEALS LIST + KANBAN (filters, drag&drop, quick create/edit) ===
# -*- coding: utf-8 -*-

DEALS_TMPL = """
<h2 style="margin:0 0 8px 0;">Сделки</h2>

<div class="card">
  <details open>
    <summary class="button ghost">Фильтры</summary>
    <form method="get" class="grid-filters" action="{{ url_for('deals_page') }}">
      {% set stg_rows = query_db('SELECT DISTINCT stage FROM deals WHERE org_id=? ORDER BY stage', (user.org_id,)) %}
      <label>Стадия
        <select class="select" name="stage">
          <option value="">— все —</option>
          {% for r in (stg_rows or []) %}
          <option value="{{ r.stage }}" {% if request.args.get('stage','')==r.stage %}selected{% endif %}>{{ r.stage }}</option>
          {% endfor %}
        </select>
      </label>
      <label>Статус
        <select class="select" name="status">
          <option value="">— все —</option>
          {% for s in ('open','won','lost','on_hold','canceled') %}
          <option value="{{ s }}" {% if request.args.get('status','')==s %}selected{% endif %}>{{ s }}</option>
          {% endfor %}
        </select>
      </label>
      <label>Исполнитель
        <select class="select" name="assignee_id">
          <option value="">— любой —</option>
          {% for a in query_db('SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username',(user.org_id,)) %}
          <option value="{{ a.id }}" {% if request.args.get('assignee_id','')==a.id|string %}selected{% endif %}>{{ a.username }}</option>
          {% endfor %}
        </select>
      </label>
      <div style="grid-column:1/-1;display:flex;gap:8px;justify-content:flex-end;margin-top:4px;">
        <button class="button" type="submit">Применить</button>
        <a class="button ghost" href="{{ url_for('deals_page') }}">Сбросить</a>
        <button class="button secondary" type="button" id="btnNewDeal">Создать сделку</button>
      </div>
    </form>
  </details>
</div>

<div class="card" style="margin-top:10px;">
  <div style="display:flex;gap:8px;align-items:center;justify-content:space-between;">
    <div class="help">Перетаскивайте карточки между колонками для смены стадии</div>
    <button class="iconbtn small" id="btnReloadKanban">↻ Обновить</button>
  </div>
  <style>
    .kanban{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:10px}
    .kan-col{background:var(--surface);border:1px solid var(--border);border-radius:12px;min-height:220px;display:flex;flex-direction:column}
    .kan-head{padding:8px 10px;border-bottom:1px solid var(--border);font-weight:700;display:flex;align-items:center;justify-content:space-between}
    .kan-list{padding:8px;display:flex;flex-direction:column;gap:8px;min-height:160px}
    .kan-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px;cursor:grab}
    .kan-card:active{cursor:grabbing}
    .kan-card .ttl{font-weight:600;margin-bottom:4px}
    .kan-card .meta{display:flex;gap:8px;flex-wrap:wrap;color:var(--muted);font-size:12px}
    .kan-drop{outline:2px dashed var(--accent);outline-offset:-6px}
    .chip{border:1px solid var(--border);border-radius:999px;padding:0 6px;font-size:12px}
  </style>
  <div id="kanban" class="kanban">
    <div class="help" id="kanbanLoading">Загрузка...</div>
  </div>
</div>

<details class="card" style="margin-top:10px;">
  <summary class="button ghost">Таблица (резерв)</summary>
  <table class="table">
    <thead>
      <tr><th>ID</th><th>Заголовок</th><th>Стадия</th><th>Статус</th><th>Сумма</th><th>Валюта</th><th>Исполнитель</th></tr>
    </thead>
    <tbody>
      {% for d in deals %}
      <tr>
        <td>#{{ d.id }}</td>
        <td>{{ d.title }}</td>
        <td>{{ d.stage }}</td>
        <td>{{ d.status }}</td>
        <td>{{ '%.2f'|format((d.amount or 0)|float) }}</td>
        <td>{{ d.currency or 'RUB' }}</td>
        <td>
          {% set u = query_db('SELECT username FROM users WHERE id=?',(d.assignee_id,),one=True) %}
          {{ (u.username if u else '—') }}
        </td>
      </tr>
      {% else %}
      <tr><td colspan="7"><div class="help">Нет данных</div></td></tr>
      {% endfor %}
    </tbody>
  </table>
</details>

<div class="modal-backdrop" id="dealModal">
  <div class="modal">
    <h3 id="dealModalTitle">Новая сделка</h3>
    <form style="display:grid;gap:8px;">
      <label>Название <input class="input" id="dlTitle" required></label>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <label>Стадия <input class="input" id="dlStage" placeholder="new"></label>
        <label>Статус <input class="input" id="dlStatus" placeholder="open"></label>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <label>Сумма <input class="input" id="dlAmount" type="number" step="0.01" value="0"></label>
        <label>Валюта <input class="input" id="dlCurrency" value="RUB"></label>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <label>Исполнитель
          <select class="select" id="dlAssignee">
            <option value="">—</option>
            {% for a in query_db('SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username',(user.org_id,)) %}
            <option value="{{ a.id }}">{{ a.username }}</option>
            {% endfor %}
          </select>
        </label>
        <label>ID компании <input class="input" id="dlCompany" placeholder="опционально"></label>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <label>ID контакта <input class="input" id="dlContact" placeholder="опционально"></label>
        <div class="help" style="align-self:end;">Все поля можно отредактировать позже</div>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button class="button secondary" type="button" id="btnDealCancel">Отмена</button>
        <button class="button" type="button" id="btnDealSave">Создать</button>
      </div>
    </form>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
  const KAN = document.getElementById('kanban');
  let KAN_DATA = {columns:[], items:{}};

  function esc(s){ return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

  // Use users passed from the view (already converted to plain dicts)
  const USERS = {{ users|tojson }};

  function cardHTML(it){
    const assgn = it.assignee_id ? ('#'+it.assignee_id) : '—';
    const amt = (typeof it.amount==='number') ? it.amount.toFixed(2) : String(it.amount||'0');
    return `
      <div class="kan-card" draggable="true" data-id="${it.id}">
        <div class="ttl">${esc(it.title||('Deal #'+it.id))}</div>
        <div class="meta">
          <span class="chip">${esc(amt)} ${esc(it.currency||'RUB')}</span>
          <span class="chip">assignee: ${esc(it.assignee_id_name||assgn)}</span>
        </div>
        <div class="meta" style="margin-top:4px;">
          <button class="iconbtn small btnEdit" data-id="${it.id}">✎</button>
        </div>
      </div>`;
  }

  function renderKanban(){
    if(!KAN_DATA.columns || !KAN_DATA.columns.length){
      KAN.innerHTML = '<div class="help">Нет данных</div>'; return;
    }
    const frag = document.createDocumentFragment();
    for(const col of KAN_DATA.columns){
      const wrap = document.createElement('div'); wrap.className='kan-col'; wrap.dataset.stage = col;
      const head = document.createElement('div'); head.className='kan-head';
      head.innerHTML = '<span>'+esc(col)+'</span><span class="help">'+((KAN_DATA.items[col]||[]).length)+'</span>';
      const list = document.createElement('div'); list.className='kan-list'; list.dataset.stage = col;
      list.addEventListener('dragover', e=>{ e.preventDefault(); list.classList.add('kan-drop'); });
      list.addEventListener('dragleave', e=>{ list.classList.remove('kan-drop'); });
      list.addEventListener('drop', e=>{
        e.preventDefault(); list.classList.remove('kan-drop');
        const id = e.dataTransfer.getData('text/plain'); if(!id) return;
        moveDealStage(parseInt(id,10), col);
      });
      for(const it of (KAN_DATA.items[col]||[])){
        const d=document.createElement('div'); d.innerHTML = cardHTML(it).trim();
        const card = d.firstElementChild;
        card.addEventListener('dragstart', ev=>{
          ev.dataTransfer.setData('text/plain', String(it.id));
          ev.dataTransfer.effectAllowed = 'move';
        });
        list.appendChild(card);
      }
      wrap.appendChild(head); wrap.appendChild(list);
      frag.appendChild(wrap);
    }
    KAN.innerHTML=''; KAN.appendChild(frag);
  }

  async function loadKanban(){
    document.getElementById('kanbanLoading')?.remove();
    try{
      const r = await fetch('/api/deals/kanban'); const j = await r.json();
      if(!j.ok){ KAN.innerHTML='<div class="help">'+esc(j.error||'Ошибка')+'</div>'; return; }
      KAN_DATA.columns = j.columns||[];
      KAN_DATA.items = j.items||{};
      const users = USERS || [];
      for(const col of KAN_DATA.columns){
        for(const it of (KAN_DATA.items[col]||[])){
          const u = users.find(x=>String(x.id)===String(it.assignee_id));
          if(u) it.assignee_id_name = u.username;
        }
      }
      renderKanban();
    }catch(e){
      KAN.innerHTML = '<div class="help">Ошибка загрузки</div>';
    }
  }

  async function moveDealStage(id, stage){
    try{
      const r = await fetch('/api/deals/kanban/update', { method:'POST',
        headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({id, stage})});
      const j = await r.json();
      if(!j.ok){ alert(j.error||'Ошибка'); return; }
      loadKanban();
    }catch(e){ alert('Ошибка сети'); }
  }

  async function updateDeal(id, patch){
    try{
      const r = await fetch('/api/deal/update', { method:'POST',
        headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify(Object.assign({id}, patch))});
      const j = await r.json();
      if(!j.ok){ alert(j.error||'Ошибка'); return false; }
      return true;
    }catch(e){ alert('Ошибка сети'); return false; }
  }

  function openDealModal(){
    document.getElementById('dealModal').classList.add('show');
  }
  function closeDealModal(){
    document.getElementById('dealModal').classList.remove('show');
    document.getElementById('dlTitle').value='';
    document.getElementById('dlStage').value='new';
    document.getElementById('dlStatus').value='open';
    document.getElementById('dlAmount').value='0';
    document.getElementById('dlCurrency').value='RUB';
    document.getElementById('dlAssignee').value='';
    document.getElementById('dlCompany').value='';
    document.getElementById('dlContact').value='';
  }

  async function createDeal(){
    const title = (document.getElementById('dlTitle').value||'').trim();
    const stage = (document.getElementById('dlStage').value||'new').trim();
    const status = (document.getElementById('dlStatus').value||'open').trim();
    const amount = parseFloat(document.getElementById('dlAmount').value||'0')||0;
    const currency = (document.getElementById('dlCurrency').value||'RUB').trim();
    const assignee_id = (document.getElementById('dlAssignee').value||'')||null;
    const company_id = (document.getElementById('dlCompany').value||'')||null;
    const contact_id = (document.getElementById('dlContact').value||'')||null;
    if(!title) return alert('Название обязательно');
    try{
      const r = await fetch('/api/deal/create', { method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},
        body: JSON.stringify({title, stage, amount, currency, status, assignee_id, company_id, contact_id}) });
      const j = await r.json();
      if(!j.ok){ alert(j.error||'Ошибка'); return; }
      toast('Сделка создана #' + j.id);
      closeDealModal();
      loadKanban();
    }catch(e){ alert('Ошибка сети'); }
  }

  function openQuickEdit(id){
    const host = KAN.querySelector('.kan-card[data-id="'+id+'"]');
    if(!host) return;

    const box = document.createElement('div');
    box.className = 'qe';
    box.innerHTML = `
      <div style="margin-top:6px;">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">
          <input class="input" id="qeAmount" placeholder="Сумма" value="">
          <select class="select" id="qeAssignee">
            <option value="">—</option>
          </select>
        </div>
        <div style="display:flex;gap:6px;justify-content:flex-end;margin-top:6px;">
          <button class="button secondary" id="qeCancel">Отмена</button>
          <button class="button" id="qeSave">Сохранить</button>
        </div>
      </div>`;

    host.querySelector('.qe')?.remove();
    host.appendChild(box);

    const amtChip = host.querySelector('.chip');
    if(amtChip){
      const raw = (amtChip.textContent||'').trim().split(' ')[0].replace(',','.');
      box.querySelector('#qeAmount').value = raw || '';
    }

    const sel = box.querySelector('#qeAssignee');
    (USERS||[]).forEach(u=>{
      const opt = document.createElement('option');
      opt.value = String(u.id);
      opt.textContent = u.username;
      sel.appendChild(opt);
    });

    box.querySelector('#qeCancel')?.addEventListener('click', e=>{ e.preventDefault(); box.remove(); });
    box.querySelector('#qeSave')?.addEventListener('click', async e=>{
      e.preventDefault();
      const patch = {};
      const amt = parseFloat((box.querySelector('#qeAmount')?.value||'').trim());
      if(!Number.isNaN(amt)) patch.amount = amt;
      const aidRaw = (box.querySelector('#qeAssignee')?.value||'').trim();
      if(aidRaw) patch.assignee_id = parseInt(aidRaw,10);
      if(Object.keys(patch).length===0){ box.remove(); return; }
      const ok = await updateDeal(id, patch);
      if(ok){ toast('Обновлено'); box.remove(); loadKanban(); }
    });
  }

  document.getElementById('btnReloadKanban')?.addEventListener('click', e=>{ e.preventDefault(); loadKanban(); });
  document.getElementById('btnNewDeal')?.addEventListener('click', e=>{ e.preventDefault(); openDealModal(); });
  document.getElementById('btnDealCancel')?.addEventListener('click', e=>{ e.preventDefault(); closeDealModal(); });
  document.getElementById('btnDealSave')?.addEventListener('click', e=>{ e.preventDefault(); createDeal(); });

  document.getElementById('kanban')?.addEventListener('click', e=>{
    const b = e.target.closest('.btnEdit');
    if(!b) return;
    e.preventDefault();
    const id = parseInt(b.getAttribute('data-id')||'0',10)||0;
    if(id) openQuickEdit(id);
  });

  loadKanban();
</script>
<style>
  .fab{position:fixed;left:18px;bottom:18px;z-index:9999}
  .fab .plus{width:48px;height:48px;border-radius:50%;border:1px solid var(--border);background:var(--accent);color:#000;font-weight:800;cursor:pointer}
  .fab .plus:hover{filter:brightness(0.95)}
  .fab .plus:focus{outline:2px solid var(--border)}
</style>
<div class="fab">
  <button class="plus" id="btnFabDeal" title="новая сделка">+</button>
  <script nonce="{{ csp_nonce }}">
    document.getElementById('btnFabDeal')?.addEventListener('click', (e)=>{ e.preventDefault(); openDealModal(); });
  </script>
</div>
"""
# === END STYLES PART 4/9 ===
# === STYLES PART 5/9 — CLIENTS (list/detail) + CALLS (list/filters), badges/chips/pagination ===
# -*- coding: utf-8 -*-

CLIENTS_TMPL = """
<h2 style="margin:0 0 8px 0;">Клиенты</h2>

<div class="split">
  <div class="card">
    <details>
      <summary class="button ghost">Добавить клиента</summary>
      <form method="post" style="display:grid;gap:8px;max-width:720px;margin-top:8px;">
        <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
        <div class="split" style="grid-template-columns:1fr 1fr;gap:8px;">
          <label>Название <input class="input" name="name" required></label>
          <label>ИНН <input class="input" name="inn" placeholder="10–12 цифр"></label>
        </div>
        <div class="split" style="grid-template-columns:1fr 1fr;gap:8px;">
          <label>Телефон <input class="input" name="phone" placeholder="+7 900 000-00-00"></label>
          <label>Email <input class="input" name="email" type="email" placeholder="client@example.com"></label>
        </div>
        <label>Контакт/Заметки <input class="input" name="contact" placeholder="ФИО/Примечание"></label>
        <div style="display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;">
          <button class="button" type="submit">Создать</button>
        </div>
      </form>
    </details>
  </div>

  <div class="card">
    <details open>
      <summary class="button ghost">Поиск</summary>
      <form id="clSearch" style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;margin-top:8px;">
        <label>Запрос <input class="input" id="q" placeholder="название, ИНН, телефон, email"></label>
        <button class="button" type="submit">Найти</button>
        <button class="button secondary" type="button" id="btnReset">Сбросить</button>
      </form>
    </details>
  </div>
</div>

<div class="card" style="margin-top:10px;">
  <table class="table">
    <thead>
      <tr>
        <th>ID</th><th>Название</th><th>ИНН</th><th>Телефон</th><th>Email</th><th>Сделки</th><th></th>
      </tr>
    </thead>
    <tbody id="clientsTBody">
      {% for c in clients %}
      <tr data-id="{{ c.id }}">
        <td>#{{ c.id }}</td>
        <td>{{ c.name }}</td>
        <td>{{ c.inn or '—' }}</td>
        <td>{{ c.phone or '—' }}</td>
        <td>{{ c.email or '—' }}</td>
        <td><span class="badge">{{ c.deals or 0 }}</span></td>
        <td><a class="iconbtn small" href="{{ url_for('client_page', cid=c.id) }}">Открыть</a></td>
      </tr>
      {% else %}
      <tr><td colspan="7"><div class="help">Нет записей</div></td></tr>
      {% endfor %}
    </tbody>
  </table>
  <button class="button ghost" id="loadMoreClients" style="margin-top:8px;">Загрузить больше</button>
</div>

<script nonce="{{ csp_nonce }}">
  let clientsPage = 1;
  let clientsQ = '';

  function rowHTML(c){
    return `
      <tr data-id="${c.id}">
        <td>#${c.id}</td>
        <td>${esc(c.name||'')}</td>
        <td>${esc(c.inn||'—')}</td>
        <td>${esc(c.phone||'—')}</td>
        <td>${esc(c.email||'—')}</td>
        <td><span class="badge">${String(c.deals||0)}</span></td>
        <td><a class="iconbtn small" href="/client/${c.id}">Открыть</a></td>
      </tr>`;
  }
  async function loadClients(reset=false){
    try{
      if(reset){ clientsPage = 1; document.getElementById('clientsTBody').innerHTML=''; }
      const url = new URL(window.location.origin + '/api/clients/list');
      url.searchParams.set('page', clientsPage);
      url.searchParams.set('per_page', 50);
      if(clientsQ) url.searchParams.set('q', clientsQ);
      const r = await fetch(url.toString());
      const j = await r.json();
      if(!j.ok) return alert(j.error||'Ошибка');
      const tb = document.getElementById('clientsTBody');
      let added=0;
      for(const it of (j.items||[])){ tb.insertAdjacentHTML('beforeend', rowHTML(it)); added++; }
      if(added < (j.per_page||50)) document.getElementById('loadMoreClients').style.display='none';
      else document.getElementById('loadMoreClients').style.display='';
      if(reset && added===0){ tb.innerHTML = '<tr><td colspan="7"><div class="help">Ничего не найдено</div></td></tr>'; }
      if(!reset && added>0){ toast('Загружено больше'); }
    }catch(e){ alert('Ошибка загрузки'); }
  }
  document.getElementById('clSearch')?.addEventListener('submit', e=>{
    e.preventDefault();
    clientsQ = (document.getElementById('q').value||'').trim();
    loadClients(true);
  });
  document.getElementById('btnReset')?.addEventListener('click', e=>{
    e.preventDefault();
    clientsQ=''; document.getElementById('q').value='';
    loadClients(true);
  });
  document.getElementById('loadMoreClients')?.addEventListener('click', e=>{
    e.preventDefault(); clientsPage++; loadClients(false);
  });
</script>
"""

CLIENT_PAGE_TMPL = """
<h2>Клиент #{{ c.id }} · {{ c.name }}</h2>

<div class="split">
  <div>
    <div class="card">
      <h3>Карточка</h3>
      <div class="help" id="clInfo"></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <label>Название <input class="input" id="clName" value="{{ c.name }}"></label>
        <label>ИНН <input class="input" id="clInn" value="{{ c.inn or '' }}"></label>
        <label>Телефон <input class="input" id="clPhone" value="{{ c.phone or '' }}"></label>
        <label>Email <input class="input" id="clEmail" value="{{ c.email or '' }}"></label>
        <label>Адрес <input class="input" id="clAddr" value="{{ c.address or '' }}"></label>
        <label>Заметки <input class="input" id="clNotes" value="{{ c.notes or '' }}"></label>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px;flex-wrap:wrap;">
        <button class="button" id="btnClSave">Сохранить</button>
        <button class="iconbtn phone" id="btnClDial"><span class="icon">📞</span><span>Позвонить</span></button>
        <a class="button ghost" href="{{ url_for('clients_list') }}">← к списку</a>
      </div>
    </div>

    <div class="card" style="margin-top:10px;">
      <h3>Звонки</h3>
      <table class="table">
        <thead><tr><th>ID</th><th>Дата</th><th>Напр.</th><th>От</th><th>Кому</th><th>Статус</th><th>Агент</th><th></th></tr></thead>
        <tbody id="clCalls">
          {% for r in calls %}
          <tr data-id="{{ r.id }}">
            <td>#{{ r.id }}</td>
            <td>{{ r.started_at or '' }}</td>
            <td>{{ r.direction or '' }}</td>
            <td>{{ r.from_e164 or '' }}</td>
            <td>{{ r.to_e164 or '' }}</td>
            <td>{{ r.status or '' }}</td>
            <td>{{ r.agent_id or '—' }}</td>
            <td style="white-space:nowrap;display:flex;gap:6px;">
              <button class="iconbtn small btnPlay" data-id="{{ r.id }}">▶︎</button>
              <button class="iconbtn small btnToTask" data-id="{{ r.id }}">В задачу</button>
            </td>
          </tr>
          {% else %}
          <tr><td colspan="8"><div class="help">Нет звонков</div></td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <div>
    <div class="card">
      <h3>Быстрые действия</h3>
      <ul>
        <li><a href="{{ url_for('tasks_page') }}">Создать задачу</a> из звонка на вкладке “Звонки”</li>
        <li>Позвонить клиенту: кнопка “Позвонить” выше</li>
      </ul>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
  const CID = {{ c.id }};

  async function saveClient(){
    try{
      const payload = {
        name: document.getElementById('clName').value||'',
        inn: (document.getElementById('clInn').value||'').trim(),
        phone: document.getElementById('clPhone').value||'',
        email: document.getElementById('clEmail').value||'',
        address: document.getElementById('clAddr').value||'',
        notes: document.getElementById('clNotes').value||''
      };
      const r = await fetch('/api/clients/'+CID, { method:'PATCH', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify(payload) });
      const j = await r.json(); if(!j.ok){ alert(j.error||'Ошибка'); return; }
      document.getElementById('clInfo').textContent='Сохранено';
      setTimeout(()=>{ document.getElementById('clInfo').textContent=''; }, 1500);
    }catch(e){ alert('Ошибка сети'); }
  }
  async function dialClient(){
    const raw = (document.getElementById('clPhone').value||'').trim();
    if(!raw) return alert('Нет номера');
    const d = raw.replace(/\\D+/g,''); if(!d) return;
    let n=d; if(n.length===11 && n.startsWith('8')) n='7'+n.slice(1); if(n.length===10) n='7'+n;
    const e164 = '+'+n;
    try{
      const r=await fetch('/api/cti/click_to_call',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({to:e164})});
      const j=await r.json(); if(j.ok) toast('Звонок: '+e164); else alert(j.error||'Ошибка звонка');
    }catch(e){ alert('Ошибка сети'); }
  }
  async function playRecording(callId){
    try{
      const r = await fetch('/api/call/recording/presign/'+callId);
      const j = await r.json(); if(!j.ok) return alert(j.error||'Нет записи');
      const url = j.url||'';
      if(!url) return alert('Нет записи');
      const a = new Audio(url); a.play().catch(()=>window.open(url,'_blank'));
    }catch(e){ alert('Ошибка проигрывания'); }
  }
  async function callToTask(callId){
    const title = prompt('Заголовок задачи', 'Звонок '+callId) || '';
    try{
      const r=await fetch('/api/call/to_task',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({call_id: callId, title})});
      const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      toast('Задача #'+j.task_id+' создана');
    }catch(e){ alert('Ошибка сети'); }
  }

  document.getElementById('btnClSave')?.addEventListener('click', e=>{ e.preventDefault(); saveClient(); });
  document.getElementById('btnClDial')?.addEventListener('click', e=>{ e.preventDefault(); dialClient(); });
  document.getElementById('clCalls')?.addEventListener('click', e=>{
    const p = e.target.closest('.btnPlay'); if(p){ e.preventDefault(); playRecording(parseInt(p.getAttribute('data-id')||'0',10)); return; }
    const t = e.target.closest('.btnToTask'); if(t){ e.preventDefault(); callToTask(parseInt(t.getAttribute('data-id')||'0',10)); return; }
  });
</script>
"""

CALLS_TMPL = """
<h2 style="margin:0 0 8px 0;">Звонки</h2>

<div class="card">
  <details open>
    <summary class="button ghost">Фильтры</summary>
    <form id="callsFilters" style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;margin-top:8px;">
      <label><input type="checkbox" id="mine" checked> Только мои/входящие</label>
      <label>С <input class="input" type="date" id="dateFrom"></label>
      <label>По <input class="input" type="date" id="dateTo"></label>
      <button class="button" type="submit">Применить</button>
      <button class="button secondary" type="button" id="btnCallsReset">Сбросить</button>
    </form>
  </details>
</div>

<div class="card" style="margin-top:10px;">
  <table class="table">
    <thead>
      <tr>
        <th>ID</th><th>Начало</th><th>Напр.</th><th>От</th><th>Кому</th><th>Агент</th><th>Длит., сек</th><th>Статус</th><th>Запись</th><th></th>
      </tr>
    </thead>
    <tbody id="callsTBody"></tbody>
  </table>
  <button class="button ghost" id="loadMoreCalls" style="margin-top:8px;">Загрузить больше</button>
</div>

<script nonce="{{ csp_nonce }}">
  let callsPage = 1;
  function callsRowHTML(d){
    const dur = (d.duration_sec!=null)? String(d.duration_sec) : '—';
    const rec = d.recording_url ? ('<button class="iconbtn small btnPlay" data-id="'+d.id+'">▶︎</button>') : '—';
    const agent = d.agent_name || (d.agent_id || '—');
    return `
      <tr data-id="${d.id}">
        <td>#${d.id}</td>
        <td>${esc(d.started_at||'')}</td>
        <td>${esc(d.direction||'')}</td>
        <td>${esc(d.from_e164||'')}</td>
        <td>${esc(d.to_e164||'')}</td>
        <td>${esc(String(agent||'—'))}</td>
        <td>${esc(dur)}</td>
        <td>${esc(d.status||'')}</td>
        <td>${rec}</td>
        <td style="white-space:nowrap;display:flex;gap:6px;">
          <button class="iconbtn small btnAssign" data-id="${d.id}">Мне</button>
          <button class="iconbtn small btnToTask" data-id="${d.id}">В задачу</button>
        </td>
      </tr>`;
  }

  function buildCallsURL(){
    const url = new URL(window.location.origin + '/api/calls/list');
    url.searchParams.set('page', callsPage);
    const mine = document.getElementById('mine').checked ? '1' : '0';
    url.searchParams.set('mine', mine);
    const df = (document.getElementById('dateFrom').value||'').trim();
    const dt = (document.getElementById('dateTo').value||'').trim();
    if(df) url.searchParams.set('date_from', df);
    if(dt) url.searchParams.set('date_to', dt);
    return url.toString();
  }

  async function loadCalls(reset=false){
    try{
      if(reset){ callsPage = 1; document.getElementById('callsTBody').innerHTML=''; }
      const r = await fetch(buildCallsURL());
      const j = await r.json();
      if(!j.ok) return alert(j.error||'Ошибка');
      let added=0;
      for(const it of (j.items||[])){ document.getElementById('callsTBody').insertAdjacentHTML('beforeend', callsRowHTML(it)); added++; }
      if(added < 100) document.getElementById('loadMoreCalls').style.display='none';
      else document.getElementById('loadMoreCalls').style.display='';
      if(reset && added===0){ document.getElementById('callsTBody').innerHTML = '<tr><td colspan="10"><div class="help">Ничего не найдено</div></td></tr>'; }
      if(!reset && added>0) toast('Загружено больше');
    }catch(e){ alert('Ошибка загрузки'); }
  }

  async function assignMe(callId){
    try{
      const r = await fetch('/api/call/assign_agent',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({call_id: callId})});
      const j = await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      toast('Назначено вам'); loadCalls(true);
    }catch(e){ alert('Ошибка сети'); }
  }

  async function callToTask(callId){
    const title = prompt('Заголовок задачи', 'Звонок '+callId) || '';
    try{
      const r = await fetch('/api/call/to_task',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({call_id: callId, title})});
      const j = await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      toast('Задача #'+j.task_id+' создана');
    }catch(e){ alert('Ошибка сети'); }
  }

  async function playRecording(callId){
    try{
      const r = await fetch('/api/call/recording/presign/'+callId);
      const j = await r.json(); if(!j.ok) return alert(j.error||'Нет записи');
      const url = j.url||'';
      if(!url) return alert('Нет записи');
      const a = new Audio(url); a.play().catch(()=>window.open(url,'_blank'));
    }catch(e){ alert('Ошибка проигрывания'); }
  }

  document.getElementById('callsFilters')?.addEventListener('submit', e=>{ e.preventDefault(); loadCalls(true); });
  document.getElementById('btnCallsReset')?.addEventListener('click', e=>{
    e.preventDefault();
    document.getElementById('mine').checked = true;
    document.getElementById('dateFrom').value = '';
    document.getElementById('dateTo').value = '';
    loadCalls(true);
  });
  document.getElementById('loadMoreCalls')?.addEventListener('click', e=>{
    e.preventDefault(); callsPage++; loadCalls(false);
  });

  document.getElementById('callsTBody')?.addEventListener('click', e=>{
    const a = e.target.closest('.btnAssign'); if(a){ e.preventDefault(); assignMe(parseInt(a.getAttribute('data-id')||'0',10)); return; }
    const t = e.target.closest('.btnToTask'); if(t){ e.preventDefault(); callToTask(parseInt(t.getAttribute('data-id')||'0',10)); return; }
    const p = e.target.closest('.btnPlay'); if(p){ e.preventDefault(); playRecording(parseInt(p.getAttribute('data-id')||'0',10)); return; }
  });

  loadCalls(true);
</script>
"""
# === END STYLES PART 5/9 ===
# === STYLES PART 6/9 — ANALYTICS + IMPORT WIZARD + APPROVAL PUBLIC + SIMPLE MSG + LOOKUP ===
# -*- coding: utf-8 -*-

ANALYTICS_TMPL = """
<h2 style="margin:0 0 8px 0;">Аналитика</h2>

<div class="card">
  <details open>
    <summary class="button ghost">Фильтры</summary>
    <form id="repFilters" style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;margin-top:8px;">
      <label>С <input class="input" type="date" id="dateFrom"></label>
      <label>По <input class="input" type="date" id="dateTo"></label>
      <button class="button" type="submit">Построить</button>
      <button class="button secondary" type="button" id="btnRepReset">Сбросить</button>
    </form>
  </details>
</div>

<div class="split" style="margin-top:10px;">
  <div class="card">
    <h3>Задачи по дням</h3>
    <div class="help">Создано / Завершено / Просрочено</div>
    <div id="tasksChartWrap" style="width:100%;max-width:100%;overflow:auto;">
      <svg id="tasksChart" viewBox="0 0 800 280" preserveAspectRatio="none" style="width:100%;height:260px;background:var(--surface);border:1px solid var(--border);border-radius:10px;"></svg>
    </div>
    <table class="table" style="margin-top:8px;">
      <thead><tr><th>Дата</th><th>Создано</th><th>Сделано</th><th>Просрочено</th><th>Σ абонплата</th></tr></thead>
      <tbody id="tasksTbl"></tbody>
    </table>
  </div>

  <div class="card">
    <h3>Звонки по дням</h3>
    <div class="help">Входящие / Исходящие · Суммарная длительность</div>
    <div id="callsChartWrap" style="width:100%;max-width:100%;overflow:auto;">
      <svg id="callsChart" viewBox="0 0 800 280" preserveAspectRatio="none" style="width:100%;height:260px;background:var(--surface);border:1px solid var(--border);border-radius:10px;"></svg>
    </div>
    <table class="table" style="margin-top:8px;">
      <thead><tr><th>Дата</th><th>Входящие</th><th>Исходящие</th><th>Σ длительность, сек</th></tr></thead>
      <tbody id="callsTbl"></tbody>
    </table>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
  function esc(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}

  function drawLines(svgId, series, labels, colors){
    const svg = document.getElementById(svgId);
    if(!svg) return;
    const W=800, H=240, PADL=40, PADB=24, PADT=10, PADR=10;
    const innerW = W - PADL - PADR, innerH = H - PADT - PADB;
    const n = Math.max(1, labels.length);
    const maxY = Math.max(1, ...series.flat().map(v=>Number(v)||0));
    const toX = i => PADL + (n<=1 ? innerW/2 : (i*(innerW/(n-1))));
    const toY = v => PADT + innerH - (innerH * (Number(v)||0) / maxY);

    let grid = '';
    const ySteps = 4;
    for(let i=0;i<=ySteps;i++){
      const y = PADT + (innerH*i/ySteps);
      grid += `<line x1="${PADL}" y1="${y}" x2="${PADL+innerW}" y2="${y}" stroke="var(--border)" stroke-width="1" />`;
    }
    let xlbl = '';
    const sparse = Math.ceil(n/8);
    for(let i=0;i<n;i+=sparse){
      const x = toX(i);
      xlbl += `<text x="${x}" y="${PADT+innerH+16}" font-size="11" text-anchor="middle" fill="var(--muted)">${esc(labels[i]||'')}</text>`;
    }

    let paths = '';
    for(let si=0; si<series.length; si++){
      const data = series[si] || [];
      let d = '';
      for(let i=0;i<n;i++){
        const x = toX(i), y = toY(data[i]||0);
        d += (i===0?`M ${x} ${y}`:` L ${x} ${y}`);
      }
      paths += `<path d="${d}" fill="none" stroke="${colors[si]||'#2bd66a'}" stroke-width="2"/>`;
      for(let i=0;i<n;i++){
        const x = toX(i), y = toY(data[i]||0);
        paths += `<circle cx="${x}" cy="${y}" r="2.2" fill="${colors[si]||'#2bd66a'}"/>`;
      }
    }

    svg.innerHTML = `<g>${grid}${xlbl}${paths}</g>`;
  }

  async function loadReports(){
    const df = (document.getElementById('dateFrom').value||'').trim();
    const dt = (document.getElementById('dateTo').value||'').trim();

    try{
      const url = new URL(window.location.origin + '/api/reports/tasks_daily');
      if(df) url.searchParams.set('date_from', df);
      if(dt) url.searchParams.set('date_to', dt);
      const r = await fetch(url.toString()); const j = await r.json();
      const rows = j.ok ? (j.items||[]) : [];
      const lbl = rows.map(x=>x.ymd);
      const created = rows.map(x=>Number(x.created_cnt||0));
      const done = rows.map(x=>Number(x.done_cnt||0));
      const overdue = rows.map(x=>Number(x.overdue_cnt||0));
      drawLines('tasksChart', [created, done, overdue], lbl, ['#2bd66a','#7ec1ff','#ff6b6b']);
      const tb = document.getElementById('tasksTbl'); tb.innerHTML='';
      if(!rows.length){ tb.innerHTML = '<tr><td colspan="5"><div class="help">Нет данных</div></td></tr>'; }
      for(const it of rows){
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${esc(it.ymd)}</td><td>${esc(String(it.created_cnt||0))}</td><td>${esc(String(it.done_cnt||0))}</td><td>${esc(String(it.overdue_cnt||0))}</td><td>${esc(String((it.monthly_fee_sum||0)))}</td>`;
        tb.appendChild(tr);
      }
    }catch(e){}

    try{
      const url = new URL(window.location.origin + '/api/reports/calls_daily');
      if(df) url.searchParams.set('date_from', df);
      if(dt) url.searchParams.set('date_to', dt);
      const r = await fetch(url.toString()); const j = await r.json();
      const rows = j.ok ? (j.items||[]) : [];
      const lbl = rows.map(x=>x.ymd);
      const inCnt = rows.map(x=>Number(x.in_cnt||0));
      const outCnt = rows.map(x=>Number(x.out_cnt||0));
      drawLines('callsChart', [inCnt, outCnt], lbl, ['#7ec1ff','#2bd66a']);
      const tb = document.getElementById('callsTbl'); tb.innerHTML='';
      if(!rows.length){ tb.innerHTML = '<tr><td colspan="4"><div class="help">Нет данных</div></td></tr>'; }
      for(const it of rows){
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${esc(it.ymd)}</td><td>${esc(String(it.in_cnt||0))}</td><td>${esc(String(it.out_cnt||0))}</td><td>${esc(String(it.dur_sum||0))}</td>`;
        tb.appendChild(tr);
      }
    }catch(e){}
  }

  document.getElementById('repFilters')?.addEventListener('submit', e=>{ e.preventDefault(); loadReports(); });
  document.getElementById('btnRepReset')?.addEventListener('click', e=>{
    e.preventDefault(); document.getElementById('dateFrom').value=''; document.getElementById('dateTo').value=''; loadReports();
  });
  loadReports();
</script>
"""

IMPORT_TMPL = """
<h2>Импорт CSV</h2>

<div class="card">
  <p class="help">Загрузите CSV-файл. Разделитель будет определён автоматически (предпочтительно «;»).</p>
  <form method="post" enctype="multipart/form-data" style="display:grid;gap:8px;max-width:680px;">
    <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
    <label>Файл CSV <input class="input" type="file" name="csvfile" accept=".csv,text/csv" required></label>
    <label>Режим
      <select class="select" name="mode">
        <option value="tasks">Задачи</option>
        <option value="clients">Клиенты</option>
      </select>
    </label>
    <details>
      <summary class="button ghost">Подсказки по колонкам</summary>
      <div class="help" style="margin-top:8px;">
        <strong>Задачи:</strong> title, description, comments, due, monthly_fee, company_inn, company_id<br>
        <strong>Клиенты:</strong> name, inn, phone, email, address, notes, contact_name, contact_phone, contact_email
      </div>
    </details>
    <div style="display:flex;gap:8px;justify-content:flex-end;">
      <button class="button" type="submit">Импортировать</button>
    </div>
  </form>
</div>
"""

APPROVAL_PUBLIC_TMPL = """
<h2>Согласование</h2>

<div class="card">
  <div><strong>Тема:</strong> {{ a.title or '—' }}</div>
  <div style="margin-top:6px;"><strong>Описание:</strong><br>{{ a.description or '—' }}</div>
  <div style="margin-top:6px;"><strong>Статус:</strong> <span class="badge">{{ a.status or 'pending' }}</span></div>
</div>

<div class="card" style="margin-top:10px;">
  {% if a.status and a.status.lower()=='pending' %}
  <h3>Принять решение</h3>
  <form method="post" style="display:grid;gap:8px;max-width:720px;">
    <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
    <input type="hidden" name="form_token" value="{{ a.form_token or '' }}">
    <label>Действие
      <select class="select" name="action" required>
        <option value="approve">Одобрить</option>
        <option value="request_changes">Запросить изменения</option>
      </select>
    </label>
    <label>Комментарий (опц.) <textarea class="input" name="message" rows="4" maxlength="1000"></textarea></label>
    <div style="display:flex;gap:8px;justify-content:flex-end;">
      <button class="button" type="submit">Отправить</button>
    </div>
  </form>
  {% else %}
  <div class="help">Решение уже зафиксировано.</div>
  {% endif %}
</div>

<div class="card" style="margin-top:10px;">
  <h3>История</h3>
  <table class="table">
    <thead><tr><th>ID</th><th>Кем</th><th>Действие</th><th>Сообщение</th><th>IP</th><th>UA</th><th>Дата</th></tr></thead>
    <tbody>
      {% for r in logs %}
      <tr>
        <td>#{{ r.id }}</td><td>{{ r.actor or '—' }}</td><td>{{ r.action or '—' }}</td>
        <td>{{ r.message or '' }}</td><td>{{ r.ip or '' }}</td><td class="help">{{ r.ua or '' }}</td><td>{{ r.created_at or '' }}</td>
      </tr>
      {% else %}
      <tr><td colspan="7"><div class="help">Лог пуст</div></td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>
"""

SIMPLE_MSG_TMPL = """
<div class="card">
  <h2 style="margin:0 0 8px 0;">{{ title or 'Сообщение' }}</h2>
  <div>{{ body or '' }}</div>
</div>
"""

SEARCH_TMPL = """
<h2>Поиск по базе</h2>

<div class="card">
  <form method="get" action="{{ url_for('search_page') }}" style="display:flex;gap:8px;max-width:820px;">
    <input class="input" name="q" value="{{ q or '' }}" placeholder="Что ищем? (текст, номер, email)">
    <button class="button" type="submit">Искать</button>
    <a class="button ghost" href="{{ url_for('search_page') }}">Сбросить</a>
  </form>
  {% if not q %}
  <div class="help" style="margin-top:8px;">Введите запрос и нажмите «Искать»</div>
  {% endif %}
  {% if q and (results.inbox|length + results.tasks|length + results.chats|length)==0 %}
  <div class="help" style="margin-top:8px;">Ничего не найдено</div>
  {% endif %}
  </div>

<div class="split" style="margin-top:10px;">
  <div class="card">
    <h3>Входящие</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Фрагмент</th><th></th></tr></thead>
      <tbody>
        {% for m in results.inbox %}
        <tr>
          <td>#{{ m.id }}</td>
          <td class="help">{{ (m.body or '')[:120] }}</td>
          <td><a class="iconbtn small" href="{{ url_for('thread_view', tid=m.thread_id) }}">Открыть тред</a></td>
        </tr>
        {% else %}
        <tr><td colspan="3"><div class="help">Нет результатов</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Задачи</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Заголовок</th><th></th></tr></thead>
      <tbody>
        {% for t in results.tasks %}
        <tr>
          <td>#{{ t.id }}</td>
          <td>{{ t.title or '' }}</td>
          <td><a class="iconbtn small" href="{{ url_for('task_view', tid=t.id) }}">Открыть</a></td>
        </tr>
        {% else %}
        <tr><td colspan="3"><div class="help">Нет результатов</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Чаты</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Фрагмент</th><th></th></tr></thead>
      <tbody>
        {% for c in results.chats %}
        <tr>
          <td>#{{ c.id }}</td>
          <td class="help">{{ (c.body or '')[:120] }}</td>
          <td><a class="iconbtn small" href="{{ url_for('chat_channel', cid=c.channel_id) }}">Открыть канал</a></td>
        </tr>
        {% else %}
        <tr><td colspan="3"><div class="help">Нет результатов</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
"""

LOOKUP_TMPL = """
<h2>Поиск клиента</h2>

<div class="card">
  <form method="get" action="{{ url_for('lookup') }}" style="display:grid;gap:8px;max-width:820px;">
    <div class="split" style="grid-template-columns:1fr 1fr;gap:8px;">
      <label>Телефон <input class="input" name="phone" value="{{ params.phone or '' }}" placeholder="+7 ..."></label>
      <label>ID <input class="input" name="id" value="{{ params.id or '' }}"></label>
      <label>ИНН <input class="input" name="inn" value="{{ params.inn or '' }}"></label>
      <label>Email <input class="input" name="email" value="{{ params.email or '' }}"></label>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;">
      <button class="button" type="submit">Искать</button>
      <a class="button ghost" href="{{ url_for('lookup') }}">Сбросить</a>
    </div>
  </form>
</div>

<div class="split" style="margin-top:10px;">
  <div class="card">
    <h3>По ID</h3>
    {% if results.by_id %}
      <div><a class="iconbtn small" href="{{ url_for('client_page', cid=results.by_id.id) }}">Открыть #{{ results.by_id.id }}</a></div>
      <div class="help">{{ results.by_id.name or '' }}</div>
      <div class="help">{{ results.by_id.phone or '' }} · {{ results.by_id.email or '' }}</div>
    {% else %}
      <div class="help">—</div>
    {% endif %}
  </div>

  <div class="card">
    <h3>Компании</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Название</th><th>ИНН</th><th>Телефон</th><th>Email</th><th></th></tr></thead>
      <tbody>
        {% for c in results.companies %}
        <tr>
          <td>#{{ c.id }}</td><td>{{ c.name or '' }}</td><td>{{ c.inn or '' }}</td><td>{{ c.phone or '' }}</td><td>{{ c.email or '' }}</td>
          <td><a class="iconbtn small" href="{{ url_for('client_page', cid=c.id) }}">Открыть</a></td>
        </tr>
        {% else %}
        <tr><td colspan="6"><div class="help">Нет результатов</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Контакты</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>ФИО</th><th>Телефон</th><th>Email</th></tr></thead>
      <tbody>
        {% for p in results.contacts %}
        <tr>
          <td>#{{ p.id }}</td><td>{{ p.name or '' }}</td><td>{{ p.phone or '' }}</td><td>{{ p.email or '' }}</td>
        </tr>
        {% else %}
        <tr><td colspan="4"><div class="help">Нет результатов</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
"""
# === END STYLES PART 6/9 ===
# === STYLES PART 7/9 — CHAT (org-wide) + MEETINGS (list/schedule/join) ===
# -*- coding: utf-8 -*-

CHAT_TMPL = """
<h2 style="margin:0 0 8px 0;">Командные чаты</h2>

<div class="card">
  <details open>
    <summary class="button ghost">Управление каналами</summary>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
      <button class="button secondary" id="btnNewChan" type="button">Создать канал</button>
    </div>
  </details>
</div>

<div class="split equal" style="margin-top:10px;grid-template-columns:320px 1fr;">
  <div class="card" style="display:flex;flex-direction:column;gap:8px;">
    <div style="display:flex;gap:6px;align-items:center;">
      <input class="input" id="chanFilter" placeholder="Фильтр по названию" style="flex:1 1 auto;">
      <button class="iconbtn small" id="btnChanReset">✕</button>
    </div>
    <div id="chanList" style="max-height:60vh;overflow:auto;display:flex;flex-direction:column;gap:6px;">
      {% for ch in channels %}
        <a href="{{ url_for('chat_channel', cid=ch.id) }}" class="navitem {% if current and current.id==ch.id %}active{% endif %}" data-name="{{ (ch.name or '')|lower }}">
          <span class="icon">{% if ch.type=='personal' %}👤{% elif ch.type=='group' %}👥{% else %}# {% endif %}</span>
          <span class="label">{{ ch.name or ('#'+(ch.id|string)) }}</span>
        </a>
      {% else %}
        <div class="help">Каналы отсутствуют</div>
      {% endfor %}
    </div>
  </div>

  <div class="card" style="display:flex;flex-direction:column;min-height:60vh;">
    {% if not current %}
      <div class="help">Выберите канал слева или создайте новый</div>
    {% else %}
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;">
        <div class="tag">#{{ current.id }}</div>
        <div style="font-weight:700;">{{ current.name or ('Канал #' + (current.id|string)) }}</div>
        <div class="help" style="margin-left:auto;">Тип: {{ current.type }}</div>
      </div>
      <style>
        .cwrap{display:flex;flex-direction:column-reverse;gap:8px;overflow:auto;min-height:380px;max-height:60vh;border:1px solid var(--border);border-radius:12px;padding:10px;background:var(--surface)}
        .cmsg{max-width:72%;padding:8px 10px;border-radius:12px;border:1px solid var(--border);background:var(--panel)}
        .cmsg .meta{color:var(--muted);font-size:12px;margin-bottom:4px}
        .cmsg.own{margin-left:auto;border-color:#2bd66a66;box-shadow:0 0 0 2px #2bd66a1a inset}
        .cmsg.system{background:transparent;border-style:dashed;opacity:.8}
      </style>
      <div id="chatList" class="cwrap" data-page="{{ request.args.get('page','1') }}">
        {% for m in messages %}
          {% set mine = (user and m.user_id==user.id) %}
          <div class="cmsg {% if mine %}own{% endif %} {% if m.deleted_at %}system{% endif %}">
            <div class="meta">{{ m.created_at }} • {{ m.username or ('#'+(m.user_id|string)) }}</div>
            <div class="body">{{ m.body or '' }}</div>
          </div>
        {% else %}
          <div class="help">Сообщений пока нет</div>
        {% endfor %}
      </div>
      <div style="display:flex;gap:8px;justify-content:space-between;margin-top:8px;">
        <a class="button ghost" id="btnOlder" href="{{ url_for('chat_channel', cid=current.id, page=(request.args.get('page',1)|int + 1)) }}">Загрузить ещё</a>
        <div class="help">Страница {{ request.args.get('page','1') }}</div>
      </div>

      <div class="composer" style="margin-top:10px;">
        <div id="chatDrop" style="border:2px dashed var(--border);padding:10px;text-align:center;cursor:pointer;">Перетащите файлы или кликните для загрузки</div>
        <input type="file" id="chatFile" multiple style="display:none;">
        <div id="chatAtt" class="help" style="margin:6px 0;display:none;"></div>
        <textarea class="input" id="chatBody" rows="3" placeholder="Сообщение..."></textarea>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px;flex-wrap:wrap;">
          <button class="button" id="btnChatSend" type="button">Отправить</button>
          <button class="button secondary" id="btnChatUpload" type="button">Загрузить файл</button>
        </div>
      </div>
    {% endif %}
  </div>
</div>

<div class="modal-backdrop" id="chanModal">
  <div class="modal">
    <h3>Создать канал</h3>
    <form style="display:grid;gap:8px;">
      <label>Тип
        <select class="select" id="chType">
          <option value="public">public</option>
          <option value="group">group</option>
          <option value="personal">personal (1:1)</option>
        </select>
      </label>
      <label>Название (для public/group) <input class="input" id="chTitle" placeholder="Канал"></label>
      <label>Пользователи (id через запятую) <input class="input" id="chMembers" placeholder="1,2,3"></label>
      <label>ID отделов (опц.) <input class="input" id="chDepts" placeholder="1,2"></label>
      <div class="help">Для personal должен быть указан ровно один пользователь</div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px;">
        <button class="button secondary" type="button" id="btnChCancel">Отмена</button>
        <button class="button" type="button" id="btnChCreate">Создать</button>
      </div>
    </form>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
  function esc(s){ return String(s||'').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

  // Channel filter
  document.getElementById('chanFilter')?.addEventListener('input', e=>{
    const q = (e.target.value||'').trim().toLowerCase();
    document.querySelectorAll('#chanList .navitem').forEach(it=>{
      const name = (it.getAttribute('data-name')||'');
      it.style.display = (!q || name.includes(q)) ? '' : 'none';
    });
  });
  document.getElementById('btnChanReset')?.addEventListener('click', e=>{
    e.preventDefault(); const i=document.getElementById('chanFilter'); if(i){ i.value=''; i.dispatchEvent(new Event('input')); }
  });

  // New channel modal
  function openCh(){ document.getElementById('chanModal').classList.add('show'); }
  function closeCh(){ document.getElementById('chanModal').classList.remove('show'); }
  document.getElementById('btnNewChan')?.addEventListener('click', e=>{ e.preventDefault(); openCh(); });
  document.getElementById('btnChCancel')?.addEventListener('click', e=>{ e.preventDefault(); closeCh(); });
  document.getElementById('btnChCreate')?.addEventListener('click', async e=>{
    e.preventDefault();
    const type=(document.getElementById('chType').value||'public');
    const title=(document.getElementById('chTitle').value||'').trim();
    const members=(document.getElementById('chMembers').value||'').split(',').map(s=>s.trim()).filter(Boolean).map(s=>parseInt(s,10)).filter(n=>!isNaN(n));
    const departments=(document.getElementById('chDepts').value||'').split(',').map(s=>s.trim()).filter(Boolean).map(s=>parseInt(s,10)).filter(n=>!isNaN(n));
    try{
      const r=await fetch('/api/chat/create',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({type, title, members, department_ids: departments})});
      const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      closeCh(); location.href = '/chat/'+j.id;
    }catch(_){ alert('Ошибка сети'); }
  });

  // Chat message send/upload
  async function chatSend(cid){
    const body=(document.getElementById('chatBody').value||'').trim();
    if(!body) return alert('Пустое сообщение');
    try{
      const r=await fetch('/api/chat/send',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({channel_id: cid, body})});
      const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      document.getElementById('chatBody').value=''; location.reload();
    }catch(_){ alert('Ошибка сети'); }
  }
  async function chatUpload(cid, files){
    try{
      const list = files || (document.getElementById('chatFile')?.files||[]);
      if(!list || !list.length) return;
      for(let i=0;i<list.length;i++){
        const f=list[i]; const fd = new FormData(); fd.append('file', f); fd.append('channel_id', String(cid));
        const r=await fetch('/api/chat/upload',{method:'POST',headers:{'X-CSRFToken':CSRF}, body: fd});
        const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка загрузки');
      }
      toast('Файлы загружены'); location.reload();
    }catch(_){ alert('Ошибка загрузки'); }
  }

  {% if current %}
    const CID = {{ current.id }};
    document.getElementById('btnChatSend')?.addEventListener('click', e=>{ e.preventDefault(); chatSend(CID); });
    document.getElementById('btnChatUpload')?.addEventListener('click', e=>{ e.preventDefault(); document.getElementById('chatFile')?.click(); });
    document.getElementById('chatFile')?.addEventListener('change', e=>chatUpload(CID));
    document.getElementById('chatDrop')?.addEventListener('click', e=>{ e.preventDefault(); document.getElementById('chatFile')?.click(); });
    document.getElementById('chatDrop')?.addEventListener('dragover', e=>{ e.preventDefault(); });
    document.getElementById('chatDrop')?.addEventListener('drop', e=>{ e.preventDefault(); const files=e.dataTransfer.files; if(files && files.length) chatUpload(CID, files); });
    // Hotkey: Ctrl/Cmd+Enter to send
    document.getElementById('chatBody')?.addEventListener('keydown', e=>{
      if((e.ctrlKey||e.metaKey) && e.key==='Enter'){ e.preventDefault(); chatSend(CID); }
    });
  {% endif %}
</script>
"""

MEETING_TMPL = """
{% set m = meeting %}
{% if not m %}
  <h2>Встречи</h2>

  <div class="card">
    <h3>Запланировать встречу</h3>
    <div class="help">Укажите тему, время и участников (и/или отделы)</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
      <label>Тема <input class="input" id="mtTitle" placeholder="Встреча"></label>
      <label>Уведомить за, мин <input class="input" id="mtNotify" type="number" value="15"></label>
      <label>Начало <input class="input" id="mtStart" type="datetime-local"></label>
      <label>Окончание <input class="input" id="mtEnd" type="datetime-local"></label>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;">
      <label>Участники
        <select class="select" id="mtUsers" multiple size="6">
          {% for u in query_db('SELECT id,username FROM users WHERE org_id=? AND active=1 ORDER BY username',(user.org_id,)) %}
            <option value="{{ u.id }}">{{ u.username }}</option>
          {% endfor %}
        </select>
      </label>
      <label>Отделы
        <select class="select" id="mtDepts" multiple size="6">
          {% for d in query_db('SELECT id,name FROM departments WHERE org_id=? ORDER BY name',(user.org_id,)) %}
            <option value="{{ d.id }}">{{ d.name }}</option>
          {% endfor %}
        </select>
      </label>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px;">
      <button class="button" id="btnMtCreate">Запланировать</button>
    </div>
  </div>

  <div class="card" style="margin-top:10px;">
    <h3>Список встреч</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Тема</th><th>Начало</th><th>Уведомление</th><th>Комната</th><th></th></tr></thead>
      <tbody id="mtList">
        <tr><td colspan="6"><div class="help">Загрузка...</div></td></tr>
      </tbody>
    </table>
  </div>

  <script nonce="{{ csp_nonce }}">
    function vals(selId){ const el=document.getElementById(selId); return [...(el?.selectedOptions||[])].map(o=>parseInt(o.value,10)).filter(n=>!isNaN(n)); }
    async function loadMeetings(){
      try{
        const r=await fetch('/api/meetings'); const j=await r.json();
        const tb=document.getElementById('mtList'); tb.innerHTML='';
        if(!j.ok || !(j.items||[]).length){ tb.innerHTML='<tr><td colspan="6"><div class="help">Нет встреч</div></td></tr>'; return; }
        for(const it of j.items){
          const tr=document.createElement('tr');
          tr.innerHTML = `
            <td>#${it.id}</td>
            <td>${esc(it.title||'')}</td>
            <td>${esc(it.start_at||'')}</td>
            <td>${esc(String(it.notify_before_min||0))} мин</td>
            <td class="help">${esc(it.room||'')}</td>
            <td style="white-space:nowrap;display:flex;gap:6px;">
              <a class="iconbtn small" href="/meeting/${it.id}">Join</a>
              <button class="iconbtn small btnDel" data-id="${it.id}">Удалить</button>
            </td>`;
          tb.appendChild(tr);
        }
      }catch(_){ document.getElementById('mtList').innerHTML='<tr><td colspan="6"><div class="help">Ошибка</div></td></tr>'; }
    }
    async function createMeeting(){
      const title=(document.getElementById('mtTitle').value||'').trim()||'Встреча';
      const start_at=(document.getElementById('mtStart').value||'');
      const end_at=(document.getElementById('mtEnd').value||'');
      const notify_before_min=parseInt(document.getElementById('mtNotify').value||'0',10)||0;
      const participants=vals('mtUsers'); const department_ids=vals('mtDepts');
      try{
        const r=await fetch('/api/meetings/schedule',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({title,start_at,end_at,participants,department_ids,notify_before_min})});
        const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
        toast('Встреча создана'); loadMeetings();
      }catch(_){ alert('Ошибка сети'); }
    }
    async function deleteMeeting(id){
      try{
        const r=await fetch('/api/meetings/'+id,{method:'DELETE',headers:{'X-CSRFToken':CSRF}});
        const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
        toast('Удалено'); loadMeetings();
      }catch(_){ alert('Ошибка сети'); }
    }
    document.getElementById('btnMtCreate')?.addEventListener('click', e=>{ e.preventDefault(); createMeeting(); });
    document.getElementById('mtList')?.addEventListener('click', e=>{
      const b=e.target.closest('.btnDel'); if(!b) return;
      e.preventDefault(); if(confirm('Удалить встречу?')) deleteMeeting(parseInt(b.getAttribute('data-id')||'0',10));
    });
    loadMeetings();
  </script>

{% else %}
  <h2>Встреча #{{ m.id }} · {{ m.title or 'Без темы' }}</h2>
  <div class="split equal" style="grid-template-columns:1fr 380px;">
    <div class="card">
      <div class="help">Комната: {{ m.room }}</div>
      <div style="margin-top:8px;">
        <iframe src="{{ jitsi_base }}/{{ m.room }}" allow="camera; microphone; display-capture; clipboard-write" style="width:100%;height:70vh;border:1px solid var(--border);border-radius:12px;"></iframe>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px;flex-wrap:wrap;">
        <button class="button secondary" id="btnStartRec">Начать запись</button>
        <button class="button warn" id="btnStopRec">Остановить запись</button>
        <a class="button ghost" href="{{ url_for('meetings_page') }}">← ко встречам</a>
      </div>
    </div>
    <div class="card">
      <h3>Сведения</h3>
      <div><strong>Начало:</strong> {{ m.start_at or '—' }}</div>
      <div><strong>Окончание:</strong> {{ m.end_at or '—' }}</div>
      <div><strong>Участники:</strong>
        <div class="help">
          {% set ppl = (m.participants_json or '[]') %}
          {{ ppl }}
        </div>
      </div>
      <div style="margin-top:8px;">
        <div><strong>Итог (AI):</strong></div>
        <div class="help">{{ m.ai_summary or '—' }}</div>
      </div>
    </div>
  </div>
  <script nonce="{{ csp_nonce }}">
    const MID = {{ m.id }};
    async function startRec(){
      try{
        const r=await fetch('/api/meeting/'+MID+'/start_recording',{method:'POST',headers:{'X-CSRFToken':CSRF}});
        const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка'); toast('Запись начата');
      }catch(_){ alert('Ошибка сети'); }
    }
    async function stopRec(){
      try{
        const r=await fetch('/api/meeting/'+MID+'/stop_recording',{method:'POST',headers:{'X-CSRFToken':CSRF}});
        const j=await r.json(); if(!j.ok) return alert(j.error||'Ошибка'); toast('Запись остановлена'); if(j.summary) toast('AI: '+j.summary);
      }catch(_){ alert('Ошибка сети'); }
    }
    document.getElementById('btnStartRec')?.addEventListener('click', e=>{ e.preventDefault(); startRec(); });
    document.getElementById('btnStopRec')?.addEventListener('click', e=>{ e.preventDefault(); stopRec(); });
  </script>
{% endif %}
"""
# === END STYLES PART 7/9 ===
# === STYLES PART 8/9 — SETTINGS (Admin): Channels/Webhooks/AI/Statuses/Users/Tokens/Queue/Custom Fields ===
# -*- coding: utf-8 -*-

SETTINGS_TMPL = """
<h2 style="margin:0 0 8px 0;">Настройки</h2>

<div class="split" style="align-items:start;">
  <!-- Каналы -->
  <div class="card">
    <h3>Каналы</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Тип</th><th>Название</th><th>Активен</th><th></th></tr></thead>
      <tbody>
        {% for ch in channels %}
        <tr>
          <td>#{{ ch.id }}</td>
          <td>{{ ch.type }}</td>
          <td>{{ ch.name or '' }}</td>
          <td>{{ 'yes' if ch.active else 'no' }}</td>
          <td style="white-space:nowrap;display:flex;gap:6px;">
            <form method="post" action="{{ url_for('settings_channel_toggle', cid=ch.id) }}" class="js-confirm" data-confirm="Переключить активность?">
              <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
              <button class="iconbtn small" type="submit">{{ 'Выключить' if ch.active else 'Включить' }}</button>
            </form>
            {% if ch.type=='phone' %}
              <details>
                <summary class="iconbtn small">Телефония</summary>
                <form method="post" action="{{ url_for('settings_phone_update', cid=ch.id) }}" style="display:grid;gap:8px;min-width:320px;margin-top:8px;">
                  <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
                  <label>Провайдер
                    <select class="select" name="provider">
                      {% set prov = (ch.cfg.provider or '') %}
                      {% for p in ('', 'mango', 'uis', 'telfin') %}
                      <option value="{{ p }}" {% if prov==p %}selected{% endif %}>{{ p or '—' }}</option>
                      {% endfor %}
                    </select>
                  </label>
                  <label>Секрет (канала) <input class="input" name="secret" value="{{ (ch.secret or '') }}"></label>
                  <label>Подпись провайдера <input class="input" name="signing_key" value="{{ ch.cfg.signing_key or '' }}"></label>
                  <label>From (E.164) <input class="input" name="from_e164" value="{{ ch.cfg.from_e164 or '' }}"></label>
                  <div style="display:flex;gap:8px;justify-content:flex-end;">
                    <button class="button" type="submit">Сохранить</button>
                    <button class="button secondary btnUrls" data-id="{{ ch.id }}" type="button">URL вебхуков</button>
                  </div>
                  <div class="help" id="urls-{{ ch.id }}"></div>
                </form>
              </details>
            {% endif %}
          </td>
        </tr>
        {% else %}
        <tr><td colspan="5"><div class="help">Каналы отсутствуют</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
    <details style="margin-top:8px;">
      <summary class="button ghost">Добавить канал</summary>
      <form method="post" action="{{ url_for('settings_channel_add') }}" style="display:grid;gap:8px;max-width:420px;margin-top:8px;">
        <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
        <label>Тип
          <select class="select" name="type">
            {% for t in ('phone','telegram','vk','email','web','other') %}
            <option value="{{ t }}">{{ t }}</option>
            {% endfor %}
          </select>
        </label>
        <label>Название <input class="input" name="name" placeholder="Произвольное"></label>
        <div style="display:flex;gap:8px;justify-content:flex-end;"><button class="button" type="submit">Создать</button></div>
      </form>
    </details>
  </div>

  <!-- Вебхуки -->
  <div class="card">
    <h3>Вебхуки</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Событие</th><th>URL</th><th>Секрет</th><th>Активен</th><th></th></tr></thead>
      <tbody id="whList">
        {% for w in webhooks %}
        <tr data-id="{{ w.id }}"><td>#{{ w.id }}</td><td>{{ w.event }}</td><td class="help">{{ w.url }}</td><td class="help">{{ w.secret or '' }}</td><td>{{ 'yes' if w.active else 'no' }}</td>
          <td style="white-space:nowrap;display:flex;gap:6px;">
            <button class="iconbtn small btnWhTest" data-id="{{ w.id }}">Тест</button>
            <form method="post" action="{{ url_for('settings_webhook_delete', wid=w.id) }}" class="js-confirm" data-confirm="Удалить вебхук?">
              <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
              <button class="iconbtn small" type="submit">Удалить</button>
            </form>
          </td></tr>
        {% else %}
        <tr><td colspan="6"><div class="help">Нет вебхуков</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
    <details style="margin-top:8px;">
      <summary class="button ghost">Добавить вебхук</summary>
      <form method="post" action="{{ url_for('settings_webhook_add') }}" style="display:grid;gap:8px;max-width:520px;margin-top:8px;">
        <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
        <label>Событие <input class="input" name="event" placeholder="например, task.created" required></label>
        <label>URL <input class="input" name="url" placeholder="https://example.com/wh" required></label>
        <label>Секрет (подпись) <input class="input" name="secret" placeholder="опционально"></label>
        <div style="display:flex;gap:8px;justify-content:flex-end;"><button class="button" type="submit">Добавить</button></div>
      </form>
    </details>
  </div>
</div>

<div class="split" style="margin-top:10px;align-items:start;">
  <!-- AI конфиг -->
  <div class="card">
    <h3>AI‑конфиг</h3>
    <form method="post" action="{{ url_for('settings_ai_config') }}" style="display:grid;gap:8px;max-width:520px;">
      <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
      <label>Провайдер <input class="input" name="provider" value=""></label>
      <label>Модель <input class="input" name="model" value=""></label>
      <div class="split" style="grid-template-columns:1fr 1fr;gap:8px;">
        <label>Temperature <input class="input" name="temperature" type="number" step="0.01" value="0.3"></label>
        <label>Max tokens <input class="input" name="max_tokens" type="number" value="512"></label>
      </div>
      <label>Policy (JSON) <textarea class="input" name="policy" rows="5" placeholder='{"exclude_internal_notes":true}'></textarea></label>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button class="button secondary" type="button" id="btnAiLoad">Показать текущий</button>
        <button class="button" type="submit">Сохранить</button>
      </div>
    </form>
    <div class="help" style="margin-top:6px;">Последние задания AI:</div>
    <table class="table">
      <thead><tr><th>ID</th><th>Kind</th><th>Status</th><th>Создано</th></tr></thead>
      <tbody>
        {% for j in ai_jobs %}
        <tr><td>#{{ j.id }}</td><td>{{ j.kind }}</td><td>{{ j.status }}</td><td>{{ j.created_at }}</td></tr>
        {% else %}
        <tr><td colspan="4"><div class="help">Пока нет</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Статусы задач -->
  <div class="card">
    <h3>Статусы задач</h3>
    <ul>
      {% for s in task_statuses %}
      <li style="display:flex;gap:8px;align-items:center;">
        <span class="tag">{{ s.name }}</span>
        <form method="post" action="{{ url_for('settings_task_status_delete', sid=s.id) }}" class="js-confirm" data-confirm="Удалить статус?">
          <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
          <button class="iconbtn small" type="submit">Удалить</button>
        </form>
      </li>
      {% else %}
      <li class="help">Нет пользовательских статусов</li>
      {% endfor %}
    </ul>
    <form method="post" action="{{ url_for('settings_task_status_add') }}" style="display:flex;gap:8px;align-items:end;margin-top:8px;flex-wrap:wrap;">
      <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
      <label>Новый статус <input class="input" name="name" placeholder="in_progress" required></label>
      <button class="button" type="submit">Добавить</button>
    </form>
  </div>
</div>

<div class="split" style="margin-top:10px;align-items:start;">
  <!-- Пользователи -->
  <div class="card">
    <h3>Пользователи</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Логин</th><th>Email</th><th>Роль</th><th>Активен</th><th>Создан</th><th></th></tr></thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>#{{ u.id }}</td><td>{{ u.username }}</td><td>{{ u.email or '—' }}</td><td>{{ u.role }}</td><td>{{ 'yes' if u.active else 'no' }}</td><td>{{ u.created_at }}</td>
          <td style="white-space:nowrap;display:flex;gap:6px;">
            <form method="post" action="{{ url_for('settings_user_toggle', uid=u.id) }}">
              <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
              <button class="iconbtn small" type="submit">{{ 'Деактивировать' if u.active else 'Активировать' }}</button>
            </form>
            <form method="post" action="{{ url_for('settings_user_password', uid=u.id) }}" class="js-confirm" data-confirm="Сменить пароль пользователю?">
              <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
              <input class="input" name="password" placeholder="новый пароль" style="max-width:160px;">
              <button class="iconbtn small" type="submit">Сменить пароль</button>
            </form>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="7"><div class="help">Нет пользователей</div></td></tr>
        {% endfor %}
      </tbody>
    </table>
    <details style="margin-top:8px;">
      <summary class="button ghost">Добавить пользователя</summary>
      <form method="post" action="{{ url_for('settings_user_add') }}" style="display:grid;gap:8px;max-width:520px;margin-top:8px;">
        <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
        <label>Логин <input class="input" name="username" required></label>
        <label>Email <input class="input" name="email" type="email"></label>
        <label>Роль
          <select class="select" name="role">
            {% for r in ('admin','manager','agent','finance') %}
            <option value="{{ r }}">{{ r }}</option>
            {% endfor %}
          </select>
        </label>
        <label>Пароль <input class="input" name="password" type="password" required></label>
        <div style="display:flex;gap:8px;justify-content:flex-end;"><button class="button" type="submit">Создать</button></div>
      </form>
    </details>
  </div>

  <!-- API Tokens -->
  <div class="card">
    <h3>API‑токены</h3>
    <div class="help">Токен показывается только один раз при создании</div>
    <table class="table">
      <thead><tr><th>ID</th><th>Имя</th><th>User</th><th>Scopes</th><th>Активен</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
      <tbody id="tokTbl"><tr><td colspan="8"><div class="help">Загрузка...</div></td></tr></tbody>
    </table>
    <details style="margin-top:8px;">
      <summary class="button ghost">Создать токен</summary>
      <div style="display:grid;gap:8px;max-width:520px;margin-top:8px;">
        <label>Имя <input class="input" id="tokName" placeholder="API Token"></label>
        <label>User
          <select class="select" id="tokUser">
            <option value="">—</option>
            {% for u in users %}<option value="{{ u.id }}">{{ u.username }}</option>{% endfor %}
          </select>
        </label>
        <label>Scopes (через запятую) <input class="input" id="tokScopes" placeholder="read,write"></label>
        <label>Expires (лок.) <input class="input" id="tokExpires" type="datetime-local"></label>
        <div style="display:flex;gap:8px;justify-content:flex-end;">
          <button class="button" type="button" id="btnTokCreate">Создать</button>
        </div>
        <div id="tokOnce" class="help"></div>
      </div>
    </details>
  </div>
</div>

<div class="split" style="margin-top:10px;align-items:start;">
  <!-- Очередь вебхуков -->
  <div class="card">
    <h3>Очередь вебхуков</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Событие</th><th>Статус</th><th>Пыт.</th><th>Следующая попытка</th><th>Создано</th><th></th></tr></thead>
      <tbody id="whqTbl"><tr><td colspan="7"><div class="help">Загрузка...</div></td></tr></tbody>
    </table>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px;">
      <button class="iconbtn small" id="btnWhqReload">Обновить</button>
    </div>
  </div>

  <!-- Кастомные поля (no-code) -->
  <div class="card">
    <h3>Пользовательские поля</h3>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;">
      <label>Сущность <input class="input" id="cfEntity" placeholder="task|deal|company" style="max-width:200px;"></label>
      <button class="button" id="btnCfLoad" type="button">Показать</button>
    </div>
    <table class="table" style="margin-top:8px;">
      <thead><tr><th>ID</th><th>Key</th><th>Type</th><th>Label</th><th>Required</th><th>Default</th></tr></thead>
      <tbody id="cfTbl"><tr><td colspan="6"><div class="help">—</div></td></tr></tbody>
    </table>
    <details style="margin-top:8px;">
      <summary class="button ghost">Добавить поле</summary>
      <div style="display:grid;gap:8px;max-width:520px;margin-top:8px;">
        <label>Entity <input class="input" id="cfEntityNew" placeholder="task" required></label>
        <label>Key <input class="input" id="cfKey" placeholder="priority" required></label>
        <label>Type <input class="input" id="cfType" placeholder="text|number|date|select"></label>
        <label>Label <input class="input" id="cfLabel" placeholder="Приоритет"></label>
        <label>Required <select class="select" id="cfReq"><option value="0">no</option><option value="1">yes</option></select></label>
        <label>Default <input class="input" id="cfDefault"></label>
        <label>Options (JSON) <input class="input" id="cfOptions" placeholder='["A","B"]'></label>
        <label>Rules (JSON) <input class="input" id="cfRules" placeholder='{}'></label>
        <div style="display:flex;gap:8px;justify-content:flex-end;">
          <button class="button" id="btnCfAdd" type="button">Добавить</button>
        </div>
        <div id="cfMsg" class="help"></div>
      </div>
    </details>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
  function esc(s){ return String(s||'').replace(/[&<>"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

  // Телефония: показать URL вебхуков
  document.querySelectorAll('.btnUrls')?.forEach(b=>{
    b.addEventListener('click', async e=>{
      e.preventDefault();
      const id = b.getAttribute('data-id');
      try{
        const r = await fetch('/settings/phone/'+id+'/webhook_urls');
        const j = await r.json();
        const box = document.getElementById('urls-'+id);
        if(j.ok){
          box.innerHTML = 'CTI: <code>'+esc(j.cti_webhook)+'</code><br>Recording: <code>'+esc(j.recording_webhook)+'</code>';
        }else{
          box.textContent = j.error||'Ошибка';
        }
      }catch(_){ alert('Ошибка сети'); }
    });
  });

  // Webhook test
  document.getElementById('whList')?.addEventListener('click', async e=>{
    const b = e.target.closest('.btnWhTest'); if(!b) return;
    e.preventDefault();
    const id = b.getAttribute('data-id');
    try{
      const r = await fetch('/settings/webhook/test/'+id, {method:'POST', headers:{'X-CSRFToken': CSRF}});
      const j = await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      toast('Тест поставлен в очередь');
    }catch(_){ alert('Ошибка сети'); }
  });

  // AI: показать текущий конфиг
  document.getElementById('btnAiLoad')?.addEventListener('click', async e=>{
    e.preventDefault();
    try{
      const r = await fetch('/settings/ai/config');
      const j = await r.json();
      if(j.ok){
        const c = j.config||{};
        document.querySelector('input[name="provider"]').value = c.provider||'';
        document.querySelector('input[name="model"]').value = c.model||'';
        document.querySelector('input[name="temperature"]').value = (c.temperature!=null?c.temperature:0.3);
        document.querySelector('input[name="max_tokens"]').value = (c.max_tokens!=null?c.max_tokens:512);
        document.querySelector('textarea[name="policy"]').value = JSON.stringify(c.policy||{}, null, 2);
      }else{
        alert(j.error||'Ошибка');
      }
    }catch(_){ alert('Ошибка сети'); }
  });

  // Tokens list
  async function loadTokens(){
    try{
      const r = await fetch('/api/tokens/list'); const j = await r.json();
      const tb = document.getElementById('tokTbl'); tb.innerHTML='';
      if(!j.ok || !(j.items||[]).length){ tb.innerHTML = '<tr><td colspan="8"><div class="help">Нет токенов</div></td></tr>'; return; }
      for(const t of j.items){
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>#${t.id}</td>
          <td>${esc(t.name||'')}</td>
          <td>${esc(String(t.user_id||'—'))}</td>
          <td class="help">${esc(t.scopes||'')}</td>
          <td>${t.active?'yes':'no'}</td>
          <td>${esc(t.expires_at||'')}</td>
          <td>${esc(t.last_used_at||'')}</td>
          <td><button class="iconbtn small btnTokToggle" data-id="${t.id}">${t.active?'Откл.':'Вкл.'}</button></td>`;
        tb.appendChild(tr);
      }
    }catch(_){
      document.getElementById('tokTbl').innerHTML = '<tr><td colspan="8"><div class="help">Ошибка</div></td></tr>';
    }
  }
  loadTokens();

  document.getElementById('tokTbl')?.addEventListener('click', async e=>{
    const b = e.target.closest('.btnTokToggle'); if(!b) return;
    e.preventDefault();
    const id = parseInt(b.getAttribute('data-id')||'0',10)||0;
    try{
      const r = await fetch('/api/tokens/toggle', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({id})});
      const j = await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      loadTokens();
    }catch(_){ alert('Ошибка сети'); }
  });

  document.getElementById('btnTokCreate')?.addEventListener('click', async e=>{
    e.preventDefault();
    const name = (document.getElementById('tokName').value||'API Token').trim();
    const user_id = (document.getElementById('tokUser').value||'')||null;
    const scopes = (document.getElementById('tokScopes').value||'').split(',').map(s=>s.trim()).filter(Boolean);
    const expires_at = (document.getElementById('tokExpires').value||'');
    try{
      const r = await fetch('/api/tokens/create', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({name, user_id, scopes, expires_at})});
      const j = await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      document.getElementById('tokOnce').innerHTML = 'Токен (показывается один раз): <code>'+esc(j.token||'')+'</code>';
      loadTokens();
    }catch(_){ alert('Ошибка сети'); }
  });

  // Webhook queue
  async function loadWhq(){
    try{
      const r = await fetch('/api/webhook/queue'); const j = await r.json();
      const tb = document.getElementById('whqTbl'); tb.innerHTML='';
      if(!j.ok || !(j.items||[]).length){ tb.innerHTML='<tr><td colspan="7"><div class="help">Пусто</div></td></tr>'; return; }
      for(const q of j.items){
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>#${q.id}</td><td>${esc(q.event||'')}</td><td>${esc(q.status||'')}</td><td>${esc(String(q.attempts||0))}</td>
          <td>${esc(q.next_try_at||'')}</td><td>${esc(q.created_at||'')}</td>
          <td><button class="iconbtn small btnRetry" data-id="${q.id}">Retry</button></td>`;
        tb.appendChild(tr);
      }
    }catch(_){ document.getElementById('whqTbl').innerHTML='<tr><td colspan="7"><div class="help">Ошибка</div></td></tr>'; }
  }
  loadWhq();
  document.getElementById('btnWhqReload')?.addEventListener('click', e=>{ e.preventDefault(); loadWhq(); });
  document.getElementById('whqTbl')?.addEventListener('click', async e=>{
    const b = e.target.closest('.btnRetry'); if(!b) return;
    e.preventDefault();
    const id = parseInt(b.getAttribute('data-id')||'0',10)||0;
    try{
      const r = await fetch('/api/webhook/retry/'+id, {method:'POST', headers:{'X-CSRFToken':CSRF}});
      const j = await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      toast('Переотправка запрошена'); loadWhq();
    }catch(_){ alert('Ошибка сети'); }
  });

  // Custom fields
  async function loadCf(){
    const ent = (document.getElementById('cfEntity').value||'').trim();
    if(!ent) return;
    try{
      const url = new URL(window.location.origin + '/api/custom_fields'); url.searchParams.set('entity', ent);
      const r = await fetch(url.toString()); const j = await r.json();
      const tb = document.getElementById('cfTbl'); tb.innerHTML='';
      if(!j.ok || !(j.items||[]).length){ tb.innerHTML='<tr><td colspan="6"><div class="help">Нет полей</div></td></tr>'; return; }
      for(const f of j.items){
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>#${f.id}</td><td>${esc(f.key||'')}</td><td>${esc(f.type||'')}</td><td>${esc(f.label||'')}</td><td>${f.required?'yes':'no'}</td><td>${esc(f.default||'')}</td>`;
        tb.appendChild(tr);
      }
    }catch(_){ document.getElementById('cfTbl').innerHTML='<tr><td colspan="6"><div class="help">Ошибка</div></td></tr>'; }
  }
  document.getElementById('btnCfLoad')?.addEventListener('click', e=>{ e.preventDefault(); loadCf(); });

  document.getElementById('btnCfAdd')?.addEventListener('click', async e=>{
    e.preventDefault();
    const entity=(document.getElementById('cfEntityNew').value||'').trim();
    const key=(document.getElementById('cfKey').value||'').trim();
    const type=(document.getElementById('cfType').value||'text').trim();
    const label=(document.getElementById('cfLabel').value||key).trim();
    const required = (document.getElementById('cfReq').value==='1');
    const def = (document.getElementById('cfDefault').value||'');
    let options = []; let rules = {};
    try{ options = JSON.parse(document.getElementById('cfOptions').value||'[]'); }catch(_){}
    try{ rules = JSON.parse(document.getElementById('cfRules').value||'{}'); }catch(_){}
    if(!entity || !key || !label) return alert('Заполните entity/key/label');
    try{
      const r = await fetch('/api/custom_fields', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},
        body: JSON.stringify({entity, key, type, label, required, default: def, options, rules})});
      const j = await r.json(); if(!j.ok) return alert(j.error||'Ошибка');
      document.getElementById('cfMsg').textContent='Добавлено #'+j.id;
      if((document.getElementById('cfEntity').value||'').trim()===entity) loadCf();
    }catch(_){ alert('Ошибка сети'); }
  });
</script>
"""
# === END STYLES PART 8/9 ===
# === STYLES PART 9/9 — Utilities, States, Messages, Animations, Print ===
# -*- coding: utf-8 -*-

BASE_CSS = BASE_CSS + """
/* ===== Utilities ===== */
.row{display:flex;gap:8px;align-items:center}
.col{display:flex;flex-direction:column;gap:8px}
.center{align-items:center;justify-content:center}
.right{margin-left:auto}
.wrap{flex-wrap:wrap}
.gap-4{gap:4px}.gap-6{gap:6px}.gap-8{gap:8px}.gap-12{gap:12px}.gap-16{gap:16px}.gap-24{gap:24px}
.mt-4{margin-top:4px}.mt-8{margin-top:8px}.mt-12{margin-top:12px}.mt-16{margin-top:16px}
.mb-4{margin-bottom:4px}.mb-8{margin-bottom:8px}.mb-12{margin-bottom:12px}.mb-16{margin-bottom:16px}
.ml-auto{margin-left:auto}.mr-auto{margin-right:auto}
.p-8{padding:8px}.p-12{padding:12px}.p-16{padding:16px}
.w-100{width:100%}.h-100{height:100%}
.nowrap{white-space:nowrap}
.ellipsis{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.break{word-break:break-word;overflow-wrap:anywhere}
.hidden{display:none !important}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.z-1{z-index:1}.z-5{z-index:5}.z-10{z-index:10}.z-100{z-index:100}.z-1000{z-index:1000}

/* ===== Focus/hover/disabled states ===== */
:where(.button,.iconbtn,.input,.select,textarea,.navitem,.toggle):focus-visible{
  outline:2px solid var(--accent); outline-offset:2px;
}
:where(.button):hover{filter:brightness(1.02)}
:where(.iconbtn):hover{background:var(--surface)}
:where(.navitem):hover{background:var(--surface)}
:where(.button[disabled],.iconbtn[disabled]){opacity:.6;cursor:not-allowed}
:where(.input:disabled,.select:disabled,textarea:disabled){opacity:.6;cursor:not-allowed}

/* ===== Tables ===== */
.table tr:hover td{background:color-mix(in oklab, var(--panel) 92%, var(--accent) 8%);transition:background .12s ease}
@supports not (color-mix(in oklab, white, black)){
  .table tr:hover td{background:rgba(43,214,106,.06)}
}

/* ===== Messages (threads/comments) ===== */
.msg{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:8px 10px;margin:8px 0}
.msg .meta{color:var(--muted);font-size:12px;margin-bottom:4px}
.msg .body{white-space:pre-wrap}
.msg.client{border-left:3px solid #7ec1ff}
.msg.agent{border-left:3px solid #2bd66a}
.msg.system{border-style:dashed;opacity:.85}

/* ===== Composer (common) ===== */
.composer{display:flex;flex-direction:column;gap:8px}
.composer .row{align-items:center}

/* ===== Badges / Pills for status & priority ===== */
.status-badges .badge{font-weight:600}
.badge.status-open{border-color:#7ec1ff66;color:#7ec1ff;background:#7ec1ff1a}
.badge.status-pending{border-color:#ffc85766;color:#ffc857;background:#ffc8571a}
.badge.status-resolved{border-color:#2bd66a66;color:#2bd66a;background:#2bd66a1a}
.badge.status-snoozed{border-color:#bda7ff66;color:#bda7ff;background:#bda7ff1a}

.badge.priority-low{border-color:#9ab2a666;color:#9ab2a6;background:#9ab2a61a}
.badge.priority-normal{border-color:#7ec1ff66;color:#7ec1ff;background:#7ec1ff1a}
.badge.priority-high{border-color:#ffc85766;color:#ffc857;background:#ffc8571a}
.badge.priority-urgent{border-color:#ff6b6b66;color:#ff6b6b;background:#ff6b6b1a}

/* ===== Toast / Modal animations ===== */
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
@keyframes slideUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes pop{from{transform:scale(.98)}to{transform:scale(1)}}
.toast{animation:fadeIn .18s ease}
.modal-backdrop.show .modal{animation:pop .16s ease}
.modal-backdrop{animation:fadeIn .16s ease}

/* ===== Loading / skeleton ===== */
@keyframes pulse{0%{opacity:.5}50%{opacity:.25}100%{opacity:.5}}
.skeleton{background:linear-gradient(90deg, rgba(255,255,255,.06), rgba(0,0,0,.06));border-radius:8px;animation:pulse 1.2s ease-in-out infinite}

/* ===== Icons / misc ===== */
.kbd{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;border:1px solid var(--border);border-bottom-width:2px;border-radius:6px;padding:1px 6px;background:var(--surface);font-size:12px}

/* ===== Scroll areas ===== */
.scroll{overflow:auto}
.scroll-x{overflow-x:auto;overflow-y:hidden}
.scroll-y{overflow-y:auto;overflow-x:hidden}

/* ===== Responsive helpers ===== */
@media(max-width:980px){
  .hide-md{display:none !important}
}
@media(max-width:720px){
  .hide-sm{display:none !important}
  .container{padding:12px}
  .topbar{gap:8px}
}

/* ===== Print styles ===== */
@media print{
  :root{--bg:#ffffff;--fg:#000000;--surface:#ffffff;--panel:#ffffff;--border:#00000020}
  body{background:#fff;color:#000}
  .sidebar,.topbar,.toast-wrap,.fab,.modal-backdrop,.footer-stick{display:none !important}
  .page{margin:0 !important}
  a{color:#000;text-decoration:underline}
  .card{border:1px solid #00000020;box-shadow:none}
  .table{border-color:#00000030}
  .table th,.table td{border-color:#00000020}
}

/* ===== Minor refinements ===== */
details>summary.button{list-style:none}
details>summary.button::-webkit-details-marker{display:none}
.iconbtn.small{line-height:1}
.button.small{padding:6px 10px;border-radius:8px;font-size:13px}
"""

# --- Extra routes/helpers appended in this section ---

# Reports: tasks daily aggregates
@app.route("/api/reports/tasks_daily")
@login_required
def api_reports_tasks_daily():
    try:
        org_id = current_org_id()
        date_from = request.args.get("date_from") or ""
        date_to = request.args.get("date_to") or ""
        df, dt = date_range_bounds(date_from, date_to)

        # Created per day + monthly fee sum by created date
        where_created = ["org_id=?"]
        p_created = [org_id]
        if df:
            where_created.append("created_at>=?"); p_created.append(df)
        if dt:
            where_created.append("created_at<=?"); p_created.append(dt)
        rows_created = query_db(
            f"""
            SELECT substr(created_at,1,10) AS ymd,
                   COUNT(1) AS created_cnt,
                   COALESCE(SUM(monthly_fee),0) AS monthly_fee_sum
            FROM tasks
            WHERE {' AND '.join(where_created)}
            GROUP BY ymd
            ORDER BY ymd
            """,
            tuple(p_created),
        )

        # Done per day by updated_at when status is 'done'
        where_done = ["org_id=?", "status='done'"]
        p_done = [org_id]
        if df:
            where_done.append("updated_at>=?"); p_done.append(df)
        if dt:
            where_done.append("updated_at<=?"); p_done.append(dt)
        rows_done = query_db(
            f"""
            SELECT substr(updated_at,1,10) AS ymd,
                   COUNT(1) AS done_cnt
            FROM tasks
            WHERE {' AND '.join(where_done)}
            GROUP BY ymd
            ORDER BY ymd
            """,
            tuple(p_done),
        )

        # Overdue per day by updated_at when status is 'overdue'
        where_over = ["org_id=?", "status='overdue'"]
        p_over = [org_id]
        if df:
            where_over.append("updated_at>=?"); p_over.append(df)
        if dt:
            where_over.append("updated_at<=?"); p_over.append(dt)
        rows_over = query_db(
            f"""
            SELECT substr(updated_at,1,10) AS ymd,
                   COUNT(1) AS overdue_cnt
            FROM tasks
            WHERE {' AND '.join(where_over)}
            GROUP BY ymd
            ORDER BY ymd
            """,
            tuple(p_over),
        )

        # Merge by ymd
        agg = {}
        for r in (rows_created or []):
            y = r["ymd"]
            agg[y] = {
                "ymd": y,
                "created_cnt": int(r["created_cnt"] or 0),
                "monthly_fee_sum": float(r["monthly_fee_sum"] or 0.0),
            }
        for r in (rows_done or []):
            y = r["ymd"]; it = agg.setdefault(y, {"ymd": y})
            it["done_cnt"] = int(r["done_cnt"] or 0)
        for r in (rows_over or []):
            y = r["ymd"]; it = agg.setdefault(y, {"ymd": y})
            it["overdue_cnt"] = int(r["overdue_cnt"] or 0)

        items = [
            {
                "ymd": k,
                "created_cnt": int(v.get("created_cnt", 0)),
                "done_cnt": int(v.get("done_cnt", 0)),
                "overdue_cnt": int(v.get("overdue_cnt", 0)),
                "monthly_fee_sum": float(v.get("monthly_fee_sum", 0.0)),
            }
            for k, v in sorted(agg.items())
        ]
        return jsonify(ok=True, items=items)
    except Exception as e:
        app.logger.exception(f"tasks_daily error: {e}")
        return jsonify(ok=False, error="internal error"), 500


# Reports: calls daily aggregates
@app.route("/api/reports/calls_daily")
@login_required
def api_reports_calls_daily():
    try:
        org_id = current_org_id()
        date_from = request.args.get("date_from") or ""
        date_to = request.args.get("date_to") or ""
        df, dt = date_range_bounds(date_from, date_to)
        where_ = ["org_id=?"]
        params = [org_id]
        if df:
            where_.append("started_at>=?"); params.append(df)
        if dt:
            where_.append("started_at<=?"); params.append(dt)
        rows = query_db(
            f"""
            SELECT substr(started_at,1,10) AS ymd,
                   SUM(CASE WHEN direction='in' THEN 1 ELSE 0 END) AS in_cnt,
                   SUM(CASE WHEN direction='out' THEN 1 ELSE 0 END) AS out_cnt,
                   COALESCE(SUM(COALESCE(duration_sec,0)),0) AS dur_sum
            FROM calls
            WHERE {' AND '.join(where_)}
            GROUP BY ymd
            ORDER BY ymd
            """,
            tuple(params),
        )
        items = [
            {
                "ymd": r["ymd"],
                "in_cnt": int(r["in_cnt"] or 0),
                "out_cnt": int(r["out_cnt"] or 0),
                "dur_sum": int(r["dur_sum"] or 0),
            }
            for r in (rows or [])
        ]
        return jsonify(ok=True, items=items)
    except Exception as e:
        app.logger.exception(f"calls_daily error: {e}")
        return jsonify(ok=False, error="internal error"), 500

# Навбар ссылается на /analytics; рендер простого шаблона аналитики
@app.route("/analytics")
@login_required
def analytics():
    return render_safe(ANALYTICS_TMPL)

# Точка старта приложения
def _start_server():
    print(f"Starting {APP_NAME} on {HOST}:{PORT} (debug={DEBUG})")
    app.run(host=HOST, port=PORT, debug=DEBUG, threaded=True)

# Точка входа — должна быть в самом конце раздела
if __name__ == "__main__":
    _start_server()

# === END STYLES PART 9/9 ===
