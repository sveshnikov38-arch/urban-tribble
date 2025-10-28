# ==================== CORE PART 1/10 ====================
# ===== BLOCK: IMPORTS & CONFIGURATION =====
import os
import sys
import re
import json
import uuid
import time
import hmac
import base64
import hashlib
import logging
import socket
import signal
import secrets
import threading
from io import BytesIO
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Optional, Callable, Dict, List, Tuple, Set
from collections import defaultdict
from queue import Queue, Empty, Full
from contextlib import contextmanager

from flask import (
    Flask, g, request, session, redirect, url_for, jsonify, Response,
    send_file, render_template_string, stream_with_context
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# ----- Optional deps (feature-gated) -----
try:
    import requests as _rq  # HTTP client
except Exception:
    _rq = None

try:
    import redis  # Redis client
    REDIS_AVAILABLE = True
except Exception:
    redis = None  # type: ignore
    REDIS_AVAILABLE = False

try:
    import sentry_sdk  # type: ignore
    from sentry_sdk.integrations.flask import FlaskIntegration  # type: ignore
    SENTRY_SDK_AVAILABLE = True
except Exception:
    sentry_sdk = None  # type: ignore
    FlaskIntegration = None  # type: ignore
    SENTRY_SDK_AVAILABLE = False

try:
    from opentelemetry import trace  # type: ignore
    from opentelemetry.instrumentation.flask import FlaskInstrumentor  # type: ignore
    from opentelemetry.instrumentation.requests import RequestsInstrumentor  # type: ignore
    OTEL_AVAILABLE = True
except Exception:
    trace = None  # type: ignore
    FlaskInstrumentor = None  # type: ignore
    RequestsInstrumentor = None  # type: ignore
    OTEL_AVAILABLE = False

try:
    from email_validator import validate_email as _ev_validate, EmailNotValidError  # type: ignore
    EMAIL_VALIDATOR_AVAILABLE = True
except Exception:
    _ev_validate = None  # type: ignore
    EmailNotValidError = Exception  # type: ignore
    EMAIL_VALIDATOR_AVAILABLE = False

# ----- Compatibility: app/module name -----
APP_NAME = __name__

# ----- Environment & App config -----
ENV = os.getenv("ENV", "development").lower()
DEBUG = ENV == "development"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
VERSION = "5.2.0"

# ----- Storage -----
STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local")  # local|s3
LOCAL_UPLOAD_DIR = os.getenv("LOCAL_UPLOAD_DIR", "./uploads")

# ----- Redis -----
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_REQUIRED = os.getenv("REDIS_REQUIRED", "false").lower() == "true"

# ----- Cache -----
CACHE_ENABLED = os.getenv("CACHE_ENABLED", "true").lower() == "true"
CACHE_DEFAULT_TTL = int(os.getenv("CACHE_DEFAULT_TTL", "60"))

# ----- AI -----
AI_PROVIDER = os.getenv("AI_PROVIDER", "openai")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")
AI_TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.3"))
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "1024"))
AI_MAX_RETRIES = int(os.getenv("AI_MAX_RETRIES", "3"))
AI_RETRY_BACKOFF_SECS = float(os.getenv("AI_RETRY_BACKOFF_SECS", "1.5"))
AI_CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("AI_CIRCUIT_BREAKER_THRESHOLD", "5"))
AI_CIRCUIT_BREAKER_TIMEOUT = int(os.getenv("AI_CIRCUIT_BREAKER_TIMEOUT", "60"))
AI_STREAMING_ENABLED = os.getenv("AI_STREAMING_ENABLED", "true").lower() == "true"
AI_SYNC_MODE = os.getenv("AI_SYNC_MODE", "false").lower() == "true"

# ----- SSE / Collaboration -----
SSE_ENABLED = os.getenv("SSE_ENABLED", "true").lower() == "true"
SSE_MAX_CONN_PER_USER = int(os.getenv("SSE_MAX_CONN_PER_USER", "3"))
WEBSOCKET_ENABLED = os.getenv("WEBSOCKET_ENABLED", "false").lower() == "true"
COLLABORATION_TIMEOUT = int(os.getenv("COLLABORATION_TIMEOUT", "300"))
SSE_BACKPLANE = os.getenv("SSE_BACKPLANE", "memory").lower()  # memory|redis

# ----- CSP / security / proxy -----
CSP_ENABLED = os.getenv("CSP_ENABLED", "true").lower() == "true"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = os.getenv("LOG_FORMAT", "json")  # json|text
PROXY_TRUSTED_COUNT = int(os.getenv("PROXY_TRUSTED_COUNT", "0"))
HSTS_ENABLED = os.getenv("HSTS_ENABLED", "true").lower() == "true"
HSTS_MAX_AGE = int(os.getenv("HSTS_MAX_AGE", str(31536000)))
HSTS_INCLUDE_SUBDOMAINS = os.getenv("HSTS_INCLUDE_SUBDOMAINS", "true").lower() == "true"
HSTS_PRELOAD = os.getenv("HSTS_PRELOAD", "false").lower() == "true"

# ----- Feature toggles -----
ZERO_CODE_AGENT_BUILDER_ENABLED = os.getenv("ZERO_CODE_AGENT_BUILDER_ENABLED", "true").lower() == "true"
LIVE_COLLAB_ENABLED = os.getenv("LIVE_COLLAB_ENABLED", "true").lower() == "true"
NOTIFICATION_CENTER_ENABLED = os.getenv("NOTIFICATION_CENTER_ENABLED", "true").lower() == "true"
CONVERSATIONAL_BI_ENABLED = os.getenv("CONVERSATIONAL_BI_ENABLED", "true").lower() == "true"
AUTONOMOUS_SALES_MODE_ENABLED = os.getenv("AUTONOMOUS_SALES_MODE_ENABLED", "false").lower() == "true"
DIGITAL_TWIN_DECISION_CENTER_ENABLED = os.getenv("DIGITAL_TWIN_DECISION_CENTER_ENABLED", "true").lower() == "true"
PAYROLL_ENABLED = os.getenv("PAYROLL_ENABLED", "true").lower() == "true"

# ----- Observability -----
OTEL_ENABLED = os.getenv("OTEL_ENABLED", "false").lower() == "true"
SENTRY_DSN = os.getenv("SENTRY_DSN", "")

# ----- Rate limiting -----
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
GLOBAL_RATE_LIMIT_PER_MIN = int(os.getenv("GLOBAL_RATE_LIMIT_PER_MIN", "900"))
LOGIN_RATE_LIMIT_PER_MIN = int(os.getenv("LOGIN_RATE_LIMIT_PER_MIN", "20"))
APPROVAL_RATE_LIMIT_PER_MIN = int(os.getenv("APPROVAL_RATE_LIMIT_PER_MIN", "60"))
RATE_LIMIT_MAX_KEYS = int(os.getenv("RATE_LIMIT_MAX_KEYS", "20000"))
RATE_LIMIT_CLEANUP_EVERY_SEC = int(os.getenv("RATE_LIMIT_CLEANUP_EVERY_SEC", "60"))

# ----- Misc -----
JITSI_BASE = os.getenv("JITSI_BASE", "https://meet.jit.si")

# ----- Security extras -----
ADMIN_2FA_BYPASS = os.getenv("ADMIN_2FA_BYPASS", "false").lower() == "true"

# ===== BLOCK: LOGGING & UTILITIES =====
class JSONFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "mod": record.module,
            "fn": record.funcName,
            "line": record.lineno,
        }
        rid = getattr(record, "request_id", None)
        if rid:
            data["request_id"] = rid
        try:
            return json.dumps(data, ensure_ascii=False)
        except Exception:
            return super().format(record)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(message)s" if LOG_FORMAT == "json" else "%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
if LOG_FORMAT == "json":
    for _h in logging.root.handlers:
        _h.setFormatter(JSONFormatter())

logger = logging.getLogger("crm")

def log(level: str, message: str, **kwargs):
    # Redact sensitive fields
    redact_keys = {"authorization", "password", "token", "secret", "api_key", "x-api-key", "set-cookie"}
    safe_kwargs: Dict[str, Any] = {}
    for k, v in (kwargs or {}).items():
        safe_kwargs[k] = "*" if str(k).lower() in redact_keys else v
    fn = {
        "DEBUG": logger.debug,
        "INFO": logger.info,
        "WARN": logger.warning,
        "ERROR": logger.error,
        "CRITICAL": logger.critical,
    }.get(level.upper(), logger.info)
    if LOG_FORMAT == "json":
        try:
            payload = {"message": message}
            payload.update(safe_kwargs)
            fn(json.dumps(payload, ensure_ascii=False))
        except Exception:
            fn(f"{message} | {safe_kwargs}")
    else:
        fn(f"{message} | {safe_kwargs}")

def utc_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def ensure_iso_datetime(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    t = str(s).strip().replace("T", " ").replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(t, fmt)
            if fmt == "%Y-%m-%d":
                dt = dt.replace(hour=0, minute=0, second=0)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
    try:
        dt = datetime.fromisoformat(t)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return t

def normalize_phone(phone: Optional[str]) -> str:
    if not phone:
        return ""
    digits = re.sub(r"\D", "", phone)
    if len(digits) == 11 and digits.startswith(("7", "8")):
        return "+7" + digits[-10:]
    if len(digits) == 10:
        return "+7" + digits
    if len(digits) > 10:
        return "+" + digits
    return phone or ""

def validate_email(val: Optional[str]) -> bool:
    if not val:
        return False
    if EMAIL_VALIDATOR_AVAILABLE and _ev_validate:
        try:
            _ev_validate(val, check_deliverability=False)  # type: ignore
            return True
        except EmailNotValidError:
            return False
    # Regex fallback (RFC-like, упрощённый) — экранируем точку
    return bool(re.fullmatch(r"^[A-Za-z0-9.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$", val or ""))

def generate_random_code(length: int = 6, charset: str = "0123456789") -> str:
    return "".join(secrets.choice(charset) for _ in range(length))

def generate_request_id() -> str:
    return uuid.uuid4().hex[:16]

def get_client_ip() -> str:
    try:
        if request.access_route:
            return request.access_route[0]
        return request.remote_addr or "0.0.0.0"
    except Exception:
        return "0.0.0.0"

def secure_equal(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return a == b

class TTLCache:
    """Simple in-memory TTL cache (thread-safe), used as L1 fallback."""
    def __init__(self):
        self._store: Dict[str, Tuple[Any, float]] = {}
        self._lock = threading.RLock()

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        if not CACHE_ENABLED:
            return
        exp = time.time() + float(ttl if ttl is not None else CACHE_DEFAULT_TTL)
        with self._lock:
            self._store[key] = (value, exp)

    def get(self, key: str) -> Optional[Any]:
        if not CACHE_ENABLED:
            return None
        with self._lock:
            it = self._store.get(key)
            if not it:
                return None
            val, exp = it
            if exp < time.time():
                self._store.pop(key, None)
                return None
            return val

    def delete(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def cleanup(self):
        with self._lock:
            now = time.time()
            for k, (_, exp) in list(self._store.items()):
                if exp < now:
                    self._store.pop(k, None)

_global_cache = TTLCache()

# ----- Password policy -----
def validate_password_strength(password: str) -> Tuple[bool, str]:
    pw = password or ""
    if len(pw) < 8:
        return False, "Пароль должен содержать минимум 8 символов"
    if not re.search(r"[A-Z]", pw):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"
    if not re.search(r"[a-z]", pw):
        return False, "Пароль должен содержать хотя бы одну строчную букву"
    if not re.search(r"[0-9]", pw):
        return False, "Пароль должен содержать хотя бы одну цифру"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pw):
        return False, "Пароль должен содержать хотя бы один спецсимвол"
    return True, ""

# ===== BLOCK: METRICS & OBSERVABILITY =====
_metrics_lock = threading.Lock()
_metrics: Dict[str, Any] = {
    "requests_total": 0,
    "requests_by_endpoint": defaultdict(int),
    "requests_by_status": defaultdict(int),
    "errors_total": 0,
    "api_calls_total": defaultdict(int),
    "sse_queue_len": defaultdict(int),
    "sse_dropped_total": 0,
    "rate_limit_exceeded": 0,
}

def _increment_metric(key: str, labels: Optional[dict] = None, value: int = 1):
    with _metrics_lock:
        if labels:
            bucket_key = frozenset(sorted(labels.items()))
            bucket = _metrics.get(key)
            if isinstance(bucket, (dict, defaultdict)):
                bucket[bucket_key] = bucket.get(bucket_key, 0) + value  # type: ignore
            else:
                _metrics[key] = _metrics.get(key, 0) + value
        else:
            _metrics[key] = _metrics.get(key, 0) + value

# ----- OpenTelemetry tracer (lazy init) -----
_tracer = None
def get_tracer():
    global _tracer
    if _tracer is None and OTEL_AVAILABLE and trace:
        try:
            _tracer = trace.get_tracer(APP_NAME)  # type: ignore
        except Exception:
            _tracer = None
    return _tracer

# ===== BLOCK: REDIS, CACHE & SSE =====
_redis_client = None
_redis_lock = threading.Lock()

class RedisCircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_threshold = int(failure_threshold)
        self.timeout = int(timeout)
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "closed"  # closed|open|half-open
        self._lock = threading.Lock()

    def call(self, func, *args, **kwargs):
        with self._lock:
            now = time.time()
            if self.state == "open":
                if now - self.last_failure_time > self.timeout:
                    self.state = "half-open"
                else:
                    raise RuntimeError("Redis circuit is OPEN")
        try:
            res = func(*args, **kwargs)
            with self._lock:
                if self.state in ("open", "half-open"):
                    self.state = "closed"
                    self.failure_count = 0
            return res
        except Exception as e:
            with self._lock:
                self.failure_count += 1
                self.last_failure_time = time.time()
                if self.failure_count >= self.failure_threshold:
                    self.state = "open"
                    log("ERROR", "Redis circuit opened", failures=self.failure_count)
            raise e

_redis_cb = RedisCircuitBreaker(failure_threshold=5, timeout=60)

def get_redis():
    global _redis_client
    if not REDIS_AVAILABLE or not redis:
        return None
    with _redis_lock:
        if _redis_client is None:
            try:
                _redis_client = redis.from_url(  # type: ignore
                    REDIS_URL, decode_responses=True, socket_timeout=5, socket_connect_timeout=5
                )
                _redis_cb.call(_redis_client.ping)
                log("INFO", "Redis connected", url=REDIS_URL)
            except Exception as e:
                log("WARN", "Redis connection failed", error=str(e))
                if REDIS_REQUIRED:
                    raise RuntimeError("Redis required but unavailable")
                return None
    return _redis_client

def redis_get(key: str) -> Optional[str]:
    r = get_redis()
    if not r:
        return None
    try:
        return _redis_cb.call(r.get, key)
    except Exception:
        return None

def redis_setex(key: str, ttl: int, value: str) -> bool:
    r = get_redis()
    if not r:
        return False
    try:
        _redis_cb.call(r.setex, key, ttl, value)
        return True
    except Exception:
        return False

# ===== Rate limiting (IP or user-based) =====
_rate_lock = threading.Lock()
_rate_buckets: Dict[str, List[float]] = {}
_rate_last_cleanup = 0.0

def rate_limit_allow(key: str, per_min: int) -> bool:
    if not RATE_LIMIT_ENABLED or per_min <= 0:
        return True
    now = time.time()
    r = get_redis()
    if r:
        try:
            rk = f"rl:{key}:{int(now//60)}"
            cnt = _redis_cb.call(r.incr, rk)
            if int(cnt) == 1:
                _redis_cb.call(r.expire, rk, 120)
            return int(cnt) <= per_min
        except Exception as e:
            log("WARN", "Redis rate limit error", error=str(e))
    global _rate_last_cleanup
    with _rate_lock:
        if (now - _rate_last_cleanup) > RATE_LIMIT_CLEANUP_EVERY_SEC and len(_rate_buckets) > RATE_LIMIT_MAX_KEYS:
            stale_before = now - 180
            for k2 in list(_rate_buckets.keys()):
                lst = [t for t in _rate_buckets[k2] if t >= stale_before]
                if lst:
                    _rate_buckets[k2] = lst[-100:]
                else:
                    _rate_buckets.pop(k2, None)
            _rate_last_cleanup = now
        lst = _rate_buckets.setdefault(key, [])
        cutoff = now - 60
        lst = [t for t in lst if t >= cutoff]
        if len(lst) >= per_min:
            _rate_buckets[key] = lst
            _increment_metric("rate_limit_exceeded")
            return False
        lst.append(now)
        _rate_buckets[key] = lst
        return True

def _rate_limit(prefix: str, per_min: int):
    def deco(f):
        @wraps(f)
        def wrapped(*a, **kw):
            uid = g.get("user", {}).get("id", "anon") if g.get("user") else "anon"
            ip = get_client_ip()
            key = f"{prefix}:{uid}:{ip}"
            if not rate_limit_allow(key, per_min):
                return jsonify(ok=False, error="Rate limit exceeded"), 429
            return f(*a, **kw)
        return wrapped
    return deco

def _rate_limit_ip(prefix: str, per_min: int):
    def deco(f):
        @wraps(f)
        def wrapped(*a, **kw):
            ip = get_client_ip()
            key = f"{prefix}:{ip}"
            if not rate_limit_allow(key, per_min):
                return jsonify(ok=False, error="Rate limit exceeded"), 429
            return f(*a, **kw)
        return wrapped
    return deco

def _ratelimit_housekeeping():
    """Housekeeping для in-memory rate limit buckets (вызывается воркером)."""
    now = time.time()
    stale_before = now - 180
    with _rate_lock:
        for k, lst in list(_rate_buckets.items()):
            nlst = [t for t in lst if t >= stale_before]
            if nlst:
                _rate_buckets[k] = nlst[-100:]
            else:
                _rate_buckets.pop(k, None)

# ===== SSE backplane =====
_sse_lock = threading.Lock()
_sse_queues: Dict[int, List[Queue]] = {}
_sse_pubsub_thread: Optional[threading.Thread] = None
_sse_stop_event = threading.Event()

def _sse_publish_redis(user_id: int, event: str, data: dict):
    r = get_redis()
    if not r:
        return
    try:
        payload = json.dumps({"user_id": int(user_id), "event": event, "data": data}, ensure_ascii=False)
        _redis_cb.call(r.publish, "sse:events", payload)
    except Exception as e:
        log("WARN", "SSE publish failed", error=str(e))

def _sse_subscriber_loop():
    r = get_redis()
    if not r:
        return
    try:
        p = r.pubsub(ignore_subscribe_messages=True)  # type: ignore
        p.subscribe("sse:events")  # type: ignore
        for msg in p.listen():  # type: ignore
            if _sse_stop_event.is_set():
                break
            try:
                if msg and msg.get("type") == "message":
                    raw = msg.get("data")
                    if not raw:
                        continue
                    obj = json.loads(raw)
                    uid = int(obj.get("user_id") or 0)
                    if not uid:
                        continue
                    with _sse_lock:
                        qs = _sse_queues.get(uid, [])
                        for q in qs:
                            item = {"event": obj.get("event"), "data": obj.get("data")}
                            try:
                                q.put_nowait(item)
                            except Full:
                                try:
                                    _ = q.get_nowait()
                                    _increment_metric("sse_dropped_total")
                                except Empty:
                                    pass
                                try:
                                    q.put_nowait(item)
                                except Full:
                                    _increment_metric("sse_dropped_total")
            except Exception:
                continue
    except Exception as e:
        log("WARN", "SSE subscriber error", error=str(e))

def sse_backplane_start():
    global _sse_pubsub_thread
    if SSE_BACKPLANE == "redis" and REDIS_AVAILABLE and _sse_pubsub_thread is None:
        try:
            _sse_pubsub_thread = threading.Thread(target=_sse_subscriber_loop, daemon=True, name="sse_subscriber")
            _sse_pubsub_thread.start()
            log("INFO", "SSE Redis backplane started")
        except Exception as e:
            log("WARN", "SSE backplane start failed", error=str(e))

def sse_push(user_id: int, event: str, data: dict):
    if not SSE_ENABLED:
        return
    uid = int(user_id)
    with _sse_lock:
        qs = _sse_queues.get(uid, [])
        try:
            _increment_metric("sse_queue_len", {"user": str(uid)})
        except Exception:
            pass
        for q in qs:
            item = {"event": event, "data": data}
            try:
                q.put_nowait(item)
            except Full:
                try:
                    _ = q.get_nowait()
                    _increment_metric("sse_dropped_total")
                except Empty:
                    pass
                try:
                    q.put_nowait(item)
                except Full:
                    _increment_metric("sse_dropped_total")
    if SSE_BACKPLANE == "redis" and REDIS_AVAILABLE:
        _sse_publish_redis(uid, event, data)

# ===== BLOCK: FLASK INIT & MIDDLEWARE =====
app = Flask(APP_NAME)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_SIZE", str(50 * 1024 * 1024)))
app.url_map.strict_slashes = False

# ---- Flask 3.1+ compatibility: emulate before_first_request if missing ----
if not hasattr(app, "before_first_request"):
    _ffr_called_flag = {"done": False}

    def _before_first_request_shim(fn):
        @wraps(fn)
        def _run_once_wrapper():
            if not _ffr_called_flag["done"]:
                _ffr_called_flag["done"] = True
                try:
                    fn()
                except Exception as e:
                    log("ERROR", "Bootstrap hook failed (shim)", error=str(e))
            return None
        app.before_request(_run_once_wrapper)
        return fn  # return original function as decorator contract
    app.before_first_request = _before_first_request_shim  # type: ignore
# ---- end of compatibility shim ----

# ----- Session / Cookies -----
if ENV == "production":
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    )
else:
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
        TESTING=False,
    )

# ----- Proxy -----
if PROXY_TRUSTED_COUNT > 0:
    app.wsgi_app = ProxyFix(  # type: ignore
        app.wsgi_app,
        x_for=PROXY_TRUSTED_COUNT,
        x_proto=PROXY_TRUSTED_COUNT,
        x_host=PROXY_TRUSTED_COUNT,
        x_port=PROXY_TRUSTED_COUNT,
        x_prefix=0,
    )

# ----- Sentry -----
if SENTRY_DSN and SENTRY_SDK_AVAILABLE and sentry_sdk and FlaskIntegration:
    try:
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            integrations=[FlaskIntegration()],
            traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.1")),
            environment=ENV,
            release=f"crm-erp@{VERSION}",
        )
        log("INFO", "Sentry enabled")
    except Exception as e:
        log("WARN", "Sentry init failed", error=str(e))

# ----- OTEL -----
if OTEL_ENABLED and OTEL_AVAILABLE and FlaskInstrumentor and RequestsInstrumentor:
    try:
        FlaskInstrumentor().instrument_app(app)  # type: ignore
        RequestsInstrumentor().instrument()  # type: ignore
        log("INFO", "OpenTelemetry instrumentation enabled")
    except Exception as e:
        log("WARN", "OpenTelemetry init failed", error=str(e))

# ----- Request Timeout middleware -----
class TimeoutMiddleware:
    def __init__(self, wsgi_app, timeout=30):
        self.app = wsgi_app
        self.timeout = int(timeout)

    def __call__(self, environ, start_response):
        # Безопасная работа стримов: не применять SIGALRM к SSE/аудиозаписям
        path = (environ.get("PATH_INFO") or "").strip()
        if path.startswith("/sse") or path.startswith("/cti/recording"):
            return self.app(environ, start_response)

        # SIGALRM только в главном потоке на Unix-подобных системах
        if hasattr(signal, "SIGALRM") and threading.current_thread() is threading.main_thread():
            def timeout_handler(signum, frame):  # pragma: no cover
                raise TimeoutError("Request exceeded timeout")

            prev_handler = None
            try:
                prev_handler = signal.getsignal(signal.SIGALRM)
            except Exception:
                prev_handler = None

            try:
                signal.signal(signal.SIGALRM, timeout_handler)  # type: ignore
                signal.alarm(self.timeout)  # type: ignore
                return self.app(environ, start_response)
            finally:
                try:
                    signal.alarm(0)  # type: ignore
                except Exception:
                    pass
                if prev_handler is not None:
                    try:
                        signal.signal(signal.SIGALRM, prev_handler)  # type: ignore
                    except Exception:
                        pass
        else:
            return self.app(environ, start_response)

app.wsgi_app = TimeoutMiddleware(app.wsgi_app, timeout=int(os.getenv("REQUEST_TIMEOUT", "30")))

# ----- CSP builder -----
def build_csp(nonce: str) -> str:
    if not CSP_ENABLED:
        return ""
    dev_inline = ENV != "production"
    script_src = f"'self' 'nonce-{nonce}'"
    if dev_inline:
        script_src += " 'unsafe-inline'"
    connect_src = "'self' https: wss:"
    # keep style inline allowed to avoid CSP breakage with inline <style> in templates
    style_src = "'self' 'unsafe-inline'"
    img_src = "'self' data: https:"
    font_src = "'self' data:"
    frame_src = f"'self' {JITSI_BASE}"
    return (
        "default-src 'self'; "
        f"script-src {script_src}; "
        f"style-src {style_src}; "
        f"img-src {img_src}; "
        f"font-src {font_src}; "
        f"connect-src {connect_src}; "
        f"frame-src {frame_src}; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self'; "
        "form-action 'self'"
    )

@app.before_request
def _before_request():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    # set issued_at for session lifecycle enforcement
    if "issued_at" not in session:
        session["issued_at"] = utc_now()
    g.request_start_time = time.time()
    g.csp_nonce = secrets.token_hex(16)
    g.request_id = request.headers.get("X-Request-ID") or generate_request_id()
    g.idempotency_key = request.headers.get("Idempotency-Key") or ""
    _increment_metric("requests_total")
    try:
        _increment_metric("requests_by_endpoint", {"endpoint": request.endpoint or "unknown"})
    except Exception:
        pass
    # session revocation enforcement
    try:
        uid = session.get("user_id")
        if uid:
            revoked_at = None
            r = get_redis()
            if r:
                try:
                    revoked_at = _redis_cb.call(r.get, f"session_revoked_at:{int(uid)}")
                except Exception:
                    revoked_at = None
            if revoked_at is None:
                revoked_at = _global_cache.get(f"session_revoked_at:{int(uid)}")
            if revoked_at and session.get("issued_at") and str(revoked_at) > str(session.get("issued_at")):
                session.clear()
                if request.path.startswith("/api/"):
                    return jsonify(ok=False, error="Session revoked"), 401
                return redirect(url_for("login"))
    except Exception:
        pass

@app.after_request
def _after_request(resp: Response):
    try:
        if hasattr(g, "request_start_time"):
            duration = time.time() - g.request_start_time
            resp.headers["X-Request-Duration"] = f"{duration:.3f}"
        resp.headers["X-Request-ID"] = getattr(g, "request_id", generate_request_id())
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "SAMEORIGIN"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["X-XSS-Protection"] = "0"
        if HSTS_ENABLED:
            hsts = f"max-age={HSTS_MAX_AGE}"
            if HSTS_INCLUDE_SUBDOMAINS:
                hsts += "; includeSubDomains"
            if HSTS_PRELOAD:
                hsts += "; preload"
            resp.headers["Strict-Transport-Security"] = hsts
        if CSP_ENABLED and not request.path.startswith("/api/"):
            nonce = getattr(g, "csp_nonce", "")
            csp = build_csp(nonce)
            if csp:
                resp.headers["Content-Security-Policy"] = csp
        _increment_metric("requests_by_status", {"status": str(resp.status_code)})
    except Exception as e:
        log("WARN", "after_request failure", error=str(e))
    return resp

@app.errorhandler(500)
def _handle_500(e):
    _increment_metric("errors_total")
    logger.exception("Internal Server Error")
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error="Internal Server Error"), 500
    return Response("Internal Server Error", 500)

# ===== Graceful shutdown =====
_shutdown_event = threading.Event()
def _signal_handler(signum, frame):
    log("INFO", "Shutdown signal received", signal=signum)
    _shutdown_event.set()
    try:
        _sse_stop_event.set()
    except Exception:
        pass

try:
    signal.signal(signal.SIGTERM, _signal_handler)  # type: ignore
    signal.signal(signal.SIGINT, _signal_handler)  # type: ignore
except Exception:
    # not supported on some platforms (e.g., Windows in certain contexts)
    pass

# ===== BLOCK: AUTH & SESSION =====
def _get_current_user() -> Optional[dict]:
    """
    Lightweight session-based auth; DB-backed override will be set in CORE PART 2/10.
    """
    uid = session.get("user_id")
    if not uid:
        return None
    # Placeholder structure; will be replaced by real DB fetch
    return {
        "id": int(uid),
        "role": session.get("role", "agent"),
        "scopes": session.get("scopes", "read,write"),
        "org_id": session.get("org_id", 1),
        "username": session.get("username", "user")
    }

def _login_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        user = _get_current_user()
        if not user:
            if request.path.startswith("/api/"):
                return jsonify(ok=False, error="Unauthorized"), 401
            return redirect(url_for("login"))
        g.user = user
        return f(*args, **kwargs)
    return _wrap

def _auth_or_token(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        # DB-backed token lookup will override helper in DATABASE layer
        user = _get_current_user()
        if not user:
            return jsonify(ok=False, error="Unauthorized"), 401
        g.user = user
        return f(*args, **kwargs)
    return _wrap

def _require_role(role: str):
    def deco(f):
        @wraps(f)
        def _wrap(*args, **kwargs):
            user = g.get("user") or _get_current_user()
            if not user:
                return jsonify(ok=False, error="Unauthorized"), 401
            if user.get("role") != role and user.get("role") != "admin":
                return jsonify(ok=False, error="Forbidden"), 403
            g.user = user
            return f(*args, **kwargs)
        return _wrap
    return deco

def _require_scopes(required: Set[str]):
    def deco(f):
        @wraps(f)
        def _wrap(*args, **kwargs):
            user = g.get("user") or _get_current_user()
            if not user:
                return jsonify(ok=False, error="Unauthorized"), 401
            scopes = set((user.get("scopes") or "").split(",")) if isinstance(user, dict) else set()
            if required and not (scopes.issuperset(required) or (user.get("role") == "admin")):
                return jsonify(ok=False, error="Forbidden"), 403
            g.user = user
            return f(*args, **kwargs)
        return _wrap
    return deco

def _csrf_protect(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
            expected = session.get("csrf_token")
            if not token or not expected or not secure_equal(token, expected):
                return jsonify(ok=False, error="CSRF validation failed"), 403
        return f(*args, **kwargs)
    return _wrap

# ----- Session invalidation (optional Redis-backed) -----
def invalidate_user_sessions(user_id: int, exclude_session_id: Optional[str] = None):
    """
    Strategy for cookie-based sessions: set a revocation timestamp per user and enforce it in before_request (DB override).
    If Redis available, we store a 'session_revoked_at:{uid}' ts.
    """
    r = get_redis()
    if not r:
        # fallback: store in L1 cache
        _global_cache.set(f"session_revoked_at:{int(user_id)}", utc_now(), ttl=24 * 3600)
        return
    try:
        _redis_cb.call(r.setex, f"session_revoked_at:{int(user_id)}", 24 * 3600, utc_now())
    except Exception as e:
        log("WARN", "invalidate sessions failed", error=str(e))

# ----- Bootstrap hooks (stubs overridden later) -----
def ensure_schema():  # will be implemented in CORE PART 2/10+
    pass

def start_workers_once():  # will be implemented in CORE PART 10/10
    pass

@app.before_first_request
def _bootstrap_once():
    try:
        ensure_schema()
        log("INFO", "Schema ensured (bootstrap)")
    except Exception as e:
        log("CRITICAL", "Schema ensure failed on boot", error=str(e))
        raise
    try:
        sse_backplane_start()
    except Exception as e:
        log("WARN", "SSE backplane start error", error=str(e))
    try:
        start_workers_once()
    except Exception as e:
        log("ERROR", "Workers start failed", error=str(e))

# ===== BLOCK: DB TRANSACTION CONTEXT =====
@contextmanager
def db_transaction():
    """
    Unified transaction context for both SQLite and Postgres.
    Relies on get_db() defined in DATABASE layer (CORE PART 2/10).
    """
    conn = None
    try:
        conn_fn = globals().get("get_db")
        conn = conn_fn() if callable(conn_fn) else None
    except Exception:
        conn = None
    setattr(g, "_db_in_tx", True)
    try:
        yield
        if conn and hasattr(conn, "commit"):
            try:
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
    finally:
        setattr(g, "_db_in_tx", False)

# ==================== END OF CORE PART 1/10 ====================
# ===== START OF CORE PART 2/10 =====
# coding: utf-8

# ==================== CORE PART 2/10 ====================
# ===== BLOCK: DATABASE & ORM =====
import threading
from typing import Any, Optional, Callable, Dict, List, Tuple, Set

# Database configuration
POSTGRES_DSN = os.getenv("POSTGRES_DSN", "").strip()
DATABASE_PATH = os.getenv("DATABASE_PATH", "./crm.db")
DB_TIMEOUT = float(os.getenv("DB_TIMEOUT", "30.0"))
DB_WAL_CHECKPOINT_INTERVAL = int(os.getenv("DB_WAL_CHECKPOINT_INTERVAL", "300"))

# 5.2.0 schema default
SCHEMA_VERSION = int(os.getenv("SCHEMA_VERSION", "52020"))

# Optional DB drivers
try:
    import sqlite3  # type: ignore
    SQLITE_AVAILABLE = True
except Exception:
    sqlite3 = None  # type: ignore
    SQLITE_AVAILABLE = False

try:
    import psycopg2  # type: ignore
    import psycopg2.pool  # type: ignore
    PG_AVAILABLE = True
except Exception:
    psycopg2 = None  # type: ignore
    PG_AVAILABLE = False

DIALECT = "postgres" if (POSTGRES_DSN and PG_AVAILABLE) else "sqlite"

_pg_pool = None
_pg_pool_lock = threading.Lock()


def _init_pg_pool():
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool
    dsn = POSTGRES_DSN
    if not dsn:
        return None
    with _pg_pool_lock:
        if _pg_pool is None:
            try:
                _pg_pool = psycopg2.pool.SimpleConnectionPool(  # type: ignore
                    minconn=1, maxconn=int(os.getenv("PG_POOL_MAX", "10")), dsn=dsn
                )
                log("INFO", "PostgreSQL pool initialized")
            except Exception as e:
                log("CRITICAL", "PostgreSQL pool init failed", error=str(e))
                raise
    return _pg_pool


if DIALECT == "postgres":
    _init_pg_pool()


def _pg_conn_setup(conn):
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SET application_name = %s", (f"crm:{os.getpid()}",))
            except Exception:
                pass
            try:
                cur.execute("SET statement_timeout = %s", (int(os.getenv("PG_STATEMENT_TIMEOUT_MS", "30000")),))
            except Exception:
                pass
    except Exception:
        pass


def _get_pg_conn():
    pool = _init_pg_pool()
    if pool is None:
        raise RuntimeError("PostgreSQL pool is not initialized")
    conn = pool.getconn()  # type: ignore
    try:
        _pg_conn_setup(conn)
        if not hasattr(g, "_pg_conn"):
            g._pg_conn = conn
            g._pg_from_pool = True
        return g._pg_conn
    except Exception:
        try:
            pool.putconn(conn)  # type: ignore
        except Exception:
            pass
    raise RuntimeError("Failed to obtain PostgreSQL connection")


def _get_sqlite_conn():
    if not hasattr(g, "_sqlite_conn"):
        if not SQLITE_AVAILABLE or sqlite3 is None:
            raise RuntimeError("sqlite3 module is unavailable")
        os.makedirs(os.path.dirname(os.path.abspath(DATABASE_PATH)) or ".", exist_ok=True)
        con = sqlite3.connect(
            DATABASE_PATH,
            isolation_level="DEFERRED",
            timeout=DB_TIMEOUT,
            check_same_thread=False,
        )
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        try:
            cur.execute("PRAGMA foreign_keys = ON")
            cur.execute("PRAGMA journal_mode = WAL")
            cur.execute("PRAGMA synchronous = NORMAL")
            cur.execute("PRAGMA cache_size = -64000")
            cur.execute("PRAGMA temp_store = MEMORY")
            cur.execute("PRAGMA busy_timeout = 5000")
        finally:
            cur.close()
        g._sqlite_conn = con
    return g._sqlite_conn


def get_db():
    if DIALECT == "postgres":
        return _get_pg_conn()
    return _get_sqlite_conn()


@app.teardown_appcontext
def close_db(exc=None):
    try:
        if DIALECT == "postgres":
            if hasattr(g, "_pg_conn"):
                try:
                    if getattr(g, "_pg_from_pool", False):
                        _pg_pool.putconn(g._pg_conn)  # type: ignore
                    else:
                        g._pg_conn.close()
                except Exception:
                    pass
        else:
            if hasattr(g, "_sqlite_conn"):
                try:
                    g._sqlite_conn.close()
                except Exception:
                    pass
    except Exception:
        pass


def _adapt_sql(sql: str) -> str:
    """Convert SQLite-style '?' placeholders to Postgres '%s' preserving quoted strings."""
    if DIALECT != "postgres":
        return sql
    res: List[str] = []
    i = 0
    in_single = False
    in_double = False
    while i < len(sql):
        ch = sql[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            res.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            res.append(ch)
            i += 1
            continue
        if ch == "?" and not in_single and not in_double:
            res.append("%s")
            i += 1
            continue
        res.append(ch)
        i += 1
    return "".join(res)


def _fetch_all_dicts(cur) -> List[dict]:
    desc = cur.description or []
    cols = [d[0] for d in desc]
    if not cols:
        return []
    rows = cur.fetchall()
    return [dict(zip(cols, r)) for r in rows]


# ===== BLOCK: TRANSACTIONS & HELPERS =====
def _in_tx() -> bool:
    return bool(getattr(g, "_db_in_tx", False))


def query_db(query: str, args: Tuple[Any, ...] = (), one: bool = False):
    tracer = get_tracer()
    span_ctx = None
    if tracer:
        span_ctx = tracer.start_as_current_span("db.query")  # type: ignore
        span_ctx.__enter__()  # type: ignore
        try:
            from opentelemetry import trace as _trace  # type: ignore
            _trace.get_current_span().set_attribute("db.statement", query[:300])  # type: ignore
            _trace.get_current_span().set_attribute("db.system", DIALECT)  # type: ignore
        except Exception:
            pass
    try:
        if DIALECT == "postgres":
            conn = get_db()
            sql = _adapt_sql(query)
            with conn.cursor() as cur:
                cur.execute(sql, args or None)
                _increment_metric("api_calls_total", {"provider": "db", "model": DIALECT})
                rows = _fetch_all_dicts(cur)
                if one:
                    return rows[0] if rows else None
                return rows
        else:
            con = get_db()
            cur = con.execute(query, args or ())
            rows = cur.fetchall()
            cur.close()
            _increment_metric("api_calls_total", {"provider": "db", "model": DIALECT})
            if one:
                return dict(rows[0]) if rows else None
            return [dict(r) for r in rows]
    except Exception as e:
        log("ERROR", "query_db error", error=str(e), query=query[:300])
        raise
    finally:
        if span_ctx:
            span_ctx.__exit__(None, None, None)  # type: ignore


def exec_db(query: str, args: Tuple[Any, ...] = ()):
    """Execute write query; returns last inserted id when available (SQLite returns rowid, PG returns id if RETURNING used)."""
    tracer = get_tracer()
    span_ctx = None
    if tracer:
        span_ctx = tracer.start_as_current_span("db.exec")  # type: ignore
        span_ctx.__enter__()  # type: ignore
        try:
            from opentelemetry import trace as _trace  # type: ignore
            _trace.get_current_span().set_attribute("db.statement", query[:300])  # type: ignore
            _trace.get_current_span().set_attribute("db.system", DIALECT)  # type: ignore
        except Exception:
            pass
    try:
        if DIALECT == "postgres":
            conn = get_db()
            sql = _adapt_sql(query)
            return_id = False
            if re.match(r"^\s*insert\s+into\b", sql, re.I) and "returning" not in sql.lower():
                sql = sql.rstrip(";") + " RETURNING id"
                return_id = True
            with conn.cursor() as cur:
                cur.execute(sql, args or None)
                last_id = None
                if return_id:
                    row = cur.fetchone()
                    if row:
                        last_id = row[0]
                if not _in_tx():
                    try:
                        conn.commit()
                    except Exception:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                        raise
                return last_id
        else:
            con = get_db()
            cur = con.execute(query, args or ())
            last_id = cur.lastrowid
            if not _in_tx():
                con.commit()
            cur.close()
            return last_id
    except Exception as e:
        log("ERROR", "exec_db error", error=str(e), query=query[:300])
        try:
            get_db().rollback()
        except Exception:
            pass
        raise
    finally:
        if span_ctx:
            span_ctx.__exit__(None, None, None)  # type: ignore


def exec_db_affect(query: str, args: Tuple[Any, ...] = ()) -> int:
    """Execute write query; returns affected rowcount."""
    tracer = get_tracer()
    span_ctx = None
    if tracer:
        span_ctx = tracer.start_as_current_span("db.exec_affect")  # type: ignore
        span_ctx.__enter__()  # type: ignore
        try:
            from opentelemetry import trace as _trace  # type: ignore
            _trace.get_current_span().set_attribute("db.statement", query[:300])  # type: ignore
            _trace.get_current_span().set_attribute("db.system", DIALECT)  # type: ignore
        except Exception:
            pass
    try:
        if DIALECT == "postgres":
            conn = get_db()
            sql = _adapt_sql(query)
            with conn.cursor() as cur:
                cur.execute(sql, args or None)
                rc = cur.rowcount
                if not _in_tx():
                    try:
                        conn.commit()
                    except Exception:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                        raise
                return int(rc or 0)
        else:
            con = get_db()
            cur = con.execute(query, args or ())
            rc = cur.rowcount
            if not _in_tx():
                con.commit()
            cur.close()
            return int(rc or 0)
    except Exception as e:
        log("ERROR", "exec_db_affect error", error=str(e), query=query[:300])
        try:
            get_db().rollback()
        except Exception:
            pass
        raise
    finally:
        if span_ctx:
            span_ctx.__exit__(None, None, None)  # type: ignore


# WAL checkpoint throttling (SQLite) — module-level, not per-request
_WAL_LAST_CHECKPOINT = 0.0
_WAL_LOCK = threading.Lock()

def wal_checkpoint_if_needed():
    if DIALECT != "sqlite":
        return
    global _WAL_LAST_CHECKPOINT
    now = time.time()
    with _WAL_LOCK:
        if (now - _WAL_LAST_CHECKPOINT) < DB_WAL_CHECKPOINT_INTERVAL:
            return
        try:
            con = get_db()
            con.execute("PRAGMA wal_checkpoint(PASSIVE)")
            _WAL_LAST_CHECKPOINT = now
            log("DEBUG", "WAL checkpoint completed")
        except Exception as e:
            log("WARN", "WAL checkpoint failed", error=str(e))


def _safe_update_clause(allowed_fields: Set[str], data: Dict[str, Any]) -> Tuple[str, List[Any]]:
    updates: List[str] = []
    params: List[Any] = []
    for k, v in data.items():
        if k in allowed_fields:
            updates.append(f"{k}=?")
            params.append(v)
    return (", ".join(updates), params)


def _hash_api_token(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


# ===== BLOCK: SCHEMA ENSURE & MIGRATIONS =====
def ensure_schema():
    if DIALECT == "postgres":
        _ensure_schema_postgres()
    else:
        _ensure_schema_sqlite()


def _ensure_schema_postgres():
    conn = get_db()
    with conn.cursor() as cur:
        # migrations table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id SERIAL PRIMARY KEY,
            version INTEGER NOT NULL UNIQUE,
            applied_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            description TEXT
        )
        """)
        if not _in_tx():
            conn.commit()
    # Core schema split into parts (implemented in CORE PART 3/10..4/10)
    _pg_schema_part1()
    _pg_schema_part2()
    _pg_schema_part3()
    _pg_schema_additional_part1()
    _pg_schema_additional_part2()
    _pg_schema_additional_part3()
    # Auxiliary tables that were missing in original code (new)
    _pg_schema_aux()
    # Indexes & FTS
    _ensure_indexes_postgres()
    _ensure_fts_postgres()
    current = get_current_schema_version()
    if current < SCHEMA_VERSION:
        _run_migrations(current)
    log("INFO", "Schema ensured (Postgres)", version=SCHEMA_VERSION)


def _ensure_schema_sqlite():
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS schema_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version INTEGER NOT NULL UNIQUE,
        applied_at TEXT DEFAULT (datetime('now')),
        description TEXT
    );
    """)
    # Back-compat: на старых БД колонка description могла отсутствовать — добавим её
    try:
        cols = query_db("PRAGMA table_info(schema_migrations)") or []
        names = {str(c.get("name")) for c in cols}
        if "description" not in names:
            exec_db("ALTER TABLE schema_migrations ADD COLUMN description TEXT")
            log("INFO", "schema_migrations.description column added for back-compat")
    except Exception as e:
        log("WARN", "schema_migrations description add failed", error=str(e))
    if not _in_tx():
        con.commit()
    # Core schema split into parts (implemented in CORE PART 3/10..4/10)
    _sqlite_schema_part1()
    _sqlite_schema_part2()
    _sqlite_schema_part3()
    _sqlite_schema_additional_part1()
    _sqlite_schema_additional_part2()
    _sqlite_schema_additional_part3()
    # Auxiliary tables missing in original code (new)
    _sqlite_schema_aux()
    # Legacy columns backfill for older DBs
    _sqlite_ensure_legacy_columns()
    # Indexes & FTS
    _ensure_indexes_sqlite()
    _ensure_fts_sqlite()
    current = get_current_schema_version()
    if current < SCHEMA_VERSION:
        _run_migrations(current)
    log("INFO", "Schema ensured (SQLite)", version=SCHEMA_VERSION)


def _ensure_indexes_postgres():
    _pg_indexes_part1()
    _pg_indexes_part2()
    _pg_indexes_part3()
    _pg_indexes_part4()  # extra hot-path indexes


def _ensure_indexes_sqlite():
    _sqlite_indexes_part1()
    _sqlite_indexes_part2()
    _sqlite_indexes_part3()
    _sqlite_indexes_part4()  # extra hot-path indexes


def _ensure_fts_postgres():
    _pg_fts_part1()


def _ensure_fts_sqlite():
    _sqlite_fts_part1()


def get_current_schema_version() -> int:
    try:
        row = query_db("SELECT MAX(version) AS v FROM schema_migrations", (), one=True)
        return int(row["v"]) if row and row.get("v") is not None else 0
    except Exception:
        return 0


def record_migration(version: int, description: str = ""):
    if DIALECT == "postgres":
        exec_db("INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, NOW(), ?)", (version, description))
    else:
        # SQLite back-compat: если в legacy БД нет колонки description — пишем без неё
        try:
            exec_db("INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)", (version, utc_now(), description))
        except Exception as e:
            if "no column named description" in str(e).lower():
                exec_db("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (version, utc_now()))
                log("INFO", "Recorded migration without description (legacy schema)", version=version)
            else:
                raise


# ---- Legacy schema self-healing (SQLite) ----
def _sqlite_add_column_if_missing(table: str, column: str, ddl: str):
    """
    Безопасно добавляет колонку (ALTER TABLE) в SQLite, если её нет.
    ddl — фрагмент типа 'TEXT DEFAULT ''' или 'INTEGER DEFAULT 0'.
    """
    try:
        cols = query_db(f"PRAGMA table_info({table})") or []
        names = {str(c.get("name")) for c in cols}
        if column not in names:
            exec_db(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            log("INFO", "Column added", table=table, column=column)
    except Exception as e:
        log("WARN", "Add column failed", table=table, column=column, error=str(e))


def _sqlite_ensure_legacy_columns():
    """
    Догоняем схему для старых БД: добавляем недостающие поля, на которые опирается UI и API.
    Вызывается из ensure_schema_sqlite().
    """
    # users — предпочтения интерфейса и 2FA/аватар
    _sqlite_add_column_if_missing("users", "timezone", "TEXT DEFAULT 'UTC'")
    _sqlite_add_column_if_missing("users", "locale", "TEXT DEFAULT 'ru'")
    _sqlite_add_column_if_missing("users", "theme", "TEXT DEFAULT 'light'")
    _sqlite_add_column_if_missing("users", "telegram_chat_id", "TEXT")
    _sqlite_add_column_if_missing("users", "whatsapp_phone", "TEXT")
    _sqlite_add_column_if_missing("users", "avatar_url", "TEXT")
    _sqlite_add_column_if_missing("users", "must_change_password", "INTEGER DEFAULT 0")
    _sqlite_add_column_if_missing("users", "totp_secret", "TEXT")
    _sqlite_add_column_if_missing("users", "totp_enabled", "INTEGER DEFAULT 0")
    _sqlite_add_column_if_missing("users", "last_login_at", "TEXT")

    # companies — поля, используемые в списке/поиске клиентов
    _sqlite_add_column_if_missing("companies", "phone_norm", "TEXT")
    _sqlite_add_column_if_missing("companies", "industry", "TEXT")
    _sqlite_add_column_if_missing("companies", "score", "INTEGER DEFAULT 0")
    _sqlite_add_column_if_missing("companies", "updated_at", "TEXT")

    # contacts — нормализованный телефон
    _sqlite_add_column_if_missing("contacts", "phone_norm", "TEXT")

    # inbox_threads — дедлайн первого ответа (используется в SLA)
    _sqlite_add_column_if_missing("inbox_threads", "first_response_due_at", "TEXT")
# ---- /Legacy ----


def _run_migrations(from_version: int):
    """
    Lightweight migrations registry. Heavy DDL live in schema parts (3/10, 4/10).
    """
    migrations: List[Tuple[int, Callable[[], None], str]] = []

    def _mig_rebuild_indexes():
        try:
            if DIALECT == "postgres":
                _ensure_indexes_postgres()
            else:
                _ensure_indexes_sqlite()
        except Exception as e:
            log("WARN", "Indexes migration failed", error=str(e))

    def _mig_rebuild_fts():
        try:
            if DIALECT == "postgres":
                _ensure_fts_postgres()
            else:
                _ensure_fts_sqlite()
        except Exception as e:
            log("WARN", "FTS migration failed", error=str(e))

    def _mig_add_ai_jobs_attempts():
        try:
            if DIALECT == "postgres":
                conn = get_db()
                with conn.cursor() as cur:
                    cur.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns
                            WHERE table_name='ai_jobs' AND column_name='attempts'
                        ) THEN
                            ALTER TABLE ai_jobs ADD COLUMN attempts INTEGER DEFAULT 0;
                        END IF;
                    END$$;
                    """)
                conn.commit()
            else:
                cols = query_db("PRAGMA table_info(ai_jobs)") or []
                names = {c.get("name") for c in cols}
                if "attempts" not in names:
                    exec_db("ALTER TABLE ai_jobs ADD COLUMN attempts INTEGER DEFAULT 0")
        except Exception as e:
            log("WARN", "Add ai_jobs.attempts failed", error=str(e))

    # New migrations (safe, idempotent)

    def _mig_tokens_indexes():
        """Ensure index/unique index on api_tokens.token_hash and index on approval_tokens.token_hash."""
        try:
            if DIALECT == "postgres":
                conn = get_db()
                with conn.cursor() as cur:
                    # Try UNIQUE; if fails due to duplicates, fallback to non-unique index
                    try:
                        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash)")
                    except Exception as e:
                        log("WARN", "UNIQUE idx_api_tokens_token_hash failed, will fallback", error=str(e))
                        try:
                            cur.execute("CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash)")
                        except Exception:
                            pass
                    try:
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_approval_tokens_token_hash ON approval_tokens(token_hash)")
                    except Exception:
                        pass
                if not _in_tx():
                    conn.commit()
            else:
                # SQLite
                try:
                    exec_db("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash)")
                except Exception as e:
                    log("WARN", "SQLite UNIQUE idx_api_tokens_token_hash failed, fallback non-unique", error=str(e))
                    try:
                        exec_db("CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash)")
                    except Exception:
                        pass
                try:
                    exec_db("CREATE INDEX IF NOT EXISTS idx_approval_tokens_token_hash ON approval_tokens(token_hash)")
                except Exception:
                    pass
        except Exception as e:
            log("WARN", "tokens indexes migration failed", error=str(e))

    def _mig_stage_transitions_org():
        """Add org_id to stage_transitions and backfill for deals; add covering index."""
        try:
            if DIALECT == "postgres":
                conn = get_db()
                with conn.cursor() as cur:
                    cur.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns
                            WHERE table_name='stage_transitions' AND column_name='org_id'
                        ) THEN
                            ALTER TABLE stage_transitions ADD COLUMN org_id INTEGER;
                        END IF;
                    END$$;
                    """)
                    # backfill for deals
                    cur.execute("""
                    UPDATE stage_transitions st
                    SET org_id = d.org_id
                    FROM deals d
                    WHERE st.entity_type='deal' AND d.id = st.entity_id AND st.org_id IS NULL
                    """)
                    # Optional: backfill for tasks if нужно (закомментировано)
                    # cur.execute("""
                    # UPDATE stage_transitions st
                    # SET org_id = t.org_id
                    # FROM tasks t
                    # WHERE st.entity_type='task' AND t.id = st.entity_id AND st.org_id IS NULL
                    # """)
                    # index
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_stage_transitions_org ON stage_transitions(org_id, entity_type, entity_id, created_at)")
                if not _in_tx():
                    conn.commit()
            else:
                # SQLite
                cols = query_db("PRAGMA table_info(stage_transitions)") or []
                names = {c.get("name") for c in cols}
                if "org_id" not in names:
                    exec_db("ALTER TABLE stage_transitions ADD COLUMN org_id INTEGER")
                # backfill for deals
                try:
                    exec_db("""
                    UPDATE stage_transitions
                    SET org_id = (SELECT d.org_id FROM deals d WHERE d.id = stage_transitions.entity_id)
                    WHERE entity_type='deal' AND org_id IS NULL
                    """)
                except Exception:
                    pass
                try:
                    exec_db("CREATE INDEX IF NOT EXISTS idx_stage_transitions_org ON stage_transitions(org_id, entity_type, entity_id, created_at)")
                except Exception:
                    pass
        except Exception as e:
            log("WARN", "stage_transitions org migration failed", error=str(e))

    start = max(from_version, 0)
    migrations.append((start + 1, _mig_rebuild_indexes, "Rebuild indexes"))
    migrations.append((start + 2, _mig_rebuild_fts, "Rebuild FTS"))
    migrations.append((start + 3, _mig_add_ai_jobs_attempts, "Add ai_jobs.attempts"))
    # new ones
    migrations.append((start + 4, _mig_tokens_indexes, "Add token hash indexes"))
    migrations.append((start + 5, _mig_stage_transitions_org, "Add org_id to stage_transitions and backfill"))

    for ver, fn, desc in sorted(migrations, key=lambda x: x[0]):
        if ver > from_version and ver <= SCHEMA_VERSION:
            try:
                fn()
                record_migration(ver, desc)
                log("INFO", "Migration applied", version=ver, description=desc)
            except Exception as e:
                log("WARN", "Migration failed", version=ver, error=str(e))


# DB helpers
def db_table_count(table: str, org_field: Optional[str] = None, org_id: Optional[int] = None) -> int:
    try:
        if org_field and org_id is not None:
            row = query_db(f"SELECT COUNT(*) AS c FROM {table} WHERE {org_field}=?", (org_id,), one=True)
        else:
            row = query_db(f"SELECT COUNT(*) AS c FROM {table}", (), one=True)
        return int((row or {}).get("c") or 0)
    except Exception as e:
        log("WARN", "db_table_count failed", error=str(e), table=table)
        return 0


# ===== BLOCK: SCHEMA PART STUBS (implemented in CORE PART 3/10..4/10) =====
def _pg_schema_part1(): pass
def _pg_schema_part2(): pass
def _pg_schema_part3(): pass
def _pg_schema_additional_part1(): pass
def _pg_schema_additional_part2(): pass
def _pg_schema_additional_part3(): pass

def _sqlite_schema_part1(): pass
def _sqlite_schema_part2(): pass
def _sqlite_schema_part3(): pass
def _sqlite_schema_additional_part1(): pass
def _sqlite_schema_additional_part2(): pass
def _sqlite_schema_additional_part3(): pass

def _pg_indexes_part1(): pass
def _pg_indexes_part2(): pass
def _pg_indexes_part3(): pass
def _pg_indexes_part4(): pass
def _sqlite_indexes_part1(): pass
def _sqlite_indexes_part2(): pass
def _sqlite_indexes_part3(): pass
def _sqlite_indexes_part4(): pass
def _pg_fts_part1(): pass
def _sqlite_fts_part1(): pass


# ===== BLOCK: AUXILIARY SCHEMA (NEW: ensure missing tables used by logic) =====
def _pg_schema_aux():
    conn = get_db()
    with conn.cursor() as cur:
        # activity_timeline (used widely)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_timeline (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL,
            actor_type TEXT,
            actor_id INTEGER,
            entity_type TEXT,
            entity_id INTEGER,
            action TEXT,
            data_json TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        # workflow_tasks (executor placeholder)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS workflow_tasks (
            id SERIAL PRIMARY KEY,
            status TEXT DEFAULT 'pending',
            scheduled_at TIMESTAMP WITHOUT TIME ZONE,
            started_at TIMESTAMP WITHOUT TIME ZONE,
            completed_at TIMESTAMP WITHOUT TIME ZONE,
            error TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        # saved_views (calendar/others)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS saved_views (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            config_json TEXT NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        # lead_scoring_rules (for deals score)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS lead_scoring_rules (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL,
            field TEXT NOT NULL,
            operator TEXT NOT NULL,
            value TEXT,
            score_delta INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        # task_status_department_rules (auto-assign dept by status)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS task_status_department_rules (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL,
            status_name TEXT NOT NULL,
            department_id INTEGER,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        # email sequences (used by email_sequence_worker)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS sequence_enrollments (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            sequence_id INTEGER NOT NULL,
            current_step INTEGER DEFAULT 0,
            last_sent_at TIMESTAMP WITHOUT TIME ZONE,
            status TEXT DEFAULT 'active'
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS sequence_steps (
            id SERIAL PRIMARY KEY,
            sequence_id INTEGER NOT NULL,
            step_num INTEGER NOT NULL,
            delay_hours INTEGER DEFAULT 24,
            subject TEXT,
            body_template TEXT
        )
        """)
    if not _in_tx():
        conn.commit()


def _sqlite_schema_aux():
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS activity_timeline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        actor_type TEXT,
        actor_id INTEGER,
        entity_type TEXT,
        entity_id INTEGER,
        action TEXT,
        data_json TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS workflow_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        status TEXT DEFAULT 'pending',
        scheduled_at TEXT,
        started_at TEXT,
        completed_at TEXT,
        error TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS saved_views (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        entity_type TEXT NOT NULL,
        config_json TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS lead_scoring_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        field TEXT NOT NULL,
        operator TEXT NOT NULL,
        value TEXT,
        score_delta INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS task_status_department_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        status_name TEXT NOT NULL,
        department_id INTEGER,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sequence_enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        sequence_id INTEGER NOT NULL,
        current_step INTEGER DEFAULT 0,
        last_sent_at TEXT,
        status TEXT DEFAULT 'active'
    );
    CREATE TABLE IF NOT EXISTS sequence_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sequence_id INTEGER NOT NULL,
        step_num INTEGER NOT NULL,
        delay_hours INTEGER DEFAULT 24,
        subject TEXT,
        body_template TEXT
    );
    """)
    if not _in_tx():
        con.commit()


# ===== BLOCK: AUTH OVERRIDES (DB) =====
def _get_token_user():
    """Bearer token auth (org/user scoped), scopes-aware."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    th = _hash_api_token(token)
    row = query_db(
        """
        SELECT t.id AS token_id, t.org_id, t.user_id, t.scopes, t.active, t.expires_at,
               t.last_used_at, u.username, u.role
        FROM api_tokens t
        LEFT JOIN users u ON u.id = t.user_id
        WHERE t.token_hash=? AND t.active=1 AND (t.expires_at IS NULL OR t.expires_at >= ?)
        """,
        (th, utc_now()),
        one=True
    )
    if not row:
        return None
    try:
        exec_db("UPDATE api_tokens SET last_used_at=? WHERE id=?", (utc_now(), row.get("token_id")))
    except Exception:
        pass
    scopes_raw = row.get("scopes") or "read,write"
    scopes_set = set(s.strip() for s in str(scopes_raw).split(",") if s.strip())
    scopes = ",".join(sorted(scopes_set)) if scopes_set else "read,write"
    if row.get("user_id"):
        role = row.get("role") or "agent"
        username = row.get("username") or f"user:{row.get('user_id')}"
        uid = row.get("user_id")
    else:
        role = "admin" if ("admin" in scopes_set) else "agent"
        username = f"org_token:{row.get('token_id')}"
        uid = None
    return {
        "id": uid,
        "org_id": row.get("org_id"),
        "role": role,
        "username": username,
        "scopes": scopes
    }


def _get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    u = query_db("SELECT * FROM users WHERE id=? AND active=1", (uid,), one=True)
    return dict(u) if u else None


def _auth_or_token(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        user = _get_current_user() or _get_token_user()
        if not user:
            return jsonify(ok=False, error="Unauthorized"), 401
        g.user = user
        return f(*args, **kwargs)
    return _wrap


# ===== END OF CORE PART 2/10 =====
# ===== START OF CORE PART 3/10 =====
# coding: utf-8

# ==================== CORE PART 3/10 ====================
# ===== BLOCK: DATABASE SCHEMA (PART 1) =====
def _pg_schema_part1():
    conn = get_db()
    with conn.cursor() as cur:
        # Orgs and structure
        cur.execute("""
        CREATE TABLE IF NOT EXISTS orgs (
            id SERIAL PRIMARY KEY,
            slug TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            inn TEXT,
            settings_json TEXT DEFAULT '{}'::text,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            slug TEXT,
            parent_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS job_titles (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, name)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'agent',
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            job_title_id INTEGER REFERENCES job_titles(id) ON DELETE SET NULL,
            first_name TEXT,
            last_name TEXT,
            phone TEXT,
            telegram_chat_id TEXT,
            whatsapp_phone TEXT,
            avatar_url TEXT,
            timezone TEXT DEFAULT 'UTC',
            locale TEXT DEFAULT 'ru',
            theme TEXT DEFAULT 'light',
            active BOOLEAN DEFAULT TRUE,
            must_change_password BOOLEAN DEFAULT FALSE,
            totp_secret TEXT,
            totp_enabled BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            last_login_at TIMESTAMP WITHOUT TIME ZONE,
            UNIQUE(org_id, username)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            scopes TEXT DEFAULT 'read,write',
            active BOOLEAN DEFAULT TRUE,
            expires_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            last_used_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS channels (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            name TEXT,
            config_json TEXT DEFAULT '{}'::text,
            secret TEXT,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            storage_key TEXT NOT NULL,
            name TEXT NOT NULL,
            content_type TEXT,
            size_bytes INTEGER DEFAULT 0,
            uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
    if not _in_tx():
        conn.commit()


def _sqlite_schema_part1():
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS orgs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        inn TEXT,
        settings_json TEXT DEFAULT '{}',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        slug TEXT,
        parent_id INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(parent_id) REFERENCES departments(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS job_titles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, name),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        email TEXT,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'agent',
        department_id INTEGER,
        job_title_id INTEGER,
        first_name TEXT,
        last_name TEXT,
        phone TEXT,
        telegram_chat_id TEXT,
        whatsapp_phone TEXT,
        avatar_url TEXT,
        timezone TEXT DEFAULT 'UTC',
        locale TEXT DEFAULT 'ru',
        theme TEXT DEFAULT 'light',
        active INTEGER DEFAULT 1,
        must_change_password INTEGER DEFAULT 0,
        totp_secret TEXT,
        totp_enabled INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        last_login_at TEXT,
        UNIQUE(org_id, username),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE SET NULL,
        FOREIGN KEY(job_title_id) REFERENCES job_titles(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS api_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        user_id INTEGER,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        scopes TEXT DEFAULT 'read,write',
        active INTEGER DEFAULT 1,
        expires_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        last_used_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        name TEXT,
        config_json TEXT DEFAULT '{}',
        secret TEXT,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        storage_key TEXT NOT NULL,
        name TEXT NOT NULL,
        content_type TEXT,
        size_bytes INTEGER DEFAULT 0,
        uploaded_by INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
    );
    """)
    if not _in_tx():
        con.commit()


# ===== BLOCK: DATABASE SCHEMA (PART 2) =====
def _pg_schema_part2():
    conn = get_db()
    with conn.cursor() as cur:
        # Companies & contacts
        cur.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            inn TEXT,
            phone TEXT,
            phone_norm TEXT,
            email TEXT,
            address TEXT,
            notes TEXT,
            score INTEGER DEFAULT 0,
            industry TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
            name TEXT NOT NULL,
            position TEXT,
            phone TEXT,
            phone_norm TEXT,
            email TEXT,
            notes TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        # Inbox
        cur.execute("""
        CREATE TABLE IF NOT EXISTS inbox_threads (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            channel_id INTEGER REFERENCES channels(id) ON DELETE SET NULL,
            subject TEXT,
            status TEXT DEFAULT 'open',
            priority TEXT DEFAULT 'normal',
            assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
            contact_id INTEGER REFERENCES contacts(id) ON DELETE SET NULL,
            external_thread_id TEXT,
            tags_csv TEXT,
            first_response_at TIMESTAMP WITHOUT TIME ZONE,
            first_response_due_at TIMESTAMP WITHOUT TIME ZONE,
            last_message_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS inbox_messages (
            id SERIAL PRIMARY KEY,
            thread_id INTEGER NOT NULL REFERENCES inbox_threads(id) ON DELETE CASCADE,
            sender_type TEXT NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            external_user_id TEXT,
            body TEXT,
            internal_note BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS message_attachments (
            id SERIAL PRIMARY KEY,
            message_id INTEGER NOT NULL REFERENCES inbox_messages(id) ON DELETE CASCADE,
            file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        # Tasks
        cur.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'open',
            priority TEXT DEFAULT 'normal',
            assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
            contact_id INTEGER REFERENCES contacts(id) ON DELETE SET NULL,
            due_at TIMESTAMP WITHOUT TIME ZONE,
            completed_at TIMESTAMP WITHOUT TIME ZONE,
            monthly_fee DOUBLE PRECISION DEFAULT 0,
            address TEXT,
            contact_phone TEXT,
            last_commented_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS task_statuses (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            color TEXT DEFAULT '#888',
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, name)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS task_comments (
            id SERIAL PRIMARY KEY,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            body TEXT NOT NULL,
            format TEXT DEFAULT 'plain',
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS task_comment_attachments (
            id SERIAL PRIMARY KEY,
            comment_id INTEGER NOT NULL REFERENCES task_comments(id) ON DELETE CASCADE,
            file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS task_participants (
            id SERIAL PRIMARY KEY,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT DEFAULT 'watcher',
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(task_id, user_id)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS task_checklists (
            id SERIAL PRIMARY KEY,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            item TEXT NOT NULL,
            checked BOOLEAN DEFAULT FALSE,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS task_reminders (
            id SERIAL PRIMARY KEY,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            remind_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            message TEXT,
            sent BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        # Deals & workflow
        cur.execute("""
        CREATE TABLE IF NOT EXISTS deals (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            amount DOUBLE PRECISION DEFAULT 0,
            currency TEXT DEFAULT 'RUB',
            status TEXT DEFAULT 'open',
            stage TEXT,
            pipeline_key TEXT DEFAULT 'default',
            assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
            contact_id INTEGER REFERENCES contacts(id) ON DELETE SET NULL,
            due_at TIMESTAMP WITHOUT TIME ZONE,
            won_at TIMESTAMP WITHOUT TIME ZONE,
            lost_at TIMESTAMP WITHOUT TIME ZONE,
            score INTEGER DEFAULT 0,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS workflow_stages (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            entity_type TEXT NOT NULL,
            pipeline_key TEXT DEFAULT 'default',
            key TEXT NOT NULL,
            name TEXT NOT NULL,
            sort_order INTEGER DEFAULT 0,
            sla_hours INTEGER,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, entity_type, pipeline_key, key)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS stage_transitions (
            id SERIAL PRIMARY KEY,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            from_stage TEXT,
            to_stage TEXT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            comment TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        # Webhooks & audit & ai_jobs
        cur.execute("""
        CREATE TABLE IF NOT EXISTS webhooks (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            event TEXT NOT NULL,
            url TEXT NOT NULL,
            secret TEXT,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS webhook_queue (
            id SERIAL PRIMARY KEY,
            webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
            event TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            attempts INTEGER DEFAULT 0,
            next_try_at TIMESTAMP WITHOUT TIME ZONE,
            last_error TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            request_id TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_jobs (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            job_type TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            input_text TEXT,
            output_text TEXT,
            model TEXT,
            tokens_used INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            error TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            completed_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS kb_docs (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            tags_csv TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
    if not _in_tx():
        conn.commit()


def _sqlite_schema_part2():
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS companies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        inn TEXT,
        phone TEXT,
        phone_norm TEXT,
        email TEXT,
        address TEXT,
        notes TEXT,
        score INTEGER DEFAULT 0,
        industry TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        company_id INTEGER,
        name TEXT NOT NULL,
        position TEXT,
        phone TEXT,
        phone_norm TEXT,
        email TEXT,
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS inbox_threads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        channel_id INTEGER,
        subject TEXT,
        status TEXT DEFAULT 'open',
        priority TEXT DEFAULT 'normal',
        assignee_id INTEGER,
        company_id INTEGER,
        contact_id INTEGER,
        external_thread_id TEXT,
        tags_csv TEXT,
        first_response_at TEXT,
        first_response_due_at TEXT,
        last_message_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(channel_id) REFERENCES channels(id) ON DELETE SET NULL,
        FOREIGN KEY(assignee_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL,
        FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS inbox_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id INTEGER NOT NULL,
        sender_type TEXT NOT NULL,
        user_id INTEGER,
        external_user_id TEXT,
        body TEXT,
        internal_note INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(thread_id) REFERENCES inbox_threads(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS message_attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        file_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(message_id) REFERENCES inbox_messages(id) ON DELETE CASCADE,
        FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'open',
        priority TEXT DEFAULT 'normal',
        assignee_id INTEGER,
        department_id INTEGER,
        company_id INTEGER,
        contact_id INTEGER,
        due_at TEXT,
        completed_at TEXT,
        monthly_fee REAL DEFAULT 0,
        address TEXT,
        contact_phone TEXT,
        last_commented_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(assignee_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE SET NULL,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL,
        FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS task_statuses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        color TEXT DEFAULT '#888',
        sort_order INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, name),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS task_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        user_id INTEGER,
        body TEXT NOT NULL,
        format TEXT DEFAULT 'plain',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS task_comment_attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        comment_id INTEGER NOT NULL,
        file_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(comment_id) REFERENCES task_comments(id) ON DELETE CASCADE,
        FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS task_participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'watcher',
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(task_id, user_id),
        FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS task_checklists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        item TEXT NOT NULL,
        checked INTEGER DEFAULT 0,
        sort_order INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS task_reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        remind_at TEXT NOT NULL,
        message TEXT,
        sent INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS deals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        amount REAL DEFAULT 0,
        currency TEXT DEFAULT 'RUB',
        status TEXT DEFAULT 'open',
        stage TEXT,
        pipeline_key TEXT DEFAULT 'default',
        assignee_id INTEGER,
        company_id INTEGER,
        contact_id INTEGER,
        due_at TEXT,
        won_at TEXT,
        lost_at TEXT,
        score INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(assignee_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL,
        FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS workflow_stages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        entity_type TEXT NOT NULL,
        pipeline_key TEXT DEFAULT 'default',
        key TEXT NOT NULL,
        name TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0,
        sla_hours INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, entity_type, pipeline_key, key),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS stage_transitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id INTEGER NOT NULL,
        from_stage TEXT,
        to_stage TEXT,
        user_id INTEGER,
        comment TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS webhooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        event TEXT NOT NULL,
        url TEXT NOT NULL,
        secret TEXT,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS webhook_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        webhook_id INTEGER NOT NULL,
        event TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        attempts INTEGER DEFAULT 0,
        next_try_at TEXT,
        last_error TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        user_id INTEGER,
        action TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        request_id TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS ai_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        user_id INTEGER,
        job_type TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        input_text TEXT,
        output_text TEXT,
        model TEXT,
        tokens_used INTEGER DEFAULT 0,
        attempts INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending',
        error TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        completed_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS kb_docs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        tags_csv TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    """)
    if not _in_tx():
        con.commit()


# ===== BLOCK: INDEXES (PART 1) =====
def _pg_indexes_part1():
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(org_id, username)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_active ON users(org_id, active)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_companies_org ON companies(org_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_companies_inn ON companies(inn)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_companies_phone_norm ON companies(phone_norm)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_contacts_org ON contacts(org_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threads_org ON inbox_threads(org_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threads_status ON inbox_threads(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threads_lastmsg ON inbox_threads(last_message_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_msgs_thread ON inbox_messages(thread_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_msgs_created ON inbox_messages(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_org ON tasks(org_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_deals_org ON deals(org_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_deals_status ON deals(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_deals_stage ON deals(stage)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ai_jobs_org ON ai_jobs(org_id)")
    if not _in_tx():
        conn.commit()


def _sqlite_indexes_part1():
    con = get_db()
    con.executescript("""
    CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(org_id, username);
    CREATE INDEX IF NOT EXISTS idx_users_active ON users(org_id, active);
    CREATE INDEX IF NOT EXISTS idx_companies_org ON companies(org_id);
    CREATE INDEX IF NOT EXISTS idx_companies_inn ON companies(inn);
    CREATE INDEX IF NOT EXISTS idx_companies_phone_norm ON companies(phone_norm);
    CREATE INDEX IF NOT EXISTS idx_contacts_org ON contacts(org_id);
    CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company_id);
    CREATE INDEX IF NOT EXISTS idx_threads_org ON inbox_threads(org_id);
    CREATE INDEX IF NOT EXISTS idx_threads_status ON inbox_threads(status);
    CREATE INDEX IF NOT EXISTS idx_threads_lastmsg ON inbox_threads(last_message_at);
    CREATE INDEX IF NOT EXISTS idx_msgs_thread ON inbox_messages(thread_id);
    CREATE INDEX IF NOT EXISTS idx_msgs_created ON inbox_messages(created_at);
    CREATE INDEX IF NOT EXISTS idx_tasks_org ON tasks(org_id);
    CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee_id);
    CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
    CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_at);
    CREATE INDEX IF NOT EXISTS idx_deals_org ON deals(org_id);
    CREATE INDEX IF NOT EXISTS idx_deals_status ON deals(status);
    CREATE INDEX IF NOT EXISTS idx_deals_stage ON deals(stage);
    CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id);
    CREATE INDEX IF NOT EXISTS idx_ai_jobs_org ON ai_jobs(org_id);
    """)
    if not _in_tx():
        con.commit()


# ===== END OF CORE PART 3/10 =====
# ===== START OF CORE PART 4/10 =====
# coding: utf-8

# ==================== CORE PART 4/10 ====================
# ===== BLOCK: DATABASE SCHEMA (PART 3 — DOCS/PRODUCTS/CALLS/MEETINGS/CHAT/EMBEDDINGS/AGENTS/ETC.) =====
def _pg_schema_part3():
    conn = get_db()
    with conn.cursor() as cur:
        # Documents (templates before documents)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS document_templates (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            tkey TEXT,
            name TEXT NOT NULL,
            body_template TEXT NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            template_id INTEGER REFERENCES document_templates(id) ON DELETE SET NULL,
            doc_type TEXT,
            title TEXT NOT NULL,
            content_html TEXT,
            company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)

        # Products / Calls / Meetings
        cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            sku TEXT,
            name TEXT NOT NULL,
            description TEXT,
            price DOUBLE PRECISION DEFAULT 0,
            currency TEXT DEFAULT 'RUB',
            qty DOUBLE PRECISION DEFAULT 0,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE,
            UNIQUE(org_id, sku)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS calls (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            channel_id INTEGER REFERENCES channels(id) ON DELETE SET NULL,
            external_call_id TEXT,
            direction TEXT,
            from_e164 TEXT,
            to_e164 TEXT,
            agent_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
            contact_id INTEGER REFERENCES contacts(id) ON DELETE SET NULL,
            status TEXT,
            duration_sec INTEGER DEFAULT 0,
            recording_url TEXT,
            started_at TIMESTAMP WITHOUT TIME ZONE,
            ended_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS meetings (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            title TEXT,
            room TEXT NOT NULL,
            start_at TIMESTAMP WITHOUT TIME ZONE,
            end_at TIMESTAMP WITHOUT TIME ZONE,
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            participants_json TEXT DEFAULT '[]',
            recording_started_at TIMESTAMP WITHOUT TIME ZONE,
            recording_stopped_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS meeting_notes (
            id SERIAL PRIMARY KEY,
            meeting_id INTEGER NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
            transcript TEXT,
            summary TEXT,
            action_items_json TEXT,
            key_decisions TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)

        # Chat
        cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_channels (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            type TEXT DEFAULT 'public',
            title TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_members (
            id SERIAL PRIMARY KEY,
            channel_id INTEGER NOT NULL REFERENCES chat_channels(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            department_id INTEGER REFERENCES departments(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id SERIAL PRIMARY KEY,
            channel_id INTEGER NOT NULL REFERENCES chat_channels(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)

        # Embeddings (BYTEA) + optional pgvector backend
        cur.execute("""
        CREATE TABLE IF NOT EXISTS embeddings (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            model TEXT NOT NULL,
            vector BYTEA NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, entity_type, entity_id, model)
        )
        """)
        # Optional pgvector materialization
        try:
            if "VECTOR_BACKEND" in globals() and globals().get("VECTOR_BACKEND") == "pgvector":
                cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
                dim = int(globals().get("EMBEDDINGS_DIM", 384))
                cur.execute(f"""
                CREATE TABLE IF NOT EXISTS embeddings_vec (
                    id SERIAL PRIMARY KEY,
                    org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    model TEXT NOT NULL,
                    v VECTOR({dim}) NOT NULL,
                    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                    UNIQUE(org_id, entity_type, entity_id, model)
                )
                """)
        except Exception as e:
            log("WARN", "pgvector table create failed", error=str(e))

        # Agent / Actions / Approvals
        cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_actions (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            agent_name TEXT NOT NULL,
            action_type TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            reasoning TEXT,
            success BOOLEAN DEFAULT TRUE,
            error TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_approval_requests (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            agent_name TEXT NOT NULL,
            decision_json TEXT NOT NULL,
            context_json TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            approved_at TIMESTAMP WITHOUT TIME ZONE,
            approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS approval_tokens (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            jti TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            revoked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, jti)
        )
        """)

        # Feedback/KPIs/Twin
        cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_feedback (
            id SERIAL PRIMARY KEY,
            ai_job_id INTEGER NOT NULL REFERENCES ai_jobs(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            rating INTEGER,
            correction TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_kpis (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            value_number DOUBLE PRECISION,
            value_text TEXT,
            ts TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS digital_twin_snapshots (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            state_json TEXT NOT NULL,
            health_json TEXT NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)

        # Agent definitions/executions
        cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_definitions (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            description TEXT,
            graph_json TEXT NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_executions (
            id SERIAL PRIMARY KEY,
            agent_id INTEGER NOT NULL REFERENCES agent_definitions(id) ON DELETE CASCADE,
            context_json TEXT NOT NULL,
            result_json TEXT,
            status TEXT DEFAULT 'running',
            started_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            completed_at TIMESTAMP WITHOUT TIME ZONE,
            error TEXT
        )
        """)

        # Collaboration (sessions/changes)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS collaboration_sessions (
            id SERIAL PRIMARY KEY,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            socket_id TEXT,
            cursor_position TEXT,
            last_heartbeat TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS collaboration_changes (
            id SERIAL PRIMARY KEY,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
            change_type TEXT NOT NULL,
            change_data TEXT NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)

        # Custom fields/values
        cur.execute("""
        CREATE TABLE IF NOT EXISTS custom_fields (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            entity_type TEXT NOT NULL,
            name TEXT NOT NULL,
            key TEXT NOT NULL,
            data_type TEXT NOT NULL,
            options_json TEXT,
            required BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, entity_type, key)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS custom_values (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            field_id INTEGER NOT NULL REFERENCES custom_fields(id) ON DELETE CASCADE,
            entity_id INTEGER NOT NULL,
            value_text TEXT,
            value_number DOUBLE PRECISION,
            value_date TIMESTAMP WITHOUT TIME ZONE,
            value_bool BOOLEAN,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE,
            UNIQUE(field_id, entity_id)
        )
        """)
    if not _in_tx():
        conn.commit()


def _sqlite_schema_part3():
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS document_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        tkey TEXT,
        name TEXT NOT NULL,
        body_template TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        template_id INTEGER,
        doc_type TEXT,
        title TEXT NOT NULL,
        content_html TEXT,
        company_id INTEGER,
        user_id INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(template_id) REFERENCES document_templates(id) ON DELETE SET NULL,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        sku TEXT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL DEFAULT 0,
        currency TEXT DEFAULT 'RUB',
        qty REAL DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        UNIQUE(org_id, sku),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        channel_id INTEGER,
        external_call_id TEXT,
        direction TEXT,
        from_e164 TEXT,
        to_e164 TEXT,
        agent_id INTEGER,
        company_id INTEGER,
        contact_id INTEGER,
        status TEXT,
        duration_sec INTEGER DEFAULT 0,
        recording_url TEXT,
        started_at TEXT,
        ended_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS meetings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        title TEXT,
        room TEXT NOT NULL,
        start_at TEXT,
        end_at TEXT,
        created_by INTEGER,
        participants_json TEXT DEFAULT '[]',
        recording_started_at TEXT,
        recording_stopped_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS meeting_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        meeting_id INTEGER NOT NULL,
        transcript TEXT,
        summary TEXT,
        action_items_json TEXT,
        key_decisions TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(meeting_id) REFERENCES meetings(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS chat_channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        type TEXT DEFAULT 'public',
        title TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS chat_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER NOT NULL,
        user_id INTEGER,
        department_id INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER NOT NULL,
        user_id INTEGER,
        body TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS embeddings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER NOT NULL,
        model TEXT NOT NULL,
        vector BLOB NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, entity_type, entity_id, model),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS agent_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        agent_name TEXT NOT NULL,
        action_type TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        reasoning TEXT,
        success INTEGER DEFAULT 1,
        error TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS agent_approval_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        agent_name TEXT NOT NULL,
        decision_json TEXT NOT NULL,
        context_json TEXT,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT (datetime('now')),
        approved_at TEXT,
        approved_by INTEGER,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(approved_by) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS approval_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER NOT NULL,
        jti TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        revoked INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, jti),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS ai_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ai_job_id INTEGER NOT NULL,
        user_id INTEGER,
        rating INTEGER,
        correction TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(ai_job_id) REFERENCES ai_jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS ai_kpis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        value_number REAL,
        value_text TEXT,
        ts TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS digital_twin_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        state_json TEXT NOT NULL,
        health_json TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS agent_definitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        graph_json TEXT NOT NULL,
        active INTEGER DEFAULT 1,
        created_by INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS agent_executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id INTEGER NOT NULL,
        context_json TEXT NOT NULL,
        result_json TEXT,
        status TEXT DEFAULT 'running',
        started_at TEXT DEFAULT (datetime('now')),
        completed_at TEXT,
        error TEXT,
        FOREIGN KEY(agent_id) REFERENCES agent_definitions(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS collaboration_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        socket_id TEXT,
        cursor_position TEXT,
        last_heartbeat TEXT DEFAULT (datetime('now')),
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS collaboration_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        change_type TEXT NOT NULL,
        change_data TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS custom_fields (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        entity_type TEXT NOT NULL,
        name TEXT NOT NULL,
        key TEXT NOT NULL,
        data_type TEXT NOT NULL,
        options_json TEXT,
        required INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, entity_type, key),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS custom_values (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        field_id INTEGER NOT NULL,
        entity_id INTEGER NOT NULL,
        value_text TEXT,
        value_number REAL,
        value_date TEXT,
        value_bool INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        UNIQUE(field_id, entity_id),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(field_id) REFERENCES custom_fields(id) ON DELETE CASCADE
    );
    """)
    if not _in_tx():
        con.commit()


# ===== BLOCK: DATABASE SCHEMA (ADDITIONAL PART 1 — CPQ & CALENDAR) =====
def _pg_schema_additional_part1():
    """CPQ (quotes) and Calendar schema (Postgres)."""
    conn = get_db()
    with conn.cursor() as cur:
        # CPQ: quotes
        cur.execute("""
        CREATE TABLE IF NOT EXISTS quotes (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            deal_id INTEGER REFERENCES deals(id) ON DELETE SET NULL,
            company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
            title TEXT NOT NULL,
            currency TEXT DEFAULT 'RUB',
            total DOUBLE PRECISION DEFAULT 0,
            status TEXT DEFAULT 'draft',
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS quote_items (
            id SERIAL PRIMARY KEY,
            quote_id INTEGER NOT NULL REFERENCES quotes(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
            name TEXT NOT NULL,
            qty DOUBLE PRECISION DEFAULT 1,
            price DOUBLE PRECISION DEFAULT 0,
            discount_pct DOUBLE PRECISION DEFAULT 0,
            total DOUBLE PRECISION DEFAULT 0,
            sort_order INTEGER DEFAULT 0
        )
        """)

        # Calendar
        cur.execute("""
        CREATE TABLE IF NOT EXISTS calendar_events (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,

            title TEXT NOT NULL,
            description TEXT,
            location TEXT,
            event_type TEXT DEFAULT 'meeting',

            start_time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            end_time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            all_day BOOLEAN DEFAULT FALSE,
            timezone TEXT DEFAULT 'UTC',

            recurrence_rule TEXT,
            recurrence_parent_id INTEGER REFERENCES calendar_events(id) ON DELETE CASCADE,
            recurrence_exception_dates TEXT,

            organizer_id INTEGER NOT NULL REFERENCES users(id),

            task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
            deal_id INTEGER REFERENCES deals(id) ON DELETE SET NULL,
            company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,

            status TEXT DEFAULT 'confirmed',
            visibility TEXT DEFAULT 'default',

            reminder_minutes TEXT,
            meeting_url TEXT,
            attachments_json TEXT,
            color TEXT DEFAULT '#3B82F6',

            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            created_by INTEGER REFERENCES users(id)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS event_participants (
            id SERIAL PRIMARY KEY,
            event_id INTEGER NOT NULL REFERENCES calendar_events(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,

            response_status TEXT DEFAULT 'needs-action',
            response_comment TEXT,
            response_time TIMESTAMP WITHOUT TIME ZONE,

            notified_at TIMESTAMP WITHOUT TIME ZONE,
            reminder_sent_at TIMESTAMP WITHOUT TIME ZONE,

            is_required BOOLEAN DEFAULT TRUE,
            can_modify BOOLEAN DEFAULT FALSE,

            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE (event_id, user_id)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS event_reminders (
            id SERIAL PRIMARY KEY,
            event_id INTEGER NOT NULL REFERENCES calendar_events(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,

            reminder_time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            minutes_before INTEGER NOT NULL,

            status TEXT DEFAULT 'pending',
            sent_at TIMESTAMP WITHOUT TIME ZONE,
            delivery_channel TEXT DEFAULT 'notification',

            attempts INTEGER DEFAULT 0,
            last_error TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS calendar_views (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,

            view_type TEXT DEFAULT 'month',
            default_duration INTEGER DEFAULT 60,
            work_hours_start TEXT DEFAULT '09:00',
            work_hours_end TEXT DEFAULT '18:00',
            work_days TEXT DEFAULT '[1,2,3,4,5]',

            visible_calendars TEXT,
            visible_event_types TEXT DEFAULT '["meeting","call","task"]',

            week_starts_on INTEGER DEFAULT 1,
            time_format TEXT DEFAULT '24h',

            updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE (user_id)
        )
        """)
        # Indexes for calendar
        cur.execute("CREATE INDEX IF NOT EXISTS idx_calendar_org_start ON calendar_events(org_id, start_time)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_calendar_organizer ON calendar_events(organizer_id, start_time)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_calendar_task ON calendar_events(task_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_calendar_deal ON calendar_events(deal_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_participant_user ON event_participants(user_id, response_status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reminder_pending ON event_reminders(status, reminder_time)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reminder_event ON event_reminders(event_id)")
    if not _in_tx():
        conn.commit()


def _pg_schema_additional_part2():
    # reserved for future DDL
    return


def _sqlite_schema_additional_part1():
    """CPQ (quotes) and Calendar schema (SQLite)."""
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS quotes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        deal_id INTEGER,
        company_id INTEGER,
        title TEXT NOT NULL,
        currency TEXT DEFAULT 'RUB',
        total REAL DEFAULT 0,
        status TEXT DEFAULT 'draft',
        created_by INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS quote_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        quote_id INTEGER NOT NULL,
        product_id INTEGER,
        name TEXT NOT NULL,
        qty REAL DEFAULT 1,
        price REAL DEFAULT 0,
        discount_pct REAL DEFAULT 0,
        total REAL DEFAULT 0,
        sort_order INTEGER DEFAULT 0,
        FOREIGN KEY(quote_id) REFERENCES quotes(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS calendar_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,

        title TEXT NOT NULL,
        description TEXT,
        location TEXT,
        event_type TEXT DEFAULT 'meeting',

        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        all_day INTEGER DEFAULT 0,
        timezone TEXT DEFAULT 'UTC',

        recurrence_rule TEXT,
        recurrence_parent_id INTEGER,
        recurrence_exception_dates TEXT,

        organizer_id INTEGER NOT NULL,

        task_id INTEGER,
        deal_id INTEGER,
        company_id INTEGER,

        status TEXT DEFAULT 'confirmed',
        visibility TEXT DEFAULT 'default',

        reminder_minutes TEXT,
        meeting_url TEXT,
        attachments_json TEXT,
        color TEXT DEFAULT '#3B82F6',

        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        created_by INTEGER,

        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(organizer_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE SET NULL,
        FOREIGN KEY(deal_id) REFERENCES deals(id) ON DELETE SET NULL,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_calendar_org_start ON calendar_events(org_id, start_time);
    CREATE INDEX IF NOT EXISTS idx_calendar_organizer ON calendar_events(organizer_id, start_time);
    CREATE INDEX IF NOT EXISTS idx_calendar_task ON calendar_events(task_id);
    CREATE INDEX IF NOT EXISTS idx_calendar_deal ON calendar_events(deal_id);

    CREATE TABLE IF NOT EXISTS event_participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,

        response_status TEXT DEFAULT 'needs-action',
        response_comment TEXT,
        response_time TEXT,

        notified_at TEXT,
        reminder_sent_at TEXT,

        is_required INTEGER DEFAULT 1,
        can_modify INTEGER DEFAULT 0,

        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE (event_id, user_id),
        FOREIGN KEY(event_id) REFERENCES calendar_events(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_participant_user ON event_participants(user_id, response_status);

    CREATE TABLE IF NOT EXISTS event_reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,

        reminder_time TEXT NOT NULL,
        minutes_before INTEGER NOT NULL,

        status TEXT DEFAULT 'pending',
        sent_at TEXT,
        delivery_channel TEXT DEFAULT 'notification',

        attempts INTEGER DEFAULT 0,
        last_error TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(event_id) REFERENCES calendar_events(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_reminder_pending ON event_reminders(status, reminder_time);
    CREATE INDEX IF NOT EXISTS idx_reminder_event ON event_reminders(event_id);

    CREATE TABLE IF NOT EXISTS calendar_views (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,

        view_type TEXT DEFAULT 'month',
        default_duration INTEGER DEFAULT 60,
        work_hours_start TEXT DEFAULT '09:00',
        work_hours_end TEXT DEFAULT '18:00',
        work_days TEXT DEFAULT '[1,2,3,4,5]',

        visible_calendars TEXT,
        visible_event_types TEXT DEFAULT '["meeting","call","task"]',

        week_starts_on INTEGER DEFAULT 1,
        time_format TEXT DEFAULT '24h',

        updated_at TEXT DEFAULT (datetime('now')),
        UNIQUE (user_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    if not _in_tx():
        con.commit()


def _sqlite_schema_additional_part2():
    # reserved for future DDL
    return


# ===== BLOCK: DATABASE SCHEMA (ADDITIONAL PART 3 — PAYROLL) =====
def _pg_schema_additional_part3():
    """Payroll schema for flexible compensation plans (Postgres)."""
    conn = get_db()
    with conn.cursor() as cur:
        # Payroll plans
        cur.execute("""
        CREATE TABLE IF NOT EXISTS payroll_plans (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            description TEXT,
            config_json TEXT NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE
        )
        """)
        # Assignment
        cur.execute("""
        CREATE TABLE IF NOT EXISTS payroll_assignments (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            plan_id INTEGER NOT NULL REFERENCES payroll_plans(id) ON DELETE CASCADE,
            effective_from TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            effective_to TIMESTAMP WITHOUT TIME ZONE,
            quota_number DOUBLE PRECISION,
            team_leader BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, user_id, plan_id, effective_from)
        )
        """)
        # Periods
        cur.execute("""
        CREATE TABLE IF NOT EXISTS payroll_periods (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            period_key TEXT NOT NULL,
            date_start TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            date_end TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            locked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, period_key)
        )
        """)
        # Metrics
        cur.execute("""
        CREATE TABLE IF NOT EXISTS payroll_metrics (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            period_id INTEGER NOT NOT NULL REFERENCES payroll_periods(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            deals_amount DOUBLE PRECISION DEFAULT 0,
            deals_margin DOUBLE PRECISION DEFAULT 0,
            tasks_done INTEGER DEFAULT 0,
            calls_made INTEGER DEFAULT 0,
            kpi_json TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, period_id, user_id)
        )
        """)
        # Payouts
        cur.execute("""
        CREATE TABLE IF NOT EXISTS payroll_payouts (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            period_id INTEGER NOT NULL REFERENCES payroll_periods(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            plan_id INTEGER REFERENCES payroll_plans(id) ON DELETE SET NULL,
            gross_amount DOUBLE PRECISION DEFAULT 0,
            bonus_amount DOUBLE PRECISION DEFAULT 0,
            penalty_amount DOUBLE PRECISION DEFAULT 0,
            net_amount DOUBLE PRECISION DEFAULT 0,
            breakdown_json TEXT,
            status TEXT DEFAULT 'draft',
            approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            approved_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            UNIQUE(org_id, period_id, user_id)
        )
        """)
    if not _in_tx():
        conn.commit()


def _sqlite_schema_additional_part3():
    """Payroll schema for flexible compensation plans (SQLite)."""
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS payroll_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        config_json TEXT NOT NULL,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS payroll_assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        plan_id INTEGER NOT NULL,
        effective_from TEXT NOT NULL,
        effective_to TEXT,
        quota_number REAL,
        team_leader INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, user_id, plan_id, effective_from),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(plan_id) REFERENCES payroll_plans(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS payroll_periods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        period_key TEXT NOT NULL,
        date_start TEXT NOT NULL,
        date_end TEXT NOT NULL,
        locked INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, period_key),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS payroll_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        period_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        deals_amount REAL DEFAULT 0,
        deals_margin REAL DEFAULT 0,
        tasks_done INTEGER DEFAULT 0,
        calls_made INTEGER DEFAULT 0,
        kpi_json TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, period_id, user_id),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(period_id) REFERENCES payroll_periods(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS payroll_payouts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        period_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        plan_id INTEGER,
        gross_amount REAL DEFAULT 0,
        bonus_amount REAL DEFAULT 0,
        penalty_amount REAL DEFAULT 0,
        net_amount REAL DEFAULT 0,
        breakdown_json TEXT,
        status TEXT DEFAULT 'draft',
        approved_by INTEGER,
        approved_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org_id, period_id, user_id),
        FOREIGN KEY(org_id) REFERENCES orgs(id) ON DELETE CASCADE,
        FOREIGN KEY(period_id) REFERENCES payroll_periods(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(plan_id) REFERENCES payroll_plans(id) ON DELETE SET NULL
    );
    """)
    if not _in_tx():
        con.commit()


# ===== BLOCK: INDEXES (PART 2 + PART 3 + PART 4 HOT-PATH) =====
def _pg_indexes_part2():
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_docs_org ON documents(org_id, created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_products_org ON products(org_id, name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_calls_started ON calls(org_id, started_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_meetings_org ON meetings(org_id, start_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_channel ON chat_messages(channel_id, created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_embeddings_entity ON embeddings(org_id, entity_type, entity_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_agent_actions_org ON agent_actions(org_id, created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_quotes_org ON quotes(org_id, created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_quote_items_quote ON quote_items(quote_id, sort_order)")
        # additional/misc (guarded)
        try:
            cur.execute("CREATE INDEX IF NOT EXISTS idx_workflow_tasks_status ON workflow_tasks(status, scheduled_at)")
        except Exception:
            pass
        try:
            cur.execute("CREATE INDEX IF NOT EXISTS idx_saved_views ON saved_views(org_id, user_id, entity_type)")
        except Exception:
            pass
        try:
            cur.execute("CREATE INDEX IF NOT EXISTS idx_activity_org ON activity_timeline(org_id, created_at)")
        except Exception:
            pass
        # pgvector indexes (optional)
        if "VECTOR_BACKEND" in globals() and globals().get("VECTOR_BACKEND") == "pgvector":
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS idx_embeddings_vec_ivf ON embeddings_vec USING ivfflat (v) WITH (lists = 100)")
            except Exception as e:
                log("WARN", "pgvector index failed", error=str(e))
    if not _in_tx():
        conn.commit()


def _pg_indexes_part3():
    if DIALECT != "postgres":
        return
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_org_status_due ON tasks(org_id, status, due_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threads_org_assignee_status_last ON inbox_threads(org_id, assignee_id, status, last_message_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_deals_org_status_stage_created ON deals(org_id, status, stage, created_at)")
        try:
            cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_open_partial ON tasks(org_id, due_at) WHERE status NOT IN ('done','cancelled')")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_threads_last_notnull ON inbox_threads(last_message_at) WHERE last_message_at IS NOT NULL")
        except Exception:
            pass
    if not _in_tx():
        conn.commit()


def _pg_indexes_part4():
    """Hot-path composite/covering indexes for frequent filters."""
    if DIALECT != "postgres":
        return
    conn = get_db()
    with conn.cursor() as cur:
        # Inbox list filters: org, status, assignee, last message
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_threads_hot
        ON inbox_threads(org_id, status, assignee_id, last_message_at DESC)
        """)
        # Tasks common filters
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_tasks_hot
        ON tasks(org_id, assignee_id, status, created_at DESC)
        """)
        # Deals kanban filters
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_deals_hot
        ON deals(org_id, pipeline_key, status, stage, created_at DESC)
        """)
    if not _in_tx():
        conn.commit()


def _sqlite_indexes_part2():
    con = get_db()
    con.executescript("""
    CREATE INDEX IF NOT EXISTS idx_docs_org ON documents(org_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_products_org ON products(org_id, name);
    CREATE INDEX IF NOT EXISTS idx_calls_started ON calls(org_id, started_at);
    CREATE INDEX IF NOT EXISTS idx_meetings_org ON meetings(org_id, start_at);
    CREATE INDEX IF NOT EXISTS idx_chat_channel ON chat_messages(channel_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_embeddings_entity ON embeddings(org_id, entity_type, entity_id);
    CREATE INDEX IF NOT EXISTS idx_agent_actions_org ON agent_actions(org_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_quotes_org ON quotes(org_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_quote_items_quote ON quote_items(quote_id, sort_order);
    """)
    # Guarded indices for optional tables
    try:
        exec_db_affect("CREATE INDEX IF NOT EXISTS idx_workflow_tasks_status ON workflow_tasks(status, scheduled_at)")
    except Exception:
        pass
    try:
        exec_db_affect("CREATE INDEX IF NOT EXISTS idx_saved_views ON saved_views(org_id, user_id, entity_type)")
    except Exception:
        pass
    try:
        exec_db_affect("CREATE INDEX IF NOT EXISTS idx_activity_org ON activity_timeline(org_id, created_at)")
    except Exception:
        pass
    # campaign_events/ab_results likely absent — skip safely
    if not _in_tx():
        con.commit()


def _sqlite_indexes_part3():
    con = get_db()
    con.executescript("""
    CREATE INDEX IF NOT EXISTS idx_tasks_org_status_due ON tasks(org_id, status, due_at);
    CREATE INDEX IF NOT EXISTS idx_threads_org_assignee_status_last ON inbox_threads(org_id, assignee_id, status, last_message_at);
    CREATE INDEX IF NOT EXISTS idx_deals_org_status_stage_created ON deals(org_id, status, stage, created_at);
    """)
    if not _in_tx():
        con.commit()


def _sqlite_indexes_part4():
    con = get_db()
    con.executescript("""
    CREATE INDEX IF NOT EXISTS idx_threads_hot ON inbox_threads(org_id, status, assignee_id, last_message_at);
    CREATE INDEX IF NOT EXISTS idx_tasks_hot ON tasks(org_id, assignee_id, status, created_at);
    CREATE INDEX IF NOT EXISTS idx_deals_hot ON deals(org_id, pipeline_key, status, stage, created_at);
    """)
    if not _in_tx():
        con.commit()


# ===== BLOCK: FTS (PG & SQLite) =====
def _pg_fts_part1():
    """
    Postgres FTS с использованием словаря 'russian' вместо 'simple' для лучшей поддержки русскоязычных данных.
    """
    conn = get_db()
    with conn.cursor() as cur:
        # inbox_messages FTS
        cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid
                WHERE c.relname='inbox_messages' AND a.attname='fts'
            ) THEN
                ALTER TABLE inbox_messages ADD COLUMN fts tsvector;
            END IF;
        END $$;
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_inbox_messages_fts ON inbox_messages USING GIN(fts)")
        cur.execute("""
        CREATE OR REPLACE FUNCTION inbox_messages_fts_trigger() RETURNS trigger AS $$
        begin
            new.fts := to_tsvector('russian', coalesce(new.body,'') || ' ' || coalesce(new.external_user_id,''));
            return new;
        end
        $$ LANGUAGE plpgsql;
        """)
        cur.execute("""
        DROP TRIGGER IF EXISTS trg_inbox_messages_fts ON inbox_messages;
        CREATE TRIGGER trg_inbox_messages_fts BEFORE INSERT OR UPDATE ON inbox_messages
        FOR EACH ROW EXECUTE FUNCTION inbox_messages_fts_trigger();
        """)

        # tasks FTS
        cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid
                WHERE c.relname='tasks' AND a.attname='fts'
            ) THEN
                ALTER TABLE tasks ADD COLUMN fts tsvector;
            END IF;
        END $$;
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_fts ON tasks USING GIN(fts)")
        cur.execute("""
        CREATE OR REPLACE FUNCTION tasks_fts_trigger() RETURNS trigger AS $$
        begin
            new.fts := to_tsvector('russian', coalesce(new.title,'') || ' ' || coalesce(new.description,''));
            return new;
        end
        $$ LANGUAGE plpgsql;
        """)
        cur.execute("""
        DROP TRIGGER IF EXISTS trg_tasks_fts ON tasks;
        CREATE TRIGGER trg_tasks_fts BEFORE INSERT OR UPDATE ON tasks
        FOR EACH ROW EXECUTE FUNCTION tasks_fts_trigger();
        """)

        # chat_messages FTS
        cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid
                WHERE c.relname='chat_messages' AND a.attname='fts'
            ) THEN
                ALTER TABLE chat_messages ADD COLUMN fts tsvector;
            END IF;
        END $$;
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_fts ON chat_messages USING GIN(fts)")
        cur.execute("""
        CREATE OR REPLACE FUNCTION chat_messages_fts_trigger() RETURNS trigger AS $$
        begin
            new.fts := to_tsvector('russian', coalesce(new.body,''));
            return new;
        end
        $$ LANGUAGE plpgsql;
        """)
        cur.execute("""
        DROP TRIGGER IF EXISTS trg_chat_messages_fts ON chat_messages;
        CREATE TRIGGER trg_chat_messages_fts BEFORE INSERT OR UPDATE ON chat_messages
        FOR EACH ROW EXECUTE FUNCTION chat_messages_fts_trigger();
        """)
    if not _in_tx():
        conn.commit()


def _sqlite_fts_part1():
    con = get_db()
    cur = con.cursor()
    try:
        # virtual tables
        cur.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS fts_inbox_messages USING fts5(
            body, external_user_id,
            content='inbox_messages', content_rowid='id'
        )
        """)
        cur.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS fts_tasks USING fts5(
            title, description,
            content='tasks', content_rowid='id'
        )
        """)
        cur.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS fts_chat_messages USING fts5(
            body,
            content='chat_messages', content_rowid='id'
        )
        """)
        # triggers inbox_messages
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_inbox_messages_ai
        AFTER INSERT ON inbox_messages BEGIN
            INSERT INTO fts_inbox_messages(rowid, body, external_user_id)
            VALUES (new.id, COALESCE(new.body,''), COALESCE(new.external_user_id,''));
        END;
        """)
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_inbox_messages_au
        AFTER UPDATE ON inbox_messages BEGIN
            INSERT INTO fts_inbox_messages(fts_inbox_messages, rowid, body, external_user_id)
            VALUES('delete', old.id, '', '');
            INSERT INTO fts_inbox_messages(rowid, body, external_user_id)
            VALUES (new.id, COALESCE(new.body,''), COALESCE(new.external_user_id,''));
        END;
        """)
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_inbox_messages_ad
        AFTER DELETE ON inbox_messages BEGIN
            INSERT INTO fts_inbox_messages(fts_inbox_messages, rowid, body, external_user_id)
            VALUES('delete', old.id, '', '');
        END;
        """)
        # triggers tasks
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_tasks_ai
        AFTER INSERT ON tasks BEGIN
            INSERT INTO fts_tasks(rowid, title, description)
            VALUES (new.id, COALESCE(new.title,''), COALESCE(new.description,''));
        END;
        """)
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_tasks_au
        AFTER UPDATE ON tasks BEGIN
            INSERT INTO fts_tasks(fts_tasks, rowid, title, description)
            VALUES('delete', old.id, '', '');
            INSERT INTO fts_tasks(rowid, title, description)
            VALUES (new.id, COALESCE(new.title,''), COALESCE(new.description,''));
        END;
        """)
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_tasks_ad
        AFTER DELETE ON tasks BEGIN
            INSERT INTO fts_tasks(fts_tasks, rowid, title, description)
            VALUES('delete', old.id, '', '');
        END;
        """)
        # triggers chat_messages
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_chat_messages_ai
        AFTER INSERT ON chat_messages BEGIN
            INSERT INTO fts_chat_messages(rowid, body)
            VALUES (new.id, COALESCE(new.body,''));
        END;
        """)
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_chat_messages_au
        AFTER UPDATE ON chat_messages BEGIN
            INSERT INTO fts_chat_messages(fts_chat_messages, rowid, body)
            VALUES('delete', old.id, '');
            INSERT INTO fts_chat_messages(rowid, body)
            VALUES (new.id, COALESCE(new.body,''));
        END;
        """)
        cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_fts_chat_messages_ad
        AFTER DELETE ON chat_messages BEGIN
            INSERT INTO fts_chat_messages(fts_chat_messages, rowid, body)
            VALUES('delete', old.id, '');
        END;
        """)
        if not _in_tx():
            con.commit()
    except Exception as e:
        try:
            con.rollback()
        except Exception:
            pass
        log("ERROR", "ensure_fts_sqlite failed", error=str(e))
        raise

# ===== END OF CORE PART 4/10 =====
# ==================== CORE PART 5/10 ====================
# ===== BLOCK: AI PROVIDER =====
# Defaults for AI/Embeddings (define if not set earlier)
if "EMBEDDINGS_MODEL" not in globals():
    EMBEDDINGS_MODEL = os.getenv("EMBEDDINGS_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
if "EMBEDDINGS_BATCH_SIZE" not in globals():
    EMBEDDINGS_BATCH_SIZE = int(os.getenv("EMBEDDINGS_BATCH_SIZE", "32"))
if "VECTOR_SEARCH_TOP_K" not in globals():
    VECTOR_SEARCH_TOP_K = int(os.getenv("VECTOR_SEARCH_TOP_K", "10"))
if "VECTOR_BACKEND" not in globals():
    VECTOR_BACKEND = os.getenv("VECTOR_BACKEND", "memory")  # memory|pgvector|qdrant
if "EMBEDDINGS_DIM" not in globals():
    EMBEDDINGS_DIM = int(os.getenv("EMBEDDINGS_DIM", "384"))
if "VECTOR_FALLBACK_MAX_ROWS" not in globals():
    VECTOR_FALLBACK_MAX_ROWS = int(os.getenv("VECTOR_FALLBACK_MAX_ROWS", "1000"))

# Optional deps flags (lazy)
NUMPY_AVAILABLE = False
SENTENCE_TRANSFORMERS_AVAILABLE = False
QDRANT_AVAILABLE = False

# ----- AI Circuit Breaker -----
_ai_cb_lock = threading.Lock()
_ai_cb_state = {"failures": 0, "last_failure_time": 0.0, "open": False}

def _ai_cb_allow() -> bool:
    with _ai_cb_lock:
        if not _ai_cb_state["open"]:
            return True
        if (time.time() - _ai_cb_state["last_failure_time"]) > AI_CIRCUIT_BREAKER_TIMEOUT:
            _ai_cb_state["open"] = False
            _ai_cb_state["failures"] = 0
            log("INFO", "AI circuit breaker closed")
            return True
        return False

def _ai_cb_success():
    with _ai_cb_lock:
        if _ai_cb_state["failures"] > 0:
            _ai_cb_state["failures"] = max(0, _ai_cb_state["failures"] - 1)

def _ai_cb_failure():
    with _ai_cb_lock:
        _ai_cb_state["failures"] += 1
        _ai_cb_state["last_failure_time"] = time.time()
        if _ai_cb_state["failures"] >= AI_CIRCUIT_BREAKER_THRESHOLD:
            _ai_cb_state["open"] = True
            log("WARN", "AI circuit breaker opened", failures=_ai_cb_state["failures"])

def _ai_request(provider: str, model: str, messages: List[dict], temperature: float, max_tokens: int, stream: bool = False):
    if not AI_API_KEY:
        raise RuntimeError("AI_API_KEY not set")
    if _rq is None:
        raise RuntimeError("requests module unavailable")

    headers: Dict[str, str] = {}
    url = ""
    payload: Dict[str, Any] = {}

    if provider == "openai":
        headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
        url = "https://api.openai.com/v1/chat/completions"
        payload = {"model": model, "messages": messages, "temperature": float(temperature), "max_tokens": int(max_tokens)}
        if stream:
            payload["stream"] = True
    elif provider == "anthropic":
        headers = {"x-api-key": AI_API_KEY, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        url = "https://api.anthropic.com/v1/messages"
        sys_msg = next((m.get("content", "") for m in messages if m.get("role") == "system"), "")
        non_sys = [m for m in messages if m.get("role") != "system"]
        payload = {
            "model": model,
            "max_tokens": int(max_tokens),
            "temperature": float(temperature),
            "system": sys_msg,
            "messages": non_sys
        }
    else:
        raise ValueError(f"Unknown AI provider: {provider}")

    tracer = get_tracer()
    span_ctx = None
    if tracer:
        span_ctx = tracer.start_as_current_span("ai.completion")  # type: ignore
        span_ctx.__enter__()  # type: ignore
        try:
            from opentelemetry import trace as _trace  # type: ignore
            _trace.get_current_span().set_attribute("ai.provider", provider)  # type: ignore
            _trace.get_current_span().set_attribute("ai.model", model)  # type: ignore
            _trace.get_current_span().set_attribute("ai.streaming", bool(stream))  # type: ignore
        except Exception:
            pass

    try:
        if stream and provider == "openai":
            r = _rq.post(url, headers=headers, json=payload, timeout=60, stream=True)
            if r.status_code != 200:
                raise RuntimeError(f"AI stream error: {r.status_code} {r.text[:200]}")
            try:
                for line in r.iter_lines():
                    if not line:
                        continue
                    try:
                        s = line.decode("utf-8")
                    except Exception:
                        continue
                    if s.startswith("data: "):
                        s = s[6:]
                    if s.strip() == "" or s == "[DONE]":
                        if s == "[DONE]":
                            break
                        continue
                    try:
                        obj = json.loads(s)
                        delta = obj.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content")
                        if content:
                            yield content
                    except Exception:
                        continue
            finally:
                try:
                    r.close()
                except Exception:
                    pass
            return
        else:
            r = _rq.post(url, headers=headers, json=payload, timeout=60)
            if r.status_code != 200:
                raise RuntimeError(f"AI API error: {r.status_code} {r.text[:200]}")
            data = r.json()
            if provider == "openai":
                return data["choices"][0]["message"]["content"]
            else:
                return (data.get("content") or [{}])[0].get("text", "")
    finally:
        if span_ctx:
            span_ctx.__exit__(None, None, None)  # type: ignore

def ai_provider_call(prompt: str, system: str = "", model: Optional[str] = None,
                     temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> str:
    if not _ai_cb_allow():
        raise RuntimeError("AI circuit breaker is open")
    model = model or AI_MODEL
    temperature = AI_TEMPERATURE if temperature is None else float(temperature)
    max_tokens = max_tokens or AI_MAX_TOKENS
    messages: List[dict] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    _increment_metric("api_calls_total", {"provider": AI_PROVIDER, "model": model})
    backoff = AI_RETRY_BACKOFF_SECS
    last_err = None
    for attempt in range(AI_MAX_RETRIES + 1):
        try:
            res = _ai_request(AI_PROVIDER, model, messages, temperature, max_tokens, stream=False)
            _ai_cb_success()
            return res or ""
        except Exception as e:
            last_err = e
            _ai_cb_failure()
            if attempt >= AI_MAX_RETRIES:
                break
            sleep_for = min(10.0, backoff * (2 ** attempt)) + (uuid.uuid4().int % 250) / 1000.0
            time.sleep(sleep_for)
    raise RuntimeError(f"AI request failed after retries: {last_err}")

def ai_provider_call_streaming(prompt: str, system: str = "", model: Optional[str] = None,
                               temperature: Optional[float] = None, max_tokens: Optional[int] = None):
    if not AI_STREAMING_ENABLED:
        yield ai_provider_call(prompt, system=system, model=model, temperature=temperature, max_tokens=max_tokens)
        return
    if not _ai_cb_allow():
        raise RuntimeError("AI circuit breaker is open")
    model = model or AI_MODEL
    temperature = AI_TEMPERATURE if temperature is None else float(temperature)
    max_tokens = max_tokens or AI_MAX_TOKENS
    messages: List[dict] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        if AI_PROVIDER == "openai":
            for chunk in _ai_request(AI_PROVIDER, model, messages, temperature, max_tokens, stream=True):  # type: ignore
                yield chunk
        else:
            yield ai_provider_call(prompt, system=system, model=model, temperature=temperature, max_tokens=max_tokens)
        _ai_cb_success()
    except Exception as e:
        _ai_cb_failure()
        raise

def truncate_for_ai_context(text: str, max_chars: int = 8000) -> str:
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n[... truncated ...]"

# ===== BLOCK: EMBEDDINGS & VECTOR SEARCH (memory|pgvector|qdrant) =====
# Lazy optional imports
def _ensure_numpy():
    global NUMPY_AVAILABLE, np
    if NUMPY_AVAILABLE:
        return
    try:
        import numpy as np  # type: ignore
        NUMPY_AVAILABLE = True
    except Exception:
        NUMPY_AVAILABLE = False

def _ensure_st_model():
    global SENTENCE_TRANSFORMERS_AVAILABLE, SentenceTransformer
    if SENTENCE_TRANSFORMERS_AVAILABLE:
        return
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
        SENTENCE_TRANSFORMERS_AVAILABLE = True
    except Exception:
        SENTENCE_TRANSFORMERS_AVAILABLE = False

def _ensure_qdrant():
    global QDRANT_AVAILABLE, QdrantClient, qmodels
    if QDRANT_AVAILABLE:
        return
    try:
        from qdrant_client import QdrantClient  # type: ignore
        from qdrant_client.http import models as qmodels  # type: ignore
        QDRANT_AVAILABLE = True
    except Exception:
        QDRANT_AVAILABLE = False

_embeddings_model = None
_embeddings_lock = threading.Lock()

def get_embeddings_model():
    global _embeddings_model
    _ensure_st_model()
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        return None
    with _embeddings_lock:
        if _embeddings_model is None:
            try:
                _embeddings_model = SentenceTransformer(EMBEDDINGS_MODEL)
                log("INFO", "Embeddings model loaded", model=EMBEDDINGS_MODEL)
            except Exception as e:
                log("ERROR", "Embeddings model load failed", error=str(e))
                return None
    return _embeddings_model

def _to_bytes_vector(vec: List[float]) -> bytes:
    _ensure_numpy()
    if NUMPY_AVAILABLE:
        try:
            arr = np.array(vec, dtype=np.float32)  # type: ignore
            return arr.tobytes(order="C")
        except Exception:
            pass
    return json.dumps(vec).encode("utf-8")

def _from_bytes_vector(b: bytes) -> Optional[List[float]]:
    if not b:
        return None
    _ensure_numpy()
    if NUMPY_AVAILABLE:
        try:
            arr = np.frombuffer(b, dtype=np.float32)  # type: ignore
            return arr.tolist()  # type: ignore
        except Exception:
            pass
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return None

def generate_embedding(text: str) -> Optional[List[float]]:
    model = get_embeddings_model()
    if model is None:
        return None
    try:
        vector = model.encode([text])[0]
        if hasattr(vector, "tolist"):
            vector = vector.tolist()
        _ensure_numpy()
        if NUMPY_AVAILABLE:
            arr = np.array(vector, dtype=np.float32)  # type: ignore
            # normalize
            norm = float((arr ** 2).sum() ** 0.5)
            if norm > 0:
                arr = arr / norm
            out = arr.astype(np.float32).tolist()  # type: ignore
        else:
            out = list(vector)  # type: ignore
        # Sanity check
        if not out or not isinstance(out, list):
            return None
        return out
    except Exception as e:
        log("ERROR", "Embedding generation failed", error=str(e))
        return None

def _qdrant_client() -> Optional["QdrantClient"]:
    _ensure_qdrant()
    if not QDRANT_AVAILABLE:
        return None
    try:
        client = QdrantClient(url=os.getenv("QDRANT_URL", "http://localhost:6333"),
                              api_key=os.getenv("QDRANT_API_KEY") or None)
        return client
    except Exception as e:
        log("WARN", "Qdrant client init failed", error=str(e))
        return None

def _qdrant_ensure_collection(client: "QdrantClient", collection: str, dim: int):
    try:
        _ensure_qdrant()
        if not QDRANT_AVAILABLE:
            return
        from qdrant_client.http.models import Distance, VectorParams  # type: ignore
        exists = False
        need_recreate = False
        try:
            info = client.get_collection(collection_name=collection)
            exists = bool(info)
            # validate vector size
            try:
                current = int(info.config.params.vectors.size)  # type: ignore
                if current != dim:
                    need_recreate = True
            except Exception:
                need_recreate = True
        except Exception:
            exists = False
        if exists and need_recreate:
            log("WARN", "Qdrant collection dim mismatch, recreating", collection=collection, want=dim)
            client.recreate_collection(
                collection_name=collection,
                vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
            )
        if not exists:
            client.recreate_collection(
                collection_name=collection,
                vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
            )
    except Exception as e:
        log("WARN", "Qdrant ensure collection failed", error=str(e), collection=collection)

def _qdrant_point_id(org_id: int, entity_type: str, entity_id: int) -> int:
    key = f"{int(org_id)}:{entity_type}:{int(entity_id)}"
    h = hashlib.md5(key.encode("utf-8")).hexdigest()
    return int(h[:16], 16) % (2**63 - 1)

def store_embedding(org_id: int, entity_type: str, entity_id: int, text: str):
    vec = generate_embedding(text)
    if vec is None:
        return
    try:
        blob = _to_bytes_vector(vec)
        # Store BYTEA/BLOB fallback for all cases
        if DIALECT == "postgres":
            exec_db(
                "INSERT INTO embeddings (org_id, entity_type, entity_id, model, vector, created_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (org_id, entity_type, entity_id, model) DO UPDATE SET vector=EXCLUDED.vector, created_at=EXCLUDED.created_at",
                (org_id, entity_type, entity_id, EMBEDDINGS_MODEL, blob, utc_now())
            )
        else:
            exec_db(
                "INSERT OR REPLACE INTO embeddings (org_id, entity_type, entity_id, model, vector, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (org_id, entity_type, entity_id, EMBEDDINGS_MODEL, blob, utc_now())
            )
        # Optional pgvector store: only if dimension matches
        if DIALECT == "postgres" and globals().get("VECTOR_BACKEND") == "pgvector":
            try:
                want_dim = int(globals().get("EMBEDDINGS_DIM", 384))
                if len(vec) != want_dim:
                    log("WARN", "pgvector skip due to dim mismatch", have=len(vec), want=want_dim)
                else:
                    vec_lit = "[" + ",".join(str(float(x)) for x in vec) + "]"
                    exec_db(
                        "INSERT INTO embeddings_vec (org_id, entity_type, entity_id, model, v, created_at) "
                        "VALUES (?, ?, ?, ?, %s::vector, ?) "
                        "ON CONFLICT (org_id, entity_type, entity_id, model) DO UPDATE SET v=EXCLUDED.v, created_at=EXCLUDED.created_at",  # type: ignore
                        (org_id, entity_type, entity_id, EMBEDDINGS_MODEL, vec_lit, utc_now())
                    )
            except Exception as e:
                log("WARN", "pgvector store failed; continue with BYTEA", error=str(e))
        # Optional Qdrant
        if VECTOR_BACKEND == "qdrant":
            client = _qdrant_client()
            if not client:
                return
            try:
                coll = "crm_embeddings"
                dim = len(vec)
                _qdrant_ensure_collection(client, coll, dim=dim)
                payload = {"org_id": int(org_id), "entity_type": entity_type, "entity_id": int(entity_id), "model": EMBEDDINGS_MODEL}
                pid = _qdrant_point_id(org_id, entity_type, entity_id)
                _ensure_qdrant()
                if QDRANT_AVAILABLE:
                    client.upsert(  # type: ignore
                        collection_name=coll,
                        points=[qmodels.PointStruct(id=pid, vector=vec, payload=payload)]  # type: ignore
                    )
            except Exception as e:
                log("WARN", "Qdrant upsert failed", error=str(e))
    except Exception as e:
        log("ERROR", "Store embedding failed", error=str(e))

def vector_search(org_id: int, query_text: str, entity_type: Optional[str] = None, top_k: Optional[int] = None) -> List[dict]:
    top_k = int(top_k or VECTOR_SEARCH_TOP_K)
    q_vec = generate_embedding(query_text)
    if q_vec is None:
        return []

    # Qdrant
    if VECTOR_BACKEND == "qdrant":
        client = _qdrant_client()
        if not client:
            return []
        try:
            coll = "crm_embeddings"
            _qdrant_ensure_collection(client, coll, dim=len(q_vec))
            _ensure_qdrant()
            if not QDRANT_AVAILABLE:
                return []
            must: List[Any] = [qmodels.FieldCondition(key="org_id", match=qmodels.MatchValue(value=int(org_id)))]  # type: ignore
            if entity_type:
                must.append(qmodels.FieldCondition(key="entity_type", match=qmodels.MatchValue(value=entity_type)))  # type: ignore
            flt = qmodels.Filter(must=must)  # type: ignore
            res = client.search(collection_name=coll, query_vector=q_vec, limit=top_k, query_filter=flt)
            out = []
            for p in res or []:
                payload = p.payload or {}
                out.append({"entity_type": payload.get("entity_type"), "entity_id": payload.get("entity_id"), "score": float(p.score or 0)})
            return out
        except Exception as e:
            log("WARN", "Qdrant search failed", error=str(e))
            return []

    # BYTEA/BLOB fallback with CPU cosine
    if DIALECT in ("postgres", "sqlite"):
        where = ["org_id=?", "model=?"]
        params: List[Any] = [org_id, EMBEDDINGS_MODEL]
        if entity_type:
            where.append("entity_type=?")
            params.append(entity_type)
        rows = query_db(
            f"SELECT entity_type, entity_id, vector FROM embeddings WHERE {' AND '.join(where)} LIMIT {max(1, VECTOR_FALLBACK_MAX_ROWS)}",
            tuple(params)
        ) or []
        if not rows:
            return []
        _ensure_numpy()
        if not NUMPY_AVAILABLE:
            return []
        sims: List[Tuple[float, dict]] = []
        q_arr = np.array(q_vec, dtype=np.float32)  # type: ignore
        q_norm = float((q_arr ** 2).sum() ** 0.5)
        for r in rows:
            try:
                v = _from_bytes_vector(r["vector"])
                if not v:
                    continue
                v_arr = np.array(v, dtype=np.float32)  # type: ignore
                denom = (q_norm * float((v_arr ** 2).sum() ** 0.5))
                sim = float(q_arr.dot(v_arr) / denom) if denom > 0 else 0.0  # type: ignore
                sims.append((sim, {"entity_type": r["entity_type"], "entity_id": r["entity_id"], "score": sim}))
            except Exception:
                continue
        sims.sort(key=lambda t: t[0], reverse=True)
        return [x for _, x in sims[:top_k]]
    return []

# ===== RAG helpers =====
def rag_index_text(org_id: int, entity_type: str, entity_id: int, text: str):
    try:
        store_embedding(org_id, entity_type, entity_id, text)
    except Exception as e:
        log("WARN", "rag_index_text failed", error=str(e))

def rag_answer(org_id: int, query_text: str, top_k: int = 5, entity_type: Optional[str] = None) -> dict:
    try:
        hits = vector_search(org_id, query_text, entity_type=entity_type, top_k=top_k)
        contexts: List[str] = []
        for h in hits:
            et, eid = h.get("entity_type"), int(h.get("entity_id") or 0)
            body = ""
            if et == "kb_doc":
                row = query_db("SELECT body FROM kb_docs WHERE id=? AND org_id=?", (eid, org_id), one=True)
                body = (row or {}).get("body") or ""
            elif et == "inbox_message":
                row = query_db("SELECT body FROM inbox_messages WHERE id=?", (eid,), one=True)
                body = (row or {}).get("body") or ""
            elif et == "chat_message":
                row = query_db("SELECT body FROM chat_messages WHERE id=?", (eid,), one=True)
                body = (row or {}).get("body") or ""
            if body:
                contexts.append(truncate_for_ai_context(body, 1200))
        context_block = "\n\n---\n".join(contexts[:5]) if contexts else ""
        prompt = (
            "На основе контекста ответь на вопрос. Если ответа нет в тексте — скажи, что данных недостаточно.\n"
            f"Вопрос: {query_text}\n\nКонтекст:\n{context_block}"
        )
        answer = ai_provider_call(prompt, system="Отвечай кратко, по-деловому. Добавь источники (перечисли).", temperature=0.2, max_tokens=300)
        return {"ok": True, "answer": answer, "sources": hits[:5]}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ===== BLOCK: SAFE EVALUATOR (ZERO-CODE) =====
import ast

class SafeEvaluator(ast.NodeVisitor):
    ALLOWED_NODES = {
        ast.Module, ast.Expr, ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare,
        ast.Name, ast.Load, ast.Constant, ast.And, ast.Or, ast.Not,
        ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE, ast.In, ast.NotIn,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.USub
    }
    MAX_LEN = 512
    MAX_DEPTH = 32

    def __init__(self, context: dict = None):
        self.context = context or {}
        self._depth = 0

    def generic_visit(self, node):
        self._depth += 1
        if self._depth > self.MAX_DEPTH:
            raise ValueError("Expression too deep")
        try:
            super().generic_visit(node)
        finally:
            self._depth -= 1

    def visit(self, node):
        if type(node) not in self.ALLOWED_NODES:
            raise ValueError(f"Unsafe expression node: {type(node).__name__}")
        return super().visit(node)

    def eval(self, expr: str) -> Any:
        expr = (expr or "").strip()
        if not expr:
            return True
        if len(expr) > self.MAX_LEN:
            raise ValueError("Expression too long")
        tree = ast.parse(expr, mode="eval")
        self.visit(tree)
        return self._eval_node(tree.body)

    def _eval_node(self, node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self.context.get(node.id)
        if isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            if isinstance(node.op, ast.Add): return left + right
            if isinstance(node.op, ast.Sub): return left - right
            if isinstance(node.op, ast.Mult): return left * right
            if isinstance(node.op, ast.Div): return left / right
            if isinstance(node.op, ast.Mod): return left % right
        if isinstance(node, ast.UnaryOp):
            operand = self._eval_node(node.operand)
            if isinstance(node.op, ast.USub): return -operand
            if isinstance(node.op, ast.Not): return not operand
        if isinstance(node, ast.BoolOp):
            vals = [self._eval_node(v) for v in node.values]
            if isinstance(node.op, ast.And): return all(vals)
            if isinstance(node.op, ast.Or): return any(vals)
        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_node(comparator)
                if isinstance(op, ast.Eq) and not (left == right): return False
                if isinstance(op, ast.NotEq) and not (left != right): return False
                if isinstance(op, ast.Gt) and not (left > right): return False
                if isinstance(op, ast.GtE) and not (left >= right): return False
                if isinstance(op, ast.Lt) and not (left < right): return False
                if isinstance(op, ast.LtE) and not (left <= right): return False
                if isinstance(op, ast.In) and not (left in right): return False
                if isinstance(op, ast.NotIn) and not (left not in right): return False
                left = right
            return True
        raise ValueError("Unsupported expression")

def safe_eval_condition(expr: str, context: dict) -> bool:
    try:
        return bool(SafeEvaluator(context).eval(expr))
    except Exception:
        return False

# ===== BLOCK: ZERO-CODE AGENT RUNNER & AGENTS =====
class CustomAgentRunner:
    def __init__(self, definition: dict):
        self.definition = definition or {}

    def _evaluate_trigger(self, node: dict, context: dict) -> bool:
        cond = (node or {}).get("when") or ""
        if not cond:
            return True
        return safe_eval_condition(cond, context)

    def _execute_action(self, action: dict, context: dict):
        if not action:
            return
        kind = (action.get("type") or "").lower()
        if kind == "create_task":
            title = (action.get("title") or "Новая задача").format(**context)
            assignee_id = action.get("assignee_id")
            due_at = action.get("due_at")
            org_id = context.get("org_id")
            try:
                task_id = create_task(org_id, title, description=(action.get("description") or "").format(**context),
                                      assignee_id=assignee_id, due_at=due_at)  # type: ignore
                context["task_id"] = int(task_id or 0)
            except Exception:
                pass
        elif kind == "update_deal":
            org_id = context.get("org_id")
            deal_id = int(action.get("deal_id") or 0)
            updates = action.get("updates") or {}
            try:
                update_deal(deal_id, org_id, updates)  # type: ignore
            except Exception:
                pass
        elif kind == "send_email":
            to = (action.get("to") or "").format(**context)
            subject = (action.get("subject") or "Сообщение").format(**context)
            body = (action.get("body") or "").format(**context)
            _send_mail_helper(to, subject, body)
        elif kind == "send_message":
            thread_id = action.get("thread_id") or context.get("thread_id")
            body = (action.get("body") or "").format(**context)
            try:
                add_message(int(thread_id or 0), "agent", body, user_id=context.get("user_id"), internal_note=False)  # type: ignore
            except Exception:
                pass
        elif kind == "notify":
            uid = context.get("user_id") or 0
            notify(int(uid), action.get("title", "Уведомление"), (action.get("body") or "").format(**context),
                   kind="info", link=action.get("link"))  # type: ignore
        elif kind == "generate_quote":
            org_id = context.get("org_id")
            title = (action.get("title") or "Коммерческое предложение").format(**context)
            deal_id = int(action.get("deal_id") or 0) or None
            company_id = int(action.get("company_id") or 0) or context.get("company_id") or None
            qid = exec_db(
                "INSERT INTO quotes (org_id, deal_id, company_id, title, currency, total, status, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (org_id, deal_id, company_id, title, "RUB", 0.0, "draft", context.get("user_id"), utc_now(), utc_now())
            )
            context["quote_id"] = int(qid or 0)
        elif kind == "schedule_meeting":
            org_id = context.get("org_id")
            room = (action.get("room") or f"room-{uuid.uuid4().hex[:8]}").format(**context)
            title = (action.get("title") or "Встреча").format(**context)
            mid = exec_db(
                "INSERT INTO meetings (org_id, title, room, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                (org_id, title, room, context.get("user_id"), utc_now())
            )
            context["meeting_id"] = int(mid or 0)
            context["meeting_url"] = f"{JITSI_BASE}/{room}"
        elif kind == "approval_request":
            org_id = int(context.get("org_id") or 0)
            entity_type = (action.get("entity_type") or "").strip()
            entity_id = int(action.get("entity_id") or 0)
            ttl = int(action.get("ttl_hours") or 48)
            if org_id and entity_type and entity_id:
                try:
                    token = generate_approval_token(org_id, entity_type, entity_id, ttl)  # type: ignore
                    context["approval_link"] = f"{request.url_root.rstrip('/')}/approve/{token}"
                    notify(int(context.get("user_id") or 0), "Запрос на одобрение", context["approval_link"], "info", link=context["approval_link"])  # type: ignore
                except Exception:
                    pass

    def _send_notification(self, node: dict, context: dict):
        target = node.get("target") or context.get("user_id") or 0
        notify(int(target), node.get("title", "Уведомление").format(**context), (node.get("body") or "").format(**context), kind="info")  # type: ignore

    def execute(self, context: dict) -> dict:
        current = self.definition.get("start_node")
        nodes = self.definition.get("nodes", {})
        guard = 0
        while current and guard < 200:
            guard += 1
            node = nodes.get(current) or {}
            ntype = node.get("type")
            if ntype == "trigger":
                if not self._evaluate_trigger(node, context):
                    break
            elif ntype == "condition":
                cond = node.get("condition", "")
                branch = node.get("true_branch") if safe_eval_condition(cond, context) else node.get("false_branch")
                current = branch
                continue
            elif ntype == "ai_prompt":
                prompt = (node.get("prompt_template", "") or "").format(**context)
                system = node.get("system_prompt", "")
                try:
                    out = ai_provider_call(prompt, system=system, model=node.get("model") or AI_MODEL,
                                           temperature=float(node.get("temperature") or AI_TEMPERATURE),
                                           max_tokens=int(node.get("max_tokens") or AI_MAX_TOKENS))
                    context["ai_output"] = out
                except Exception as e:
                    context["ai_error"] = str(e)
            elif ntype == "action":
                self._execute_action(node.get("action") or {}, context)
            elif ntype == "notification":
                self._send_notification(node, context)
            elif ntype == "rag_lookup":
                q = (node.get("q") or "").format(**context) or context.get("question") or ""
                et = node.get("entity_type") or None
                try:
                    context["rag"] = rag_answer(int(context.get("org_id") or 0), q, entity_type=et, top_k=int(node.get("top_k") or 5))
                except Exception as e:
                    context["rag"] = {"ok": False, "error": str(e)}
            current = node.get("next_node")
        return {"success": True, "context": context}

# ===== Agent base/framework =====
class AgentDecision:
    def __init__(self, action: str, confidence: float, reasoning: str, requires_approval: bool = False, metadata: Optional[dict] = None):
        self.action = action
        self.confidence = float(confidence or 0)
        self.reasoning = reasoning or ""
        self.requires_approval = bool(requires_approval)
        self.approved = not self.requires_approval
        self.metadata = metadata or {}

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "requires_approval": self.requires_approval,
            "approved": self.approved,
            "metadata": self.metadata,
        }

def _action_to_capability(action: str) -> str:
    mapping = {
        "create_deal_and_send_offer": "update_deal",
        "generate_and_send_quote": "generate_document",
        "send_automated_response": "send_message",
        "create_task_for_manual_review": "create_task",
        "send_nurturing_sequence": "send_email",
        "no_action": "read_data",
        "process_meeting_recording": "read_data",
        "request_manual_notes": "read_data",
        "escalate_to_support": "send_message",
        "auto_generate_quote": "generate_document",
        "send_knowledge_base_answer": "send_message",
        "route_to_manager": "send_message",
        "propose_meeting_slots": "send_message",
        "assign_to_human": "read_data",
    }
    return mapping.get(action, "read_data")

class BaseAgent:
    def __init__(self, org_id: int, user_id: Optional[int], capabilities: Set[str], agent_name: Optional[str] = None):
        self.org_id = org_id
        self.user_id = user_id
        self.capabilities = set(capabilities or [])
        self.agent_name = agent_name or self.__class__.__name__
        self.memory: List[dict] = []

    def perceive(self, context: dict) -> dict:
        raise NotImplementedError

    def reason(self, perception: dict) -> AgentDecision:
        raise NotImplementedError

    def act(self, decision: AgentDecision) -> dict:
        raise NotImplementedError

    def execute(self, context: dict) -> dict:
        try:
            perception = self.perceive(context or {})
            decision = self.reason(perception or {})
            if not self._has_permission(decision.action):
                return {"success": False, "error": "permission_denied"}
            if decision.requires_approval and not decision.approved:
                rid = self._request_approval(decision, context)
                return {"success": True, "pending_approval": True, "request_id": rid, "decision": decision.to_dict()}
            result = self.act(decision) or {}
            self._update_memory(context, decision, result)
            return {"success": True, "result": result, "decision": decision.to_dict()}
        except Exception as e:
            self._log_error(str(e), context)
            return {"success": False, "error": str(e)}

    def _has_permission(self, action: str) -> bool:
        required = _action_to_capability(action)
        return required in self.capabilities or "admin" in self.capabilities

    def _request_approval(self, decision: AgentDecision, context: dict) -> int:
        rid = exec_db(
            "INSERT INTO agent_approval_requests (org_id, agent_name, decision_json, context_json, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (self.org_id, self.agent_name, json.dumps(decision.to_dict(), ensure_ascii=False),
             json.dumps(context or {}, ensure_ascii=False), "pending", utc_now())
        )
        try:
            sse_push(int(self.user_id or 0), "agent.approval_requested", {"request_id": rid, "agent": self.agent_name})
        except Exception:
            pass
        return int(rid or 0)

    def _log_error(self, err: str, context: dict):
        try:
            exec_db(
                "INSERT INTO agent_actions (org_id, agent_name, action_type, reasoning, success, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self.org_id, self.agent_name, "error", json.dumps(context, ensure_ascii=False), False, err[:500], utc_now())
            )
        except Exception:
            pass

    def _update_memory(self, context: dict, decision: AgentDecision, result: dict):
        self.memory.append({"ts": utc_now(), "ctx": context, "decision": decision.to_dict(), "result": result})
        if len(self.memory) > 100:
            self.memory = self.memory[-100:]

class SalesAssistantAgent(BaseAgent):
    def __init__(self, org_id: int, user_id: Optional[int]):
        super().__init__(org_id, user_id, {"read_data", "update_deal", "send_email", "generate_document", "create_task", "predict_outcome"}, agent_name="SalesAssistant")

    def perceive(self, context: dict) -> dict:
        company_id = context.get("company_id")
        inquiry = context.get("inquiry", "")
        company = query_db("SELECT * FROM companies WHERE id=? AND org_id=?", (company_id, self.org_id), one=True) if company_id else None
        similar = query_db("SELECT id, title, amount, status, stage, created_at FROM deals WHERE company_id=? AND org_id=? ORDER BY created_at DESC LIMIT 5", (company_id, self.org_id)) if company_id else []
        return {"company": company, "inquiry": inquiry, "similar_deals": similar or []}

    def reason(self, p: dict) -> AgentDecision:
        company = p.get("company")
        inquiry = (p.get("inquiry") or "").lower()
        score = 50 + (10 if (company and company.get("industry")) else 0) + (10 if any((d.get("status") == "won") for d in p.get("similar_deals", [])) else 0)
        if "цена" in inquiry or "стоимость" in inquiry:
            return AgentDecision("generate_and_send_quote", 0.9, "Клиент спросил цену", True, {"company_id": company.get("id") if company else None})
        if score >= 75:
            return AgentDecision("create_deal_and_send_offer", 0.85, f"Высокое качество: {score}", False, {"company_id": company.get("id") if company else None})
        if score >= 55:
            return AgentDecision("create_task_for_manual_review", 0.7, f"Средний приоритет: {score}", False, {"note": "Проверить лид"})
        return AgentDecision("send_nurturing_sequence", 0.6, f"Низкий приоритет: {score}", False, {"company_id": company.get("id") if company else None})

    def act(self, d: AgentDecision) -> dict:
        a = d.action
        meta = d.metadata or {}
        if a == "create_deal_and_send_offer":
            company_id = meta.get("company_id")
            did = create_deal(self.org_id, "Новая сделка", 0.0, stage="new", assignee_id=self.user_id, company_id=company_id)  # type: ignore
            _send_mail_company(company_id, "Коммерческое предложение", f"Сделка создана: /deal/{did}")
            return {"deal_id": did}
        if a == "generate_and_send_quote":
            company_id = meta.get("company_id")
            _send_mail_company(company_id, "КП", "Ваше КП будет подготовлено в ближайшее время.")
            return {"sent": True}
        if a == "create_task_for_manual_review":
            tid = create_task(self.org_id, "Проверить лид", description=meta.get("note", ""), assignee_id=self.user_id)  # type: ignore
            return {"task_id": tid}
        if a == "send_nurturing_sequence":
            tid = create_task(self.org_id, "Nurture: связаться позже", description="Добавить в рассылку", assignee_id=self.user_id)  # type: ignore
            return {"task_id": tid}
        return {"status": "ok"}

class MeetingSecretaryAgent(BaseAgent):
    def __init__(self, org_id: int, user_id: Optional[int]):
        super().__init__(org_id, user_id, {"read_data", "create_task", "send_message"}, agent_name="MeetingSecretary")

    def perceive(self, context: dict) -> dict:
        meeting_id = context.get("meeting_id")
        m = query_db("SELECT * FROM meetings WHERE id=? AND org_id=?", (meeting_id, self.org_id), one=True) if meeting_id else None
        return {"meeting": m}

    def reason(self, p: dict) -> AgentDecision:
        m = p.get("meeting")
        if m:
            return AgentDecision("process_meeting_recording", 0.9, "Суммаризировать встречу", False, {"meeting_id": m.get("id")})
        return AgentDecision("request_manual_notes", 0.8, "Нет встречи", False, {})

    def act(self, d: AgentDecision) -> dict:
        if d.action == "process_meeting_recording":
            mid = d.metadata.get("meeting_id")
            text = ai_provider_call("Суммируй: встреча без стенограммы (демо).", system="Краткий деловой итог.", temperature=0.2, max_tokens=300)
            notes_id = exec_db(
                "INSERT INTO meeting_notes (meeting_id, transcript, summary, action_items_json, key_decisions, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (mid, "", text, "[]", "", utc_now())
            )
            try:
                row = query_db("SELECT created_by FROM meetings WHERE id=?", (mid,), one=True)
                if row and row.get("created_by"):
                    sse_push(int(row["created_by"]), "meeting.notes_ready", {"meeting_id": mid, "notes_id": notes_id})
            except Exception:
                pass
            return {"notes_id": notes_id}
        return {"status": "ok"}

class IntelligentInboxAgent(BaseAgent):
    def __init__(self, org_id: int, user_id: Optional[int]):
        super().__init__(org_id, user_id, {"read_data", "send_message", "generate_document", "create_task"}, agent_name="InboxAgent")

    def perceive(self, context: dict) -> dict:
        thread_id = context.get("thread_id")
        t = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (thread_id, self.org_id), one=True) if thread_id else None
        msgs = query_db("SELECT id, sender_type, user_id, external_user_id, body, internal_note, created_at FROM inbox_messages WHERE thread_id=? ORDER BY created_at DESC LIMIT 10", (thread_id,)) if thread_id else []
        msgs = list(reversed(msgs or []))
        return {"thread": t, "messages": msgs}

    def reason(self, p: dict) -> AgentDecision:
        last = (p.get("messages") or [{}])[-1].get("body") or ""
        prompt = f"""Классифицируй: intent(request_quote|request_support|general_question|complaint|schedule_meeting|other), urgency(low|medium|high|critical), answer_suggestion, answer_confidence(0..1). Текст: {last}"""
        try:
            txt = ai_provider_call(prompt, system="Ты оператор поддержки. Верни JSON.", temperature=0.2, max_tokens=300)
            data = json.loads(txt) if txt and txt.strip().startswith("{") else {}
        except Exception:
            data = {}
        intent = data.get("intent", "other")
        urgency = data.get("urgency", "low")
        ans = data.get("answer_suggestion", "") or ""
        if intent == "complaint":
            return AgentDecision("route_to_manager", 0.95, "Жалоба", False, {})
        if intent == "request_quote":
            return AgentDecision("auto_generate_quote", 0.85, "Запрос КП", True, {})
        if intent == "general_question" and float(data.get("answer_confidence", 0) or 0) >= 0.75 and ans:
            return AgentDecision("send_knowledge_base_answer", float(data.get("answer_confidence", 0)), "KB‑ответ", False, {"answer": ans})
        if intent == "request_support" and urgency in ("high", "critical"):
            return AgentDecision("escalate_to_support", 0.9, "Срочная поддержка", False, {})
        return AgentDecision("assign_to_human", 0.7, "Нужен человек", False, {})

    def act(self, d: AgentDecision) -> dict:
        a = d.action
        if a == "send_knowledge_base_answer":
            return {"sent": True}
        if a == "escalate_to_support":
            return {"escalated": True}
        if a == "auto_generate_quote":
            return {"document": "quote_draft"}
        if a == "route_to_manager":
            return {"routed": True}
        if a == "assign_to_human":
            return {"assigned": True}
        return {"status": "ok"}

def get_agent(agent_name: str, org_id: int, user_id: Optional[int]) -> Optional[BaseAgent]:
    name_l = (agent_name or "").lower()
    if name_l in ("sales", "salesassistant", "sales_assistant"):
        return SalesAssistantAgent(org_id, user_id)
    if name_l in ("meeting", "meetingsecretary", "meeting_secretary"):
        return MeetingSecretaryAgent(org_id, user_id)
    if name_l in ("inbox", "inboxagent", "intelligent_inbox"):
        return IntelligentInboxAgent(org_id, user_id)
    return None

def run_agent(agent_name: str, org_id: int, user_id: Optional[int], context: dict) -> dict:
    ag = get_agent(agent_name, org_id, user_id)
    if not ag:
        return {"success": False, "error": "unknown_agent"}
    return ag.execute(context or {})

# ===== BLOCK: MULTI-AGENT ORCHESTRATOR =====
from concurrent.futures import ThreadPoolExecutor

class AgentOrchestrator:
    def __init__(self, org_id: int, user_id: Optional[int], parallel: bool = False, max_workers: int = 4):
        self.org_id = org_id
        self.user_id = user_id
        self.parallel = parallel
        self.pool = ThreadPoolExecutor(max_workers=max_workers) if parallel else None

    def run(self, plan: List[dict], context: dict) -> dict:
        results: List[dict] = []

        def _one(step: dict):
            agent_name = step.get("agent")
            ctx = dict(context or {})
            ctx.update(step.get("context") or {})
            return run_agent(agent_name, self.org_id, self.user_id, ctx)

        try:
            if self.parallel and self.pool:
                futs = [self.pool.submit(_one, st) for st in plan or []]
                for f in futs:
                    try:
                        results.append(f.result(timeout=60))
                    except Exception as e:
                        results.append({"success": False, "error": str(e)})
            else:
                for st in plan or []:
                    results.append(_one(st))
        except Exception as e:
            return {"success": False, "error": str(e), "results": results}
        return {"success": True, "results": results}

# ===== BLOCK: MAIL HELPERS & CONVERSATIONAL BI (STUB) =====
def _send_mail_helper(to: str, subject: str, body: str) -> bool:
    if not to:
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        SMTP_HOST = os.getenv("SMTP_HOST", "")
        SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
        SMTP_USER = os.getenv("SMTP_USER", "")
        SMTP_PASS = os.getenv("SMTP_PASS", "")
        SMTP_FROM = os.getenv("SMTP_FROM", "noreply@crm.local")
        msg = MIMEText(body, "plain", "utf-8")
        msg["From"] = SMTP_FROM
        msg["To"] = to
        msg["Subject"] = subject
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            try:
                s.starttls()
            except Exception:
                pass
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        log("WARN", "send_mail failed", error=str(e))
        return False

def _send_mail_company(company_id: Optional[int], subject: str, body: str) -> bool:
    if not company_id:
        return False
    row = query_db("SELECT email FROM companies WHERE id=?", (company_id,), one=True)
    if not row or not row.get("email"):
        return False
    return _send_mail_helper(row["email"], subject, body)

def conversational_bi_query(nl_query: str, org_id: int, user_id: int) -> dict:
    if not CONVERSATIONAL_BI_ENABLED:
        return {"ok": False, "error": "Disabled"}
    # Placeholder: NL2SQL over whitelisted metrics will be implemented later (partially)
    return {"ok": True, "kind": "text", "data": "Not implemented yet"}

# ==================== END OF CORE PART 5/10 ====================
# ===== START OF CORE PART 6/10 =====
# coding: utf-8

# ==================== CORE PART 6/10 ====================
# ===== BLOCK: BUSINESS LOGIC: TASKS =====
from typing import Iterable
from zoneinfo import ZoneInfo  # TZ-aware ICS generation

# Safe notify shim (use global notify if defined later)
if "notify" not in globals():
    def notify(user_id: int, title: str, body: str, kind: str = "info", link: Optional[str] = None):
        try:
            sse_push(user_id, "notify.center", {"title": title, "body": body, "kind": kind, "link": link, "ts": utc_now()})
        except Exception:
            pass

TASK_ALLOWED_UPDATE_FIELDS: Set[str] = {
    "title", "description", "status", "priority",
    "assignee_id", "department_id", "company_id", "contact_id",
    "due_at", "completed_at", "monthly_fee", "address", "contact_phone"
}

def _ids_placeholders(ids: List[int]) -> Tuple[str, Tuple[Any, ...]]:
    """
    Safe placeholder builder for IN clauses. Returns "(?,?,...)" and tuple of ids.
    If list is empty — returns "(NULL)" and empty tuple which yields no rows.
    """
    if not ids:
        return "(NULL)", tuple()
    ph = ",".join(["?"] * len(ids))
    return f"({ph})", tuple(int(x) for x in ids)

def _timeline_add(org_id: int, actor_user_id: Optional[int], entity_type: str, entity_id: int, action: str, data: Optional[dict] = None):
    try:
        exec_db(
            "INSERT INTO activity_timeline (org_id, actor_type, actor_id, entity_type, entity_id, action, data_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, "user" if actor_user_id else "system", actor_user_id, entity_type, entity_id, action,
             json.dumps(data or {}, ensure_ascii=False), utc_now())
        )
    except Exception as e:
        log("WARN", "timeline_add failed", error=str(e))

def _apply_status_department_rule(org_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
    status = (updates.get("status") or "").strip()
    if not status or updates.get("department_id"):
        return updates
    try:
        row = query_db(
            "SELECT department_id FROM task_status_department_rules WHERE org_id=? AND status_name=?",
            (org_id, status), one=True
        )
        if row and row.get("department_id"):
            updates["department_id"] = row["department_id"]
    except Exception:
        pass
    return updates

def _task_push_insights_and_notifications(org_id: int, task_id: int, assignee_id: Optional[int], updates: Dict[str, Any], prev: Optional[dict] = None):
    try:
        title = updates.get("title") or (prev.get("title") if prev else None) or f"Задача #{task_id}"
        if assignee_id:
            if updates.get("status"):
                sse_push(int(assignee_id), "task.status_changed", {"task_id": task_id, "status": updates["status"]})
            else:
                sse_push(int(assignee_id), "task.updated", {"task_id": task_id, "title": title})
        # Proactive insights: overdue / due soon
        due = updates.get("due_at") or (prev.get("due_at") if prev else None)
        status = (updates.get("status") or (prev.get("status") if prev else "") or "").lower()
        if due:
            try:
                due_dt_str = ensure_iso_datetime(due)
                due_dt = datetime.strptime(due_dt_str, "%Y-%m-%d %H:%M:%S")
                hours_left = (due_dt - datetime.utcnow()).total_seconds() / 3600.0
                if hours_left < 0 and status not in ("done", "cancelled"):
                    sse_push(int(assignee_id or 0), "twin.insight", {
                        "id": uuid.uuid4().hex, "kind": "proactive",
                        "title": "Просроченная задача",
                        "message": f"Задача '{title}' просрочена на {int(abs(hours_left))} ч.",
                        "severity": "warn", "tags": ["tasks", "overdue"], "ts": utc_now()
                    })
                elif 0 <= hours_left <= 24 and status not in ("done", "cancelled"):
                    sse_push(int(assignee_id or 0), "twin.insight", {
                        "id": uuid.uuid4().hex, "kind": "proactive",
                        "title": "Срок задачи близок",
                        "message": f"Задача '{title}' истекает через {int(hours_left)} ч.",
                        "severity": "info", "tags": ["tasks", "due_soon"], "ts": utc_now()
                    })
            except Exception:
                pass
    except Exception:
        pass

def create_task(
    org_id: int,
    title: str,
    description: str = "",
    assignee_id: Optional[int] = None,
    status: str = "open",
    priority: str = "normal",
    due_at: Optional[str] = None,
    company_id: Optional[int] = None,
    contact_id: Optional[int] = None,
    monthly_fee: float = 0.0,
    address: str = "",
    contact_phone: str = "",
    department_id: Optional[int] = None
) -> int:
    if not title:
        raise ValueError("Title required")
    due_norm = ensure_iso_datetime(due_at) if due_at else None
    phone_norm = normalize_phone(contact_phone) if contact_phone else ""
    with db_transaction():
        tid = exec_db(
            """
            INSERT INTO tasks (org_id, title, description, status, priority, assignee_id, department_id,
                               company_id, contact_id, due_at, completed_at, monthly_fee, address, contact_phone,
                               last_commented_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org_id, title, description, status, priority, assignee_id, department_id,
                company_id, contact_id, due_norm, None, float(monthly_fee), address, phone_norm,
                None, utc_now(), utc_now()
            )
        )
        task_id = int(tid or 0)
        _timeline_add(org_id, assignee_id, "task", task_id, "created", {"title": title})
        try:
            add_audit(org_id, assignee_id, "task.created", "task", task_id, {"title": title})  # type: ignore
        except Exception:
            pass
        try:
            if assignee_id:
                sse_push(int(assignee_id), "task.created", {"task_id": task_id, "title": title})
                notify(int(assignee_id), "Новая задача", f"Вам назначена задача #{task_id}: {title}", kind="info", link=f"/task/{task_id}")
        except Exception:
            pass
    return task_id

def update_task(task_id: int, org_id: int, updates: Dict[str, Any]) -> bool:
    if not updates:
        return False
    # Normalize/clean
    if "due_at" in updates and updates["due_at"]:
        updates["due_at"] = ensure_iso_datetime(updates["due_at"])
    if "contact_phone" in updates and updates["contact_phone"]:
        updates["contact_phone"] = normalize_phone(updates["contact_phone"])
    updates = _apply_status_department_rule(org_id, updates)
    prev = query_db("SELECT * FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True) or {}
    set_sql, params = _safe_update_clause(TASK_ALLOWED_UPDATE_FIELDS, updates)
    if not set_sql:
        return False
    set_sql = f"{set_sql}, updated_at=?"
    params.append(utc_now())
    params.extend([task_id, org_id])
    with db_transaction():
        rc = exec_db_affect(f"UPDATE tasks SET {set_sql} WHERE id=? AND org_id=?", tuple(params))
        if rc:
            try:
                add_audit(org_id, g.get("user", {}).get("id"), "task.updated", "task", task_id, updates)  # type: ignore
            except Exception:
                pass
            _timeline_add(org_id, g.get("user", {}).get("id"), "task", task_id, "updated", updates)
        if rc:
            try:
                _task_push_insights_and_notifications(org_id, task_id, updates.get("assignee_id") or prev.get("assignee_id"), updates, prev)
            except Exception:
                pass
    return bool(rc)

def toggle_task_status(task_id: int, org_id: int) -> str:
    row = query_db("SELECT status, assignee_id, title FROM tasks WHERE id=? AND org_id=?", (task_id, org_id), one=True)
    if not row:
        raise ValueError("Task not found")
    cur = (row.get("status") or "open").lower()
    new_status = "open" if cur == "done" else "done"
    completed_at = utc_now() if new_status == "done" else None
    updates = {"status": new_status, "completed_at": completed_at}
    updates = _apply_status_department_rule(org_id, updates)
    set_sql, params = _safe_update_clause(TASK_ALLOWED_UPDATE_FIELDS, updates)
    set_sql = f"{set_sql}, updated_at=?"
    params.append(utc_now())
    params.extend([task_id, org_id])
    with db_transaction():
        exec_db_affect(f"UPDATE tasks SET {set_sql} WHERE id=? AND org_id=?", tuple(params))
        try:
            add_audit(org_id, g.get("user", {}).get("id"), "task.status_toggled", "task", task_id, {"status": new_status})  # type: ignore
        except Exception:
            pass
        _timeline_add(org_id, g.get("user", {}).get("id"), "task", task_id, "status_changed", {"status": new_status})
        try:
            assignee = row.get("assignee_id")
            if assignee:
                sse_push(int(assignee), "task.status_changed", {"task_id": task_id, "status": new_status})
                notify(int(assignee), f"Статус задачи #{task_id}", f"{row.get('title') or ''}: {new_status}", kind="info", link=f"/task/{task_id}")
        except Exception:
            pass
    return new_status

def add_task_comment(task_id: int, user_id: Optional[int], body: str, fmt: str = "plain", attachments: Optional[List[dict]] = None) -> int:
    if not body and not attachments:
        raise ValueError("Comment body or attachment required")
    org_row = query_db("SELECT org_id FROM tasks WHERE id=?", (task_id,), one=True)
    org_id = int(org_row["org_id"]) if org_row and org_row.get("org_id") is not None else None
    with db_transaction():
        cid = exec_db(
            "INSERT INTO task_comments (task_id, user_id, body, format, created_at) VALUES (?, ?, ?, ?, ?)",
            (task_id, user_id, body or "", fmt or "plain", utc_now())
        )
        exec_db_affect("UPDATE tasks SET last_commented_at=?, updated_at=? WHERE id=?", (utc_now(), utc_now(), task_id))
        if attachments:
            for a in attachments:
                fid = a.get("file_id")
                if fid:
                    # Защита по аренде: файл должен принадлежать той же org, что и задача
                    if org_id is not None:
                        ok = query_db("SELECT 1 AS x FROM files WHERE id=? AND org_id=?", (int(fid), int(org_id)), one=True)
                        if not ok:
                            log("WARN", "task_comment attachment org mismatch", file_id=int(fid), task_id=task_id, org_id=int(org_id))
                            continue
                    exec_db(
                        "INSERT INTO task_comment_attachments (comment_id, file_id, created_at) VALUES (?, ?, ?)",
                        (cid, int(fid), utc_now())
                    )
    if org_id is not None:
        try:
            add_audit(org_id, user_id, "task.comment_added", "task", task_id, {"comment_id": int(cid or 0)})  # type: ignore
        except Exception:
            pass
        _timeline_add(org_id, user_id, "task", task_id, "comment_added", {"comment_id": int(cid or 0)})
    try:
        t = query_db("SELECT assignee_id, title FROM tasks WHERE id=?", (task_id,), one=True)
        if t and t.get("assignee_id"):
            sse_push(int(t["assignee_id"]), "task.updated", {"task_id": task_id, "title": t.get("title")})
    except Exception:
        pass
    return int(cid or 0)

def get_task_comments(task_id: int) -> List[dict]:
    rows = query_db(
        """
        SELECT c.id, c.task_id, c.user_id, u.username, c.body, c.format, c.created_at
        FROM task_comments c
        LEFT JOIN users u ON u.id=c.user_id
        WHERE c.task_id=?
        ORDER BY c.created_at DESC
        """,
        (task_id,)
    ) or []
    ids = [int(r["id"]) for r in rows]
    atts_map: Dict[int, List[dict]] = defaultdict(list)
    if ids:
        inph, tpl = _ids_placeholders(ids)
        att_rows = query_db(
            f"""
            SELECT a.comment_id, f.id AS file_id, f.name, f.content_type, f.size_bytes
            FROM task_comment_attachments a
            JOIN files f ON f.id=a.file_id
            WHERE a.comment_id IN {inph}
            """,
            tpl
        ) or []
        for a in att_rows:
            atts_map[int(a["comment_id"])].append({
                "file_id": a["file_id"],
                "name": a["name"],
                "content_type": a.get("content_type"),
                "size_bytes": a.get("size_bytes"),
                "url": f"/api/files/{a['file_id']}/download"
            })
    for r in rows:
        r["attachments"] = atts_map.get(int(r["id"]), [])
    return rows

def update_task_participants(task_id: int, add: List[int], remove: List[int], role: str = "watcher"):
    add = add or []
    remove = remove or []
    with db_transaction():
        for uid in add:
            try:
                if DIALECT == "postgres":
                    exec_db(
                        "INSERT INTO task_participants (task_id, user_id, role, created_at) VALUES (?, ?, ?, ?) "
                        "ON CONFLICT (task_id, user_id) DO NOTHING",
                        (task_id, int(uid), role, utc_now())
                    )
                else:
                    existing = query_db("SELECT 1 AS x FROM task_participants WHERE task_id=? AND user_id=?", (task_id, int(uid)), one=True)
                    if not existing:
                        exec_db("INSERT INTO task_participants (task_id, user_id, role, created_at) VALUES (?, ?, ?, ?)", (task_id, int(uid), role, utc_now()))
            except Exception:
                pass
        if remove:
            ph, tpl = _ids_placeholders([int(x) for x in remove])
            exec_db_affect(f"DELETE FROM task_participants WHERE task_id=? AND user_id IN {ph}", (task_id, *tpl))

def update_task_checklist(task_id: int, items: List[dict]):
    items = items or []
    keep_ids: Set[int] = set()
    with db_transaction():
        for it in items:
            cid = it.get("id")
            item_text = (it.get("item") or "").strip()
            checked = 1 if bool(it.get("checked")) else 0
            sort_order = int(it.get("sort_order") or 0)
            if cid:
                exec_db_affect(
                    "UPDATE task_checklists SET item=?, checked=?, sort_order=? WHERE id=? AND task_id=?",
                    (item_text, checked, sort_order, int(cid), task_id)
                )
                keep_ids.add(int(cid))
            else:
                nid = exec_db(
                    "INSERT INTO task_checklists (task_id, item, checked, sort_order, created_at) VALUES (?, ?, ?, ?, ?)",
                    (task_id, item_text, checked, sort_order, utc_now())
                )
                if nid:
                    keep_ids.add(int(nid))
        try:
            existing = query_db("SELECT id FROM task_checklists WHERE task_id=?", (task_id,)) or []
            remove_ids = [int(r["id"]) for r in existing if int(r["id"]) not in keep_ids]
            if remove_ids:
                ph, tpl = _ids_placeholders(remove_ids)
                exec_db_affect(f"DELETE FROM task_checklists WHERE task_id=? AND id IN {ph}", (task_id, *tpl))
        except Exception:
            pass

def get_task_checklist_progress(task_id: int) -> int:
    rows = query_db("SELECT checked FROM task_checklists WHERE task_id=?", (task_id,)) or []
    if not rows:
        return 0
    total = len(rows)
    done = sum(1 for r in rows if (r.get("checked") in (1, True)))
    return int(round((done / max(1, total)) * 100))

def batch_update_tasks(org_id: int, ids: List[int], updates: Dict[str, Any]) -> int:
    if not ids or not updates:
        return 0
    if "due_at" in updates and updates["due_at"]:
        updates["due_at"] = ensure_iso_datetime(updates["due_at"])
    if "contact_phone" in updates and updates["contact_phone"]:
        updates["contact_phone"] = normalize_phone(updates["contact_phone"])
    updates = _apply_status_department_rule(org_id, updates)
    set_sql, params = _safe_update_clause(TASK_ALLOWED_UPDATE_FIELDS, updates)
    if not set_sql:
        return 0
    set_sql = f"{set_sql}, updated_at=?"
    params.append(utc_now())
    ph, tpl = _ids_placeholders([int(x) for x in ids])
    q = f"UPDATE tasks SET {set_sql} WHERE org_id=? AND id IN {ph}"
    params.append(org_id)
    params.extend(tpl)
    with db_transaction():
        rc = exec_db_affect(q, tuple(params))
        _timeline_add(org_id, g.get("user", {}).get("id"), "task", 0, "bulk_update", {"count": int(rc or 0), "fields": list(updates.keys())})
    return int(rc or 0)

def get_task(task_id: int, org_id: int) -> Optional[dict]:
    row = query_db(
        """
        SELECT t.*, u.username AS assignee_name, c.name AS company_name, d.name AS department_name
        FROM tasks t
        LEFT JOIN users u ON t.assignee_id=u.id
        LEFT JOIN companies c ON t.company_id=c.id
        LEFT JOIN departments d ON t.department_id=d.id
        WHERE t.id=? AND t.org_id=?
        """,
        (task_id, org_id), one=True
    )
    if not row:
        return None
    row["checklist_percent"] = get_task_checklist_progress(task_id)
    return row


# ===== BLOCK: APPROVAL TOKENS (GENERATION) =====
def generate_approval_token(org_id: int, entity_type: str, entity_id: int, ttl_hours: int = 48) -> str:
    """
    Generates a one-time approval token for external approval links.
    Token format: <jti>.<secret>, hashed and stored in approval_tokens.
    """
    jti = uuid.uuid4().hex
    secret = secrets.token_urlsafe(32)
    token = f"{jti}.{secret}"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = (datetime.utcnow() + timedelta(hours=int(ttl_hours))).strftime("%Y-%m-%d %H:%M:%S")
    exec_db(
        "INSERT INTO approval_tokens (org_id, entity_type, entity_id, jti, token_hash, expires_at, used, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)",
        (org_id, entity_type, entity_id, jti, token_hash, expires_at, utc_now())
    )
    return token


# ===== BLOCK: BUSINESS LOGIC: CALENDAR =====
class CalendarService:
    """
    Сервис управления календарем: CRUD, повторяемость, напоминания, конфликты, RSVP, iCalendar.
    """

    # --- time utils ---
    @staticmethod
    def _dt_from_iso(s: str) -> datetime:
        s = ensure_iso_datetime(s) or ""
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _iso_utc(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _validate_range(start_time: str, end_time: str):
        s = CalendarService._dt_from_iso(start_time)
        e = CalendarService._dt_from_iso(end_time)
        if e <= s:
            raise ValueError("end_time must be greater than start_time")

    # --- reminders ---
    @staticmethod
    def _create_reminders(event_id: int, org_id: int, participants: List[int], start_time: str, minutes_list: List[int]):
        if not participants or not minutes_list:
            return
        s_dt = CalendarService._dt_from_iso(start_time)
        for uid in participants:
            for m in minutes_list:
                try:
                    rtime = s_dt - timedelta(minutes=int(m))
                    exec_db(
                        "INSERT INTO event_reminders (event_id, user_id, reminder_time, minutes_before, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (event_id, int(uid), CalendarService._iso_utc(rtime), int(m), "pending", utc_now())
                    )
                except Exception as e:
                    log("WARN", "create reminder failed", error=str(e))

    @staticmethod
    def create_event(org_id: int, data: dict, created_by: int) -> dict:
        """
        Создание события календаря:
        - Валидация времени
        - Конфликты (предупреждение)
        - Запись participants
        - Напоминания
        """
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title required")
        start_time = ensure_iso_datetime(data.get("start_time")) or ""
        end_time = ensure_iso_datetime(data.get("end_time")) or ""
        CalendarService._validate_range(start_time, end_time)
        all_day = 1 if data.get("all_day") else 0
        event_type = data.get("event_type") or "meeting"
        location = data.get("location") or ""
        description = data.get("description") or ""
        timezone_name = data.get("timezone") or "UTC"
        organizer_id = int(data.get("organizer_id") or created_by)
        task_id = data.get("task_id")
        deal_id = data.get("deal_id")
        company_id = data.get("company_id")
        status = data.get("status") or "confirmed"
        visibility = data.get("visibility") or "default"
        reminder_minutes = data.get("reminder_minutes") or []
        recurrence_rule = data.get("recurrence_rule")
        recurrence_parent_id = data.get("recurrence_parent_id")
        recurrence_exception_dates = data.get("recurrence_exception_dates")
        meeting_url = data.get("meeting_url") or ""
        attachments_json = json.dumps(data.get("attachments") or [], ensure_ascii=False)
        color = data.get("color") or "#3B82F6"
        participants = [int(x) for x in (data.get("participants") or []) if x]

        with db_transaction():
            eid = exec_db(
                """
                INSERT INTO calendar_events (
                    org_id, title, description, location, event_type, start_time, end_time, all_day, timezone,
                    recurrence_rule, recurrence_parent_id, recurrence_exception_dates,
                    organizer_id, task_id, deal_id, company_id, status, visibility,
                    reminder_minutes, meeting_url, attachments_json, color, created_at, updated_at, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (org_id, title, description, location, event_type, start_time, end_time, all_day, timezone_name,
                 json.dumps(recurrence_rule or {}, ensure_ascii=False) if recurrence_rule else None,
                 recurrence_parent_id, json.dumps(recurrence_exception_dates or [], ensure_ascii=False) if recurrence_exception_dates else None,
                 organizer_id, task_id, deal_id, company_id, status, visibility,
                 json.dumps(reminder_minutes or [], ensure_ascii=False), meeting_url, attachments_json, color, utc_now(), utc_now(), created_by)
            )
            event_id = int(eid or 0)
            # participants
            for uid in participants:
                try:
                    exec_db(
                        "INSERT INTO event_participants (event_id, user_id, created_at) VALUES (?, ?, ?)",
                        (event_id, int(uid), utc_now())
                    )
                except Exception:
                    pass
            # reminders
            CalendarService._create_reminders(event_id, org_id, participants or [organizer_id], start_time, [int(x) for x in reminder_minutes])

        # timeline/audit & SSE
        _timeline_add(org_id, created_by, "calendar_event", event_id, "created", {"title": title})
        try:
            add_audit(org_id, created_by, "calendar.event_created", "calendar_event", event_id, {"title": title})  # type: ignore
        except Exception:
            pass
        try:
            for uid in (participants or []):
                sse_push(int(uid), "calendar.event.created", {"event_id": event_id, "title": title})
        except Exception:
            pass

        # Conflicts (non-blocking, org-scoped)
        conflicts = []
        for uid in (participants or []):
            conflicts.extend(CalendarService.check_conflicts(uid, start_time, end_time, exclude_event_id=event_id))
        return {"event_id": event_id, "conflicts": conflicts}

    @staticmethod
    def update_event(event_id: int, data: dict, user_id: int, update_mode: str = "single") -> dict:
        """
        Обновление события (базовая реализация single/all/следующие может быть расширена).
        - проверка прав: организатор или can_modify
        - обновление полей + пересоздание напоминаний при изменении времени
        """
        ev = query_db("SELECT * FROM calendar_events WHERE id=?", (event_id,), one=True)
        if not ev:
            raise ValueError("event not found")
        org_id = int(ev["org_id"])
        organizer_id = int(ev["organizer_id"])
        if user_id != organizer_id:
            # check modify in participants
            p = query_db("SELECT can_modify FROM event_participants WHERE event_id=? AND user_id=?", (event_id, user_id), one=True)
            if not (p and p.get("can_modify")):
                return {"ok": False, "error": "forbidden"}

        allowed = {
            "title", "description", "location", "event_type", "start_time", "end_time", "all_day", "timezone",
            "recurrence_rule", "status", "visibility", "reminder_minutes,meeting_url", "attachments", "color",
            "task_id", "deal_id", "company_id"
        }
        # fix allowed key for reminder_minutes (typo safeguard)
        allowed = (allowed - {"reminder_minutes,meeting_url"}) | {"reminder_minutes", "meeting_url"}

        updates = {k: v for k, v in data.items() if k in allowed}
        if "start_time" in updates and updates["start_time"]:
            updates["start_time"] = ensure_iso_datetime(updates["start_time"])
        if "end_time" in updates and updates["end_time"]:
            updates["end_time"] = ensure_iso_datetime(updates["end_time"])
        if "all_day" in updates:
            updates["all_day"] = 1 if updates.get("all_day") else 0
        if "attachments" in updates:
            updates["attachments_json"] = json.dumps(updates.pop("attachments") or [], ensure_ascii=False)
        if "reminder_minutes" in updates:
            updates["reminder_minutes"] = json.dumps(updates["reminder_minutes"] or [], ensure_ascii=False)
        set_sql, params = _safe_update_clause(set(updates.keys()), updates)
        if set_sql:
            set_sql = f"{set_sql}, updated_at=?"
            params.append(utc_now())
            params.extend([event_id])
            with db_transaction():
                exec_db_affect(f"UPDATE calendar_events SET {set_sql} WHERE id=?", tuple(params))
                # re-create reminders if time or reminder list changed
                if ("start_time" in updates) or ("reminder_minutes" in updates):
                    exec_db_affect("DELETE FROM event_reminders WHERE event_id=?", (event_id,))
                    start_time = updates.get("start_time") or ev.get("start_time")
                    mins = json.loads(updates.get("reminder_minutes", ev.get("reminder_minutes") or "[]") or "[]")
                    participants = [r["user_id"] for r in (query_db("SELECT user_id FROM event_participants WHERE event_id=?", (event_id,)) or [])]
                    CalendarService._create_reminders(event_id, org_id, participants or [organizer_id], start_time, mins)

        _timeline_add(org_id, user_id, "calendar_event", event_id, "updated", updates)
        try:
            add_audit(org_id, user_id, "calendar.event_updated", "calendar_event", event_id, updates)  # type: ignore
        except Exception:
            pass
        try:
            participants = query_db("SELECT user_id FROM event_participants WHERE event_id=?", (event_id,)) or []
            for p in participants:
                sse_push(int(p["user_id"]), "calendar.event.updated", {"event_id": event_id})
        except Exception:
            pass
        return {"ok": True}

    @staticmethod
    def delete_event(event_id: int, user_id: int, delete_mode: str = "single") -> bool:
        ev = query_db("SELECT * FROM calendar_events WHERE id=?", (event_id,), one=True)
        if not ev:
            return False
        org_id = int(ev["org_id"])
        organizer_id = int(ev["organizer_id"])
        if user_id != organizer_id:
            p = query_db("SELECT can_modify FROM event_participants WHERE event_id=? AND user_id=?", (event_id, user_id), one=True)
            if not (p and p.get("can_modify")):
                return False
        with db_transaction():
            # For now delete single (recurrence advanced modes can be added later)
            exec_db_affect("DELETE FROM calendar_events WHERE id=?", (event_id,))
            exec_db_affect("DELETE FROM event_participants WHERE event_id=?", (event_id,))
            exec_db_affect("DELETE FROM event_reminders WHERE event_id=?", (event_id,))
        _timeline_add(org_id, user_id, "calendar_event", event_id, "deleted", {})
        try:
            add_audit(org_id, user_id, "calendar.event_deleted", "calendar_event", event_id, {})  # type: ignore
        except Exception:
            pass
        return True

    @staticmethod
    def get_events(org_id: int, user_id: int, filters: dict) -> List[dict]:
        """
        Получение событий по диапазону и фильтрам, разворачивает простую повторяемость в пределах окна (DAILY/WEEKLY).
        """
        start = ensure_iso_datetime(filters.get("start") or "")
        end = ensure_iso_datetime(filters.get("end") or "")
        if not start or not end:
            raise ValueError("start and end are required")
        where = ["org_id=?"]
        params: List[Any] = [org_id]
        where.append("start_time <= ? AND end_time >= ?")
        params.extend([end, start])
        if filters.get("event_types"):
            types = [t.strip() for t in str(filters["event_types"]).split(",") if t.strip()]
            if types:
                in_clause = ",".join("?" for _ in types)
                where.append(f"event_type IN ({in_clause})")
                params.extend(types)
        if filters.get("view") == "my":
            where.append("(organizer_id = ? OR id IN (SELECT event_id FROM event_participants WHERE user_id=?))")
            params.extend([user_id, user_id])

        rows = query_db(f"SELECT * FROM calendar_events WHERE {' AND '.join(where)} ORDER BY start_time ASC LIMIT 2000", tuple(params)) or []
        out: List[dict] = []
        for ev in rows:
            rule = ev.get("recurrence_rule")
            if rule:
                try:
                    json.loads(rule or "{}")
                except Exception:
                    rule = "{}"
                exp = CalendarService.expand_recurrence(ev, start, end)
                out.extend(exp)
            else:
                out.append(ev)
        return out

    @staticmethod
    def check_conflicts(user_id: int, start_time: str, end_time: str, exclude_event_id: Optional[int] = None) -> List[dict]:
        """
        Проверка конфликтов по user_id (организатор или участник), с учётом org_id пользователя.
        """
        start = ensure_iso_datetime(start_time) or ""
        end = ensure_iso_datetime(end_time) or ""
        where = [
            # org_id фильтруется по org пользователя
            "org_id = (SELECT org_id FROM users WHERE id=?)",
            "(organizer_id=? OR id IN (SELECT event_id FROM event_participants WHERE user_id=?))",
            "start_time < ? AND end_time > ?"
        ]
        params: List[Any] = [user_id, user_id, user_id, end, start]
        if exclude_event_id:
            where.append("id != ?")
            params.append(exclude_event_id)
        rows = query_db(f"SELECT id, title, start_time, end_time FROM calendar_events WHERE {' AND '.join(where)} ORDER BY start_time", tuple(params)) or []
        return rows

    @staticmethod
    def respond_to_event(event_id: int, user_id: int, response: str, comment: Optional[str] = None) -> bool:
        """
        RSVP: accepted | declined | tentative
        """
        if response not in ("accepted", "declined", "tentative"):
            raise ValueError("invalid response")
        with db_transaction():
            rc = exec_db_affect(
                "UPDATE event_participants SET response_status=?, response_comment=?, response_time=? WHERE event_id=? AND user_id=?",
                (response, comment or "", utc_now(), event_id, user_id)
            )
        ev = query_db("SELECT org_id, title, organizer_id FROM calendar_events WHERE id=?", (event_id,), one=True)
        if ev:
            _timeline_add(int(ev["org_id"]), user_id, "calendar_event", event_id, "rsvp", {"response": response})
            try:
                add_audit(int(ev["org_id"]), user_id, "calendar.rsvp", "calendar_event", event_id, {"response": response})  # type: ignore
            except Exception:
                pass
            try:
                sse_push(int(ev["organizer_id"]), "calendar.event.rsvp", {"event_id": event_id, "user_id": user_id, "response": response})
            except Exception:
                pass
        return bool(rc)

    @staticmethod
    def expand_recurrence(event_row: dict, start_date: str, end_date: str) -> List[dict]:
        """
        Разворачивает DAILY/WEEKLY повторяемость в диапазоне дат (простая реализация).
        """
        try:
            rule = json.loads(event_row.get("recurrence_rule") or "{}")
        except Exception:
            rule = {}
        if not rule or not rule.get("freq"):
            return [event_row]

        freq = rule.get("freq", "").upper()
        interval = int(rule.get("interval") or 1)
        count = int(rule.get("count") or 0)
        until = rule.get("until")
        by_weekday = rule.get("by_weekday") or []

        start = CalendarService._dt_from_iso(start_date)
        end = CalendarService._dt_from_iso(end_date)
        ev_start = CalendarService._dt_from_iso(event_row["start_time"])
        ev_end = CalendarService._dt_from_iso(event_row["end_time"])
        cur_start = ev_start
        cur_end = ev_end

        out: List[dict] = []
        emitted = 0
        until_dt = CalendarService._dt_from_iso(ensure_iso_datetime(until)) if until else None

        # helper to push instance
        def push_instance(s: datetime, e: datetime):
            nonlocal out
            out.append({**event_row, "start_time": CalendarService._iso_utc(s), "end_time": CalendarService._iso_utc(e)})

        # advance function
        def advance(current_s: datetime, current_e: datetime) -> Tuple[datetime, datetime]:
            if freq == "DAILY":
                delta = timedelta(days=interval)
                return current_s + delta, current_e + delta
            if freq == "WEEKLY":
                delta = timedelta(weeks=interval)
                return current_s + delta, current_e + delta
            # fallback: daily
            return current_s + timedelta(days=interval), current_e + timedelta(days=interval)

        # For weekly with by_weekday: we generate within each week
        if freq == "WEEKLY" and by_weekday:
            # align to week of event start
            base_week_monday = cur_start - timedelta(days=(cur_start.weekday()))
            while cur_start <= end:
                # produce days in this week according to by_weekday
                for wd in sorted(set(int(x) for x in by_weekday if isinstance(x, (int, float, str)))):
                    try:
                        wd_int = int(wd)  # 0=Mon..6=Sun
                    except Exception:
                        continue
                    day_s = base_week_monday + timedelta(days=wd_int, hours=cur_start.hour, minutes=cur_start.minute, seconds=cur_start.second)
                    # align event duration
                    dur = cur_end - cur_start
                    day_e = day_s + dur
                    if day_e < start or day_s > end:
                        continue
                    if until_dt and day_s > until_dt:
                        break
                    push_instance(day_s, day_e)
                    emitted += 1
                    if count and emitted >= count:
                        break
                if count and emitted >= count:
                    break
                # next block of week according to interval
                base_week_monday = base_week_monday + timedelta(weeks=interval)
                cur_start = base_week_monday + timedelta(hours=ev_start.hour, minutes=ev_start.minute, seconds=ev_start.second)
                cur_end = cur_start + (ev_end - ev_start)
            return out

        # Generic progression (DAILY or WEEKLY without by_weekday)
        while cur_start <= end:
            if cur_end >= start:
                if until_dt and cur_start > until_dt:
                    break
                push_instance(cur_start, cur_end)
                emitted += 1
                if count and emitted >= count:
                    break
            cur_start, cur_end = advance(cur_start, cur_end)
        return out

    @staticmethod
    def generate_ics(event_id: int) -> str:
        ev = query_db("SELECT * FROM calendar_events WHERE id=?", (event_id,), one=True)
        if not ev:
            raise ValueError("event not found")
        # TZ-aware conversion to UTC
        tzname = (ev.get("timezone") or "UTC").strip() or "UTC"
        try:
            local_tz = ZoneInfo(tzname)
        except Exception:
            local_tz = ZoneInfo("UTC")
        try:
            dtstart_local = datetime.strptime(ev["start_time"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=local_tz)
        except Exception:
            dtstart_local = datetime.utcnow().replace(tzinfo=ZoneInfo("UTC"))
        try:
            dtend_local = datetime.strptime(ev["end_time"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=local_tz)
        except Exception:
            dtend_local = dtstart_local + timedelta(hours=1)
        dtstart = dtstart_local.astimezone(timezone.utc)
        dtend = dtend_local.astimezone(timezone.utc)

        uid = f"{event_id}@singularity.local"
        title = (ev.get("title") or "Event").replace("\n", " ")
        desc = (ev.get("description") or "").replace("\n", "\\n")
        loc = (ev.get("location") or "").replace("\n", " ")

        ics = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Singularity//CRM 5.2//EN
BEGIN:VEVENT
UID:{uid}
DTSTAMP:{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}
DTSTART:{dtstart.strftime('%Y%m%dT%H%M%SZ')}
DTEND:{dtend.strftime('%Y%m%dT%H%M%SZ')}
SUMMARY:{title}
DESCRIPTION:{desc}
LOCATION:{loc}
END:VEVENT
END:VCALENDAR
"""
        return ics

    @staticmethod
    def suggest_time_slots(participants: List[int], duration_minutes: int, start_date: str, end_date: str) -> List[dict]:
        """
        Находит возможные слоты времени с учетом занятости участников и рабочих часов.
        Упрощенный алгоритм: шаг 30 минут, пересечение свободного времени.
        Добавлен фильтр по org_id пользователя через подзапрос (по каждому участнику).
        """
        duration = timedelta(minutes=max(15, int(duration_minutes or 60)))
        start = CalendarService._dt_from_iso(ensure_iso_datetime(start_date) or "")
        end = CalendarService._dt_from_iso(ensure_iso_datetime(end_date) or "")
        if end <= start:
            return []

        # Build busy intervals per participant (org-scoped by user)
        busy_map: Dict[int, List[Tuple[datetime, datetime]]] = {}
        for uid in participants:
            evs = query_db(
                "SELECT start_time, end_time FROM calendar_events "
                "WHERE org_id = (SELECT org_id FROM users WHERE id=?) "
                "AND (organizer_id=? OR id IN (SELECT event_id FROM event_participants WHERE user_id=?)) "
                "AND start_time < ? AND end_time > ?",
                (uid, uid, uid, CalendarService._iso_utc(end), CalendarService._iso_utc(start))
            ) or []
            busy_map[uid] = [(CalendarService._dt_from_iso(e["start_time"]), CalendarService._dt_from_iso(e["end_time"])) for e in evs]

        # Work hours defaults
        def user_view(uid: int) -> dict:
            row = query_db("SELECT * FROM calendar_views WHERE user_id=?", (uid,), one=True)
            return row or {"work_hours_start": "09:00", "work_hours_end": "18:00", "work_days": "[1,2,3,4,5]"}

        suggestions: List[dict] = []
        cur = datetime(start.year, start.month, start.day, 0, 0, 0)
        step = timedelta(minutes=30)
        while cur + duration <= end:
            # only consider if within all users' work hours and work days
            ok_work = True
            for uid in participants:
                v = user_view(uid)
                try:
                    whs = v.get("work_hours_start", "09:00")
                    whe = v.get("work_hours_end", "18:00")
                    wd = json.loads(v.get("work_days", "[1,2,3,4,5]") or "[1,2,3,4,5]")
                except Exception:
                    whs, whe, wd = "09:00", "18:00", [1, 2, 3, 4, 5]
                start_h, start_m = [int(x) for x in whs.split(":")]
                end_h, end_m = [int(x) for x in whe.split(":")]
                start_of_day = datetime(cur.year, cur.month, cur.day, start_h, start_m, 0)
                end_of_day = datetime(cur.year, cur.month, cur.day, end_h, end_m, 0)
                weekday = (cur.weekday() + 1)  # Mon=1..Sun=7
                if weekday not in wd:
                    ok_work = False
                    break
                if cur < start_of_day or (cur + duration) > end_of_day:
                    ok_work = False
                    break
            if not ok_work:
                cur += step
                continue

            # check free for all
            slot_ok = True
            for uid, busy in busy_map.items():
                for (bs, be) in busy:
                    if not (cur + duration <= bs or cur >= be):
                        slot_ok = False
                        break
                if not slot_ok:
                    break
            if slot_ok:
                score = 0.95  # simplistic for now
                suggestions.append({"start": CalendarService._iso_utc(cur), "end": CalendarService._iso_utc(cur + duration), "score": score})
            cur += step

        suggestions.sort(key=lambda x: x["score"], reverse=True)
        return suggestions[:50]

# ===== END OF CORE PART 6/10 =====
# ===== START OF CORE PART 7/10 =====
# coding: utf-8

# ==================== CORE PART 7/10 ====================
# ===== BLOCK: BUSINESS LOGIC: DEALS =====

# Helper: add_audit (safe if already defined elsewhere)
if "add_audit" not in globals():
    def add_audit(org_id: int, user_id: Optional[int], action: str, entity_type: Optional[str] = None,
                  entity_id: Optional[int] = None, details: Optional[dict] = None):
        try:
            ip = get_client_ip()
            ua = request.headers.get("User-Agent", "") if request else ""
            req_id = g.get("request_id", "")
        except Exception:
            ip, ua, req_id = "", "", ""
        try:
            exec_db(
                "INSERT INTO audit_logs (org_id, user_id, action, entity_type, entity_id, details, ip_address, user_agent, request_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (org_id, user_id, action, entity_type, entity_id, json.dumps(details or {}, ensure_ascii=False), ip, ua, req_id, utc_now())
            )
        except Exception as e:
            log("WARN", "add_audit failed", error=str(e))

DEAL_ALLOWED_UPDATE_FIELDS: Set[str] = {
    "title", "amount", "currency", "status", "stage", "pipeline_key",
    "assignee_id", "company_id", "contact_id", "due_at", "won_at", "lost_at", "score"
}

DEFAULT_DEAL_STAGES: List[Tuple[str, str, int]] = [
    ("new", "Новая", 10),
    ("qualify", "Квалификация", 20),
    ("proposal", "Предложение", 30),
    ("negotiation", "Переговоры", 40),
    ("closed", "Закрыта", 90),
]

def ensure_default_deal_stages(org_id: int, pipeline_key: str = "default"):
    try:
        for key, name, sort_order in DEFAULT_DEAL_STAGES:
            try:
                if DIALECT == "postgres":
                    exec_db(
                        "INSERT INTO workflow_stages (org_id, entity_type, pipeline_key, key, name, sort_order, created_at) "
                        "VALUES (?, 'deal', ?, ?, ?, ?, ?) "
                        "ON CONFLICT (org_id, entity_type, pipeline_key, key) DO NOTHING",
                        (org_id, pipeline_key, key, name, sort_order, utc_now())
                    )
                else:
                    existing = query_db(
                        "SELECT 1 AS x FROM workflow_stages WHERE org_id=? AND entity_type='deal' AND pipeline_key=? AND key=?",
                        (org_id, pipeline_key, key), one=True
                    )
                    if not existing:
                        exec_db(
                            "INSERT INTO workflow_stages (org_id, entity_type, pipeline_key, key, name, sort_order, created_at) "
                            "VALUES (?, 'deal', ?, ?, ?, ?, ?)",
                            (org_id, pipeline_key, key, name, sort_order, utc_now())
                        )
            except Exception:
                pass
    except Exception:
        pass

def _record_stage_transition(entity_type: str, entity_id: int, from_stage: Optional[str], to_stage: Optional[str], user_id: Optional[int], comment: Optional[str] = None):
    try:
        exec_db(
            "INSERT INTO stage_transitions (entity_type, entity_id, from_stage, to_stage, user_id, comment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entity_type, entity_id, from_stage, to_stage, user_id, (comment or ""), utc_now())
        )
    except Exception:
        pass

def _calc_deal_score_from_rules(org_id: int, deal: dict) -> int:
    try:
        rules = query_db("SELECT * FROM lead_scoring_rules WHERE org_id=? AND active=1", (org_id,)) or []
        score = int(deal.get("score") or 0)
        for r in rules:
            field = r.get("field")
            operator = (r.get("operator") or "").lower().strip()
            value = r.get("value")
            delta = int(r.get("score_delta") or 0)
            field_val = deal.get(field)
            ok = False
            try:
                if operator == "eq":
                    ok = str(field_val) == str(value)
                elif operator == "neq":
                    ok = str(field_val) != str(value)
                elif operator == "gt":
                    ok = float(field_val or 0) > float(value or 0)
                elif operator == "lt":
                    ok = float(field_val or 0) < float(value or 0)
                elif operator == "ge":
                    ok = float(field_val or 0) >= float(value or 0)
                elif operator == "le":
                    ok = float(field_val or 0) <= float(value or 0)
                elif operator == "contains":
                    ok = (str(value or "")).lower() in (str(field_val or "")).lower()
                elif operator == "in":
                    vals = [v.strip() for v in str(value or "").split(",")]
                    ok = str(field_val) in vals
            except Exception:
                ok = False
            if ok:
                score += delta
        return max(0, min(1000, score))
    except Exception:
        return int(deal.get("score") or 0)

def _deal_predictive_score(deal: dict) -> float:
    """Heuristic predictive lead scoring (0..1)."""
    try:
        base = 0.3
        rules_score = int(deal.get("score") or 0)
        stage = (deal.get("stage") or "").lower()
        created_at = deal.get("created_at")
        age_days = 0.0
        if created_at:
            try:
                dt = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
            except Exception:
                dt = datetime.utcnow()
            age_days = max(0.0, (datetime.utcnow() - dt).total_seconds() / 86400.0)
        if rules_score >= 80: base += 0.3
        elif rules_score >= 50: base += 0.15
        if stage in ("negotiation", "proposal"): base += 0.2
        if age_days > 90: base -= 0.2
        return float(max(0.0, min(1.0, base)))
    except Exception:
        return 0.5

def _deal_close_probability(deal: dict) -> float:
    return _deal_predictive_score(deal)

def _deal_notify_and_insight(org_id: int, deal_id: int, updates: Dict[str, Any], prev: Optional[dict] = None):
    try:
        assignee_id = updates.get("assignee_id") or (prev.get("assignee_id") if prev else None)
        title = updates.get("title") or (prev.get("title") if prev else None) or f"Сделка #{deal_id}"
        if assignee_id:
            if updates.get("stage"):
                sse_push(int(assignee_id or 0), "deal.stage_changed", {"deal_id": deal_id, "stage": updates["stage"]})
            else:
                sse_push(int(assignee_id or 0), "deal.updated", {"deal_id": deal_id, "title": title})
        amount = float(updates.get("amount") or (prev.get("amount") if prev else 0) or 0)
        if amount >= 1_000_000:
            sse_push(int(assignee_id or 0), "twin.insight", {
                "id": uuid.uuid4().hex, "kind": "proactive",
                "title": "Крупная сделка",
                "message": f"Сделка '{title}' с суммой {int(amount)} требует внимания руководителя.",
                "severity": "info", "tags": ["deals", "big"], "ts": utc_now()
            })
        if updates.get("status") == "lost" and (prev and prev.get("status") != "lost"):
            sse_push(int(assignee_id or 0), "twin.insight", {
                "id": uuid.uuid4().hex, "kind": "proactive",
                "title": "Сделка проиграна",
                "message": f"Сделка '{title}' помечена как 'lost'. Рекомендуется анализ причин и обратная связь клиенту.",
                "severity": "warn", "tags": ["deals", "lost"], "ts": utc_now()
            })
    except Exception:
        pass

def create_deal(
    org_id: int,
    title: str,
    amount: float = 0.0,
    currency: str = "RUB",
    status: str = "open",
    stage: str = "new",
    pipeline_key: str = "default",
    assignee_id: Optional[int] = None,
    company_id: Optional[int] = None,
    contact_id: Optional[int] = None,
    due_at: Optional[str] = None
) -> int:
    if not title:
        raise ValueError("Title required")
    ensure_default_deal_stages(org_id, pipeline_key=pipeline_key)
    due_norm = ensure_iso_datetime(due_at) if due_at else None
    with db_transaction():
        did = exec_db(
            """
            INSERT INTO deals (org_id, title, amount, currency, status, stage, pipeline_key, assignee_id,
                               company_id, contact_id, due_at, won_at, lost_at, score, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, title, float(amount or 0), currency, status, stage, pipeline_key, assignee_id,
             company_id, contact_id, due_norm, None, None, 0, utc_now(), utc_now())
        )
        deal_id = int(did or 0)
        row = get_deal(deal_id, org_id)
        if row:
            sc = _calc_deal_score_from_rules(org_id, row)
            exec_db_affect("UPDATE deals SET score=?, updated_at=? WHERE id=?", (sc, utc_now(), deal_id))
        try:
            add_audit(org_id, g.get("user", {}).get("id"), "deal.created", "deal", deal_id, {"title": title})  # type: ignore
        except Exception:
            pass
        _timeline_add(org_id, g.get("user", {}).get("id"), "deal", deal_id, "created", {"title": title})
        try:
            if assignee_id:
                sse_push(int(assignee_id or 0), "deal.created", {"deal_id": deal_id, "title": title})
                notify(int(assignee_id or 0), "Новая сделка", f"Создана сделка #{deal_id}: {title}", kind="info", link=f"/deal/{deal_id}")
        except Exception:
            pass
    return deal_id

def update_deal(deal_id: int, org_id: int, updates: Dict[str, Any]) -> bool:
    if not updates:
        return False
    for fld in ("due_at", "won_at", "lost_at"):
        if fld in updates and updates[fld]:
            updates[fld] = ensure_iso_datetime(updates[fld])
    if "status" in updates:
        st = (updates.get("status") or "").lower()
        if st == "won" and not updates.get("won_at"):
            updates["won_at"] = utc_now()
        if st == "lost" and not updates.get("lost_at"):
            updates["lost_at"] = utc_now()
    prev = query_db("SELECT * FROM deals WHERE id=? AND org_id=?", (deal_id, org_id), one=True) or {}
    recalc = any(k in updates for k in ("amount", "stage", "status", "pipeline_key", "company_id", "assignee_id"))
    set_sql, params = _safe_update_clause(DEAL_ALLOWED_UPDATE_FIELDS, updates)
    if not set_sql:
        return False
    set_sql = f"{set_sql}, updated_at=?"
    params.append(utc_now())
    params.extend([deal_id, org_id])
    with db_transaction():
        rc = exec_db_affect(f"UPDATE deals SET {set_sql} WHERE id=? AND org_id=?", tuple(params))
        if rc:
            if "stage" in updates and (updates["stage"] != (prev.get("stage") or "")):
                _record_stage_transition("deal", deal_id, prev.get("stage"), updates["stage"], g.get("user", {}).get("id"))  # type: ignore
            if recalc:
                row = get_deal(deal_id, org_id)
                if row:
                    sc = _calc_deal_score_from_rules(org_id, row)
                    exec_db_affect("UPDATE deals SET score=?, updated_at=? WHERE id=?", (sc, utc_now(), deal_id))
            try:
                add_audit(org_id, g.get("user", {}).get("id"), "deal.updated", "deal", deal_id, updates)  # type: ignore
            except Exception:
                pass
            _timeline_add(org_id, g.get("user", {}).get("id"), "deal", deal_id, "updated", updates)
        if rc:
            try:
                _deal_notify_and_insight(org_id, deal_id, updates, prev)
            except Exception:
                pass
    return bool(rc)

def change_deal_stage(deal_id: int, org_id: int, new_stage: str, user_id: Optional[int] = None) -> bool:
    prev = query_db("SELECT stage FROM deals WHERE id=? AND org_id=?", (deal_id, org_id), one=True)
    if not prev:
        return False
    old_stage = prev.get("stage")
    if old_stage == new_stage:
        return True
    with db_transaction():
        rc = exec_db_affect("UPDATE deals SET stage=?, updated_at=? WHERE id=? AND org_id=?", (new_stage, utc_now(), deal_id, org_id))
        if rc:
            _record_stage_transition("deal", deal_id, old_stage, new_stage, user_id)
            try:
                add_audit(org_id, user_id, "deal.stage_changed", "deal", deal_id, {"stage": new_stage})  # type: ignore
            except Exception:
                pass
            _timeline_add(org_id, user_id, "deal", deal_id, "stage_changed", {"from": old_stage, "to": new_stage})
            try:
                sse_push(int(user_id or 0), "deal.stage_changed", {"deal_id": deal_id, "stage": new_stage})
            except Exception:
                pass
    return True

def get_deal(deal_id: int, org_id: int) -> Optional[dict]:
    row = query_db(
        """
        SELECT d.*, u.username AS assignee_name, c.name AS company_name
        FROM deals d
        LEFT JOIN users u ON d.assignee_id=u.id
        LEFT JOIN companies c ON d.company_id=c.id
        WHERE d.id=? AND d.org_id=?
        """,
        (deal_id, org_id), one=True
    )
    return row or None

def _encode_cursor(created_at: str, pk: int) -> str:
    try:
        payload = json.dumps({"created_at": created_at, "id": int(pk)}, ensure_ascii=False).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("utf-8")
    except Exception:
        return ""

def _decode_cursor(cursor: str) -> Tuple[Optional[str], Optional[int]]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
        obj = json.loads(raw)
        return str(obj.get("created_at") or ""), int(obj.get("id") or 0)
    except Exception:
        return None, None

def list_deals(org_id: int, pipeline_key: Optional[str] = None, stage: Optional[str] = None,
               status: Optional[str] = None, assignee_id: Optional[int] = None,
               limit: int = 100, offset: Optional[int] = None,
               cursor: Optional[str] = None) -> Tuple[List[dict], int, Optional[str]]:
    """
    Supports legacy offset pagination and keyset pagination via cursor (preferred).
    Cursor format: base64({"created_at": "...", "id": N}), ordered by created_at DESC, id DESC.
    Returns: items, total (approx if cursor used), next_cursor
    """
    limit = max(1, min(int(limit or 100), 200))
    where = ["d.org_id=?"]
    params: List[Any] = [org_id]
    if pipeline_key:
        where.append("d.pipeline_key=?"); params.append(pipeline_key)
    if stage:
        where.append("d.stage=?"); params.append(stage)
    if status:
        where.append("d.status=?"); params.append(status)
    if assignee_id:
        where.append("d.assignee_id=?"); params.append(int(assignee_id))
    wc = " AND ".join(where)

    items: List[dict] = []
    total = 0
    next_cursor = None

    if cursor:
        c_created, c_id = _decode_cursor(cursor)
        if c_created and c_id:
            where_keyset = wc + " AND (d.created_at < ? OR (d.created_at = ? AND d.id < ?))"
            params_keyset = params + [ensure_iso_datetime(c_created), ensure_iso_datetime(c_created), int(c_id)]
            items = query_db(
                f"""
                SELECT d.*, u.username AS assignee_name, c.name AS company_name
                FROM deals d
                LEFT JOIN users u ON d.assignee_id=u.id
                LEFT JOIN companies c ON d.company_id=c.id
                WHERE {where_keyset}
                ORDER BY d.created_at DESC, d.id DESC
                LIMIT ?
                """,
                (*params_keyset, int(limit))
            ) or []
            total_row = query_db(f"SELECT COUNT(*) AS c FROM deals d WHERE {wc}", tuple(params), one=True)
            total = int((total_row or {}).get("c") or 0)
    else:
        items = query_db(
            f"""
            SELECT d.*, u.username AS assignee_name, c.name AS company_name
            FROM deals d
            LEFT JOIN users u ON d.assignee_id=u.id
            LEFT JOIN companies c ON d.company_id=c.id
            WHERE {wc}
            ORDER BY d.created_at DESC, d.id DESC
            LIMIT ?
            """,
            (*params, int(limit))
        ) or []
        total_row = query_db(f"SELECT COUNT(*) AS c FROM deals d WHERE {wc}", tuple(params), one=True)
        total = int((total_row or {}).get("c") or 0)

    if items:
        last = items[-1]
        next_cursor = _encode_cursor(last.get("created_at") or utc_now(), int(last.get("id") or 0))
    else:
        next_cursor = None

    if offset is not None and cursor is None:
        items = query_db(
            f"""
            SELECT d.*, u.username AS assignee_name, c.name AS company_name
            FROM deals d
            LEFT JOIN users u ON d.assignee_id=u.id
            LEFT JOIN companies c ON d.company_id=c.id
            WHERE {wc}
            ORDER BY d.created_at DESC, d.id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, int(limit), int(offset))
        ) or []
        total_row = query_db(f"SELECT COUNT(*) AS c FROM deals d WHERE {wc}", tuple(params), one=True)
        total = int((total_row or {}).get("c") or 0)
        if items:
            last = items[-1]
            next_cursor = _encode_cursor(last.get("created_at") or utc_now(), int(last.get("id") or 0))
        else:
            next_cursor = None

    return items, total, next_cursor

def deals_kanban(org_id: int, pipeline_key: str = "default") -> Tuple[List[dict], Dict[str, List[dict]]]:
    ensure_default_deal_stages(org_id, pipeline_key=pipeline_key)
    stages = query_db(
        """
        SELECT key, name, sort_order FROM workflow_stages
        WHERE org_id=? AND entity_type='deal' AND pipeline_key=?
        ORDER BY sort_order, key
        """,
        (org_id, pipeline_key)
    ) or []
    keys = [s["key"] for s in stages] if stages else [x[0] for x in DEFAULT_DEAL_STAGES]
    items_by_stage: Dict[str, List[dict]] = {k: [] for k in keys}
    rows = query_db(
        """
        SELECT d.*, u.username AS assignee_name, c.name AS company_name
        FROM deals d
        LEFT JOIN users u ON d.assignee_id=u.id
        LEFT JOIN companies c ON d.company_id=c.id
        WHERE d.org_id=? AND d.pipeline_key=? AND d.status='open'
        ORDER BY d.created_at DESC
        """,
        (org_id, pipeline_key)
    ) or []
    for r in rows:
        k = (r.get("stage") or "new")
        if k not in items_by_stage:
            items_by_stage[k] = []
        items_by_stage[k].append(r)
    # Return stages with meta and map
    return stages, items_by_stage

def deal_close_probability(org_id: int, deal_id: int) -> float:
    row = get_deal(deal_id, org_id)
    if not row:
        return 0.0
    return _deal_close_probability(row)


# ===== BLOCK: BUSINESS LOGIC: CPQ (QUOTES) =====
QUOTE_ALLOWED_UPDATE_FIELDS: Set[str] = {"title", "currency", "status"}

def _recalc_quote_total(quote_id: int):
    try:
        rows = query_db("SELECT qty, price, discount_pct FROM quote_items WHERE quote_id=?", (quote_id,)) or []
        total = 0.0
        for r in rows:
            qty = float(r.get("qty") or 0)
            price = float(r.get("price") or 0)
            disc = float(r.get("discount_pct") or 0)
            line = qty * price * (1.0 - disc / 100.0)
            total += line
        exec_db_affect("UPDATE quotes SET total=?, updated_at=? WHERE id=?", (round(total, 2), utc_now(), quote_id))
    except Exception as e:
        log("WARN", "recalc quote failed", error=str(e))

def create_quote(org_id: int, title: str, deal_id: Optional[int] = None, company_id: Optional[int] = None,
                 currency: str = "RUB", created_by: Optional[int] = None) -> int:
    if not title:
        raise ValueError("Title required")
    with db_transaction():
        qid = exec_db(
            "INSERT INTO quotes (org_id, deal_id, company_id, title, currency, total, status, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, deal_id, company_id, title, currency, 0.0, "draft", created_by, utc_now(), utc_now())
        )
        try:
            add_audit(org_id, created_by, "quote.created", "quote", int(qid or 0), {"title": title})
        except Exception:
            pass
        _timeline_add(org_id, created_by, "quote", int(qid or 0), "created", {"title": title})
    return int(qid or 0)

def add_quote_item(quote_id: int, name: str, qty: float = 1.0, price: float = 0.0, discount_pct: float = 0.0,
                   product_id: Optional[int] = None, sort_order: int = 0) -> int:
    if not name:
        raise ValueError("Item name required")
    line_total = float(qty) * float(price) * (1.0 - float(discount_pct) / 100.0)
    with db_transaction():
        it_id = exec_db(
            "INSERT INTO quote_items (quote_id, product_id, name, qty, price, discount_pct, total, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (quote_id, product_id, name, float(qty), float(price), float(discount_pct), round(line_total, 2), sort_order)
        )
        _recalc_quote_total(quote_id)
        try:
            q = query_db("SELECT org_id FROM quotes WHERE id=?", (quote_id,), one=True)
            if q:
                add_audit(int(q["org_id"]), g.get("user", {}).get("id"), "quote.item_added", "quote", quote_id, {"item_id": int(it_id or 0)})  # type: ignore
                _timeline_add(int(q["org_id"]), g.get("user", {}).get("id"), "quote", quote_id, "item_added", {"item_id": int(it_id or 0)})
        except Exception:
            pass
    return int(it_id or 0)

def update_quote_item(item_id: int, updates: Dict[str, Any]) -> bool:
    allowed = {"name", "qty", "price", "discount_pct", "sort_order", "product_id"}
    set_sql, params = _safe_update_clause(allowed, updates or {})
    if not set_sql:
        return False
    params.append(item_id)
    with db_transaction():
        rc = exec_db_affect(f"UPDATE quote_items SET {set_sql} WHERE id=?", tuple(params))
        if rc:
            try:
                row = query_db("SELECT quote_id FROM quote_items WHERE id=?", (item_id,), one=True)
                if row and row.get("quote_id"):
                    _recalc_quote_total(int(row["quote_id"]))
            except Exception:
                pass
    return bool(rc)

def get_quote(quote_id: int, org_id: int) -> Optional[dict]:
    q = query_db("SELECT * FROM quotes WHERE id=? AND org_id=?", (quote_id, org_id), one=True)
    return q or None

def list_quote_items(quote_id: int) -> List[dict]:
    return query_db("SELECT * FROM quote_items WHERE quote_id=? ORDER BY sort_order, id", (quote_id,)) or []

def update_quote(quote_id: int, org_id: int, updates: Dict[str, Any]) -> bool:
    set_sql, params = _safe_update_clause(QUOTE_ALLOWED_UPDATE_FIELDS, updates or {})
    if not set_sql:
        return False
    set_sql = f"{set_sql}, updated_at=?"
    params.append(utc_now())
    params.extend([quote_id, org_id])
    with db_transaction():
        rc = exec_db_affect(f"UPDATE quotes SET {set_sql} WHERE id=? AND org_id=?", tuple(params))
    return bool(rc)

def finalize_quote(quote_id: int, org_id: int) -> bool:
    with db_transaction():
        rc = exec_db_affect("UPDATE quotes SET status=?, updated_at=? WHERE id=? AND org_id=?", ("final", utc_now(), quote_id, org_id))
    return bool(rc)


# ===== BLOCK: BUSINESS LOGIC: PAYROLL =====
def _payroll_parse_plan(cfg: dict) -> dict:
    """
    Normalize compensation plan config.
    Example config_json:
    {
        "base_salary": 50000,
        "percent_of_sales": 0.03,
        "margin_thresholds": [{"min":0,"pct":0.0},{"min":500000,"pct":0.01},{"min":1000000,"pct":0.02}],
        "kpis": {"tasks_done": {"weight": 0.2, "target": 50}, "calls_made": {"weight": 0.1, "target": 200}},
        "team_bonus_pct": 0.01
    }
    """
    cfg = cfg or {}
    return {
        "base_salary": float(cfg.get("base_salary", 0)),
        "percent_of_sales": float(cfg.get("percent_of_sales", 0)),
        "margin_thresholds": list(cfg.get("margin_thresholds", [])),
        "kpis": dict(cfg.get("kpis", {})),
        "team_bonus_pct": float(cfg.get("team_bonus_pct", 0)),
    }

def payroll_ensure_period(org_id: int, period_key: str, date_start: str, date_end: str) -> int:
    row = query_db("SELECT id FROM payroll_periods WHERE org_id=? AND period_key=?", (org_id, period_key), one=True)
    if row:
        return int(row["id"])
    pid = exec_db("INSERT INTO payroll_periods (org_id, period_key, date_start, date_end, locked, created_at) VALUES (?, ?, ?, ?, 0, ?)",
                  (org_id, period_key, ensure_iso_datetime(date_start), ensure_iso_datetime(date_end), utc_now()))
    return int(pid or 0)

def _payroll_calc_percent_on_thresholds(amount: float, thresholds: List[dict]) -> float:
    pct = 0.0
    for th in sorted(thresholds, key=lambda x: float(x.get("min", 0))):
        if amount >= float(th.get("min", 0)):
            pct = float(th.get("pct", 0))
        else:
            break
    return pct

def payroll_collect_metrics(org_id: int, user_id: int, date_start: str, date_end: str) -> dict:
    # Deals (won in period)
    deal_sum_row = query_db(
        "SELECT COALESCE(SUM(amount),0) AS s FROM deals WHERE org_id=? AND assignee_id=? AND status='won' AND won_at >= ? AND won_at <= ?",
        (org_id, user_id, ensure_iso_datetime(date_start), ensure_iso_datetime(date_end)), one=True
    ) or {}
    deals_amount = float(deal_sum_row.get("s") or 0)
    # Margin approximation = amount
    deals_margin = deals_amount
    # Tasks done
    tasks_row = query_db(
        "SELECT COUNT(*) AS c FROM tasks WHERE org_id=? AND assignee_id=? AND status='done' AND completed_at >= ? AND completed_at <= ?",
        (org_id, user_id, ensure_iso_datetime(date_start), ensure_iso_datetime(date_end)), one=True
    ) or {}
    tasks_done = int(tasks_row.get("c") or 0)
    # Calls made
    calls_row = query_db(
        "SELECT COUNT(*) AS c FROM calls WHERE org_id=? AND agent_id=? AND started_at >= ? AND started_at <= ?",
        (org_id, user_id, ensure_iso_datetime(date_start), ensure_iso_datetime(date_end)), one=True
    ) or {}
    calls_made = int(calls_row.get("c") or 0)
    return {"deals_amount": deals_amount, "deals_margin": deals_margin, "tasks_done": tasks_done, "calls_made": calls_made, "kpi_json": {}}

def payroll_calculate_user(org_id: int, period_id: int, user_id: int) -> dict:
    period = query_db("SELECT * FROM payroll_periods WHERE id=? AND org_id=?", (period_id, org_id), one=True) or {}
    if not period:
        return {"ok": False, "error": "period_not_found"}
    ds, de = period["date_start"], period["date_end"]

    # Assignment (latest effective)
    asg = query_db(
        "SELECT a.*, p.config_json FROM payroll_assignments a JOIN payroll_plans p ON p.id=a.plan_id "
        "WHERE a.org_id=? AND a.user_id=? AND a.effective_from <= ? AND (a.effective_to IS NULL OR a.effective_to >= ?) "
        "ORDER BY a.effective_from DESC LIMIT 1",
        (org_id, user_id, ensure_iso_datetime(de), ensure_iso_datetime(ds)), one=True
    )
    if not asg:
        plan = _payroll_parse_plan({})
        plan_id = None
    else:
        try:
            plan = _payroll_parse_plan(json.loads(asg.get("config_json") or "{}"))
        except Exception:
            plan = _payroll_parse_plan({})
        plan_id = int(asg["plan_id"])

    # Collect metrics
    metrics = payroll_collect_metrics(org_id, user_id, ds, de)
    deals_amount = metrics["deals_amount"]
    deals_margin = metrics["deals_margin"]
    tasks_done = metrics["tasks_done"]
    calls_made = metrics["calls_made"]

    # Compute components
    base_salary = plan["base_salary"]
    sales_pct = plan["percent_of_sales"]
    threshold_pct = _payroll_calc_percent_on_thresholds(deals_margin, plan["margin_thresholds"])
    kpi_bonus = 0.0
    for kpi_name, kpi_cfg in plan["kpis"].items():
        weight = float(kpi_cfg.get("weight", 0))
        target = float(kpi_cfg.get("target", 0))
        actual = 0.0
        if kpi_name == "tasks_done": actual = float(tasks_done)
        elif kpi_name == "calls_made": actual = float(calls_made)
        ratio = 0.0 if target <= 0 else min(1.2, actual / target)  # allow slight over-performance
        kpi_bonus += weight * ratio * base_salary

    pct_component = deals_amount * (sales_pct + threshold_pct)
    gross = base_salary + pct_component + kpi_bonus
    bonus = max(0.0, pct_component + kpi_bonus)
    penalty = 0.0
    net = max(0.0, gross - penalty)

    # Upsert metrics
    mid = query_db("SELECT id FROM payroll_metrics WHERE org_id=? AND period_id=? AND user_id=?", (org_id, period_id, user_id), one=True)
    if mid:
        exec_db_affect(
            "UPDATE payroll_metrics SET deals_amount=?, deals_margin=?, tasks_done=?, calls_made=?, kpi_json=?, created_at=? WHERE id=?",
            (deals_amount, deals_margin, tasks_done, calls_made, json.dumps(metrics.get("kpi_json") or {}, ensure_ascii=False), utc_now(), mid["id"])
        )
        metrics_id = int(mid["id"])
    else:
        metrics_id = exec_db(
            "INSERT INTO payroll_metrics (org_id, period_id, user_id, deals_amount, deals_margin, tasks_done, calls_made, kpi_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, period_id, user_id, deals_amount, deals_margin, tasks_done, calls_made, json.dumps(metrics.get("kpi_json") or {}, ensure_ascii=False), utc_now())
        )

    # Upsert payout
    pid = query_db("SELECT id FROM payroll_payouts WHERE org_id=? AND period_id=? AND user_id=?", (org_id, period_id, user_id), one=True)
    breakdown = {
        "base_salary": base_salary,
        "sales_component": pct_component,
        "kpi_bonus": kpi_bonus,
        "threshold_pct": threshold_pct,
        "percent_of_sales": sales_pct,
        "metrics": metrics
    }
    if pid:
        exec_db_affect(
            "UPDATE payroll_payouts SET plan_id=?, gross_amount=?, bonus_amount=?, penalty_amount=?, net_amount=?, breakdown_json=?, status='draft', approved_by=NULL, approved_at=NULL WHERE id=?",
            (plan_id, gross, bonus, penalty, net, json.dumps(breakdown, ensure_ascii=False), pid["id"])
        )
        payout_id = int(pid["id"])
    else:
        payout_id = exec_db(
            "INSERT INTO payroll_payouts (org_id, period_id, user_id, plan_id, gross_amount, bonus_amount, penalty_amount, net_amount, breakdown_json, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)",
            (org_id, period_id, user_id, plan_id, gross, bonus, penalty, net, json.dumps(breakdown, ensure_ascii=False), utc_now())
        )

    return {
        "ok": True,
        "payout_id": int(payout_id or 0),
        "metrics_id": int(metrics_id or 0),
        "gross": gross,
        "net": net,
        "bonus": bonus,
        "penalty": penalty,
        "breakdown": breakdown
    }

def payroll_recalculate_period(org_id: int, period_key: str) -> dict:
    period = query_db("SELECT * FROM payroll_periods WHERE org_id=? AND period_key=?", (org_id, period_key), one=True)
    if not period:
        return {"ok": False, "error": "period_not_found"}
    if int(period.get("locked") or 0) == 1:
        return {"ok": False, "error": "period_locked"}
    users = query_db("SELECT id FROM users WHERE org_id=? AND active=1", (org_id,)) or []
    results = []
    for u in users:
        try:
            res = payroll_calculate_user(org_id, int(period["id"]), int(u["id"]))
            results.append({"user_id": int(u["id"]), "ok": res.get("ok", True), "net": res.get("net", 0), "payout_id": res.get("payout_id")})
        except Exception as e:
            results.append({"user_id": int(u["id"]), "ok": False, "error": str(e)})
    return {"ok": True, "period_id": int(period["id"]), "results": results}

def payroll_user_summary(org_id: int, user_id: int, period_key: str) -> dict:
    period = query_db("SELECT * FROM payroll_periods WHERE org_id=? AND period_key=?", (org_id, period_key), one=True)
    if not period:
        return {"ok": False, "error": "period_not_found"}
    payout = query_db(
        "SELECT * FROM payroll_payouts WHERE org_id=? AND period_id=? AND user_id=?",
        (org_id, int(period["id"]), user_id), one=True
    ) or {}
    metrics = query_db(
        "SELECT * FROM payroll_metrics WHERE org_id=? AND period_id=? AND user_id=?",
        (org_id, int(period["id"]), user_id), one=True
    ) or {}
    return {"ok": True, "period": period, "payout": payout, "metrics": metrics}

def payroll_lock_period(org_id: int, period_key: str, lock: bool = True) -> bool:
    row = query_db("SELECT id FROM payroll_periods WHERE org_id=? AND period_key=?", (org_id, period_key), one=True)
    if not row:
        return False
    exec_db_affect("UPDATE payroll_periods SET locked=? WHERE id=?", (1 if lock else 0, row["id"]))
    return True

# ===== END OF CORE PART 7/10 =====
# ==================== CORE PART 8/10 ====================
# ===== BLOCK: DIGITAL TWIN (STATE, FORECASTS, SIMULATIONS, INSIGHTS) =====
# Cache helpers (L1 TTLCache + L2 Redis JSON)
def _cache_get_json(key: str) -> Optional[Any]:
    try:
        v = redis_get(key)
        if v is not None:
            try:
                return json.loads(v)
            except Exception:
                return None
        return _global_cache.get(key)
    except Exception:
        return None

def _cache_set_json(key: str, value: Any, ttl: int = CACHE_DEFAULT_TTL):
    try:
        payload = json.dumps(value, ensure_ascii=False)
        if not redis_setex(key, ttl, payload):
            _global_cache.set(key, value, ttl)
    except Exception:
        try:
            _global_cache.set(key, value, ttl)
        except Exception:
            pass

def _ensure_mv_tables():
    """
    Create lightweight materialized rollups for dashboard if not exists.
    Postgres/SQLite: simple key-value table updated by maintenance worker.
    """
    try:
        if DIALECT == "postgres":
            exec_db("""
            CREATE TABLE IF NOT EXISTS mv_dashboard (
                org_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value_number DOUBLE PRECISION,
                updated_at TIMESTAMP WITHOUT TIME ZONE,
                PRIMARY KEY (org_id, key)
            )
            """, ())
        else:
            exec_db("""
            CREATE TABLE IF NOT EXISTS mv_dashboard (
                org_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value_number REAL,
                updated_at TEXT,
                PRIMARY KEY (org_id, key)
            )
            """, ())
    except Exception:
        pass

class BusinessTwin:
    def __init__(self, org_id: int):
        self.org_id = int(org_id)
        _ensure_mv_tables()
        self.state = self._load_state()

    # ---- Load current org state (sales, operations, CS, finance) with caching ----
    def _load_state(self) -> dict:
        sales = {
            "pipeline_value": self._sum_cached("deals", "amount", "status='open'", cache_key="sales:pipeline_value", ttl=30),
            "open_deals": self._count_cached("deals", "status='open'", cache_key="sales:open_deals", ttl=30),
            "conversion_rate_30d": self._conversion_rate_days(30),
            "avg_deal_size": self._avg("deals", "amount", "status='won'"),
            "sales_velocity": self._sales_velocity_days(),
        }
        ops = {
            "open_tasks": self._count_cached("tasks", "status NOT IN ('done','cancelled')", cache_key="ops:open_tasks", ttl=30),
            "overdue_tasks": self._count("tasks", "status NOT IN ('done','cancelled') AND due_at IS NOT NULL AND due_at < ?", (utc_now(),)),
            "avg_task_completion_time": self._avg_task_time_days(),
            "team_utilization": self._team_utilization_ratio(),
        }
        cs = {
            "active_customers": self._active_customers_days(90),
            "churn_rate_30d": self._churn_rate_days(30),
            "nps_score": self._avg_kpi("nps_score", 90, default=0.0, clamp=(-100.0, 100.0)),
            "avg_response_time": self._avg_first_response_days(),
        }
        fin = {
            "mrr": self._mrr_approx(),
            "arr": self._arr_approx(),
            "cash_flow_30d": self._cash_flow_days(30),
            "target_month": self._sales_target_month(),
        }
        return {"sales": sales, "operations": ops, "customer_success": cs, "finance": fin}

    # ---- Basic aggregations ----
    def _count(self, table: str, where_sql: Optional[str] = None, params: Tuple[Any, ...] = ()) -> int:
        q = f"SELECT COUNT(*) AS c FROM {table} WHERE org_id=?"
        args: List[Any] = [self.org_id]
        if where_sql:
            q += f" AND {where_sql}"
            args.extend(list(params or ()))
        row = query_db(q, tuple(args), one=True)
        return int((row or {}).get("c") or 0)

    def _count_cached(self, table: str, where_sql: str, cache_key: str, ttl: int = 60) -> int:
        key = f"tw:{self.org_id}:{cache_key}"
        v = _cache_get_json(key)
        if isinstance(v, (int, float)):
            return int(v)
        val = self._count(table, where_sql)
        _cache_set_json(key, val, ttl)
        return val

    def _sum(self, table: str, field: str, where_sql: Optional[str] = None, params: Tuple[Any, ...] = ()) -> float:
        q = f"SELECT COALESCE(SUM({field}),0) AS s FROM {table} WHERE org_id=?"
        args: List[Any] = [self.org_id]
        if where_sql:
            q += f" AND {where_sql}"
            args.extend(list(params or ()))
        row = query_db(q, tuple(args), one=True)
        return float((row or {}).get("s") or 0.0)

    def _sum_cached(self, table: str, field: str, where_sql: Optional[str] = None, params: Tuple[Any, ...] = (), cache_key: str = "", ttl: int = 60) -> float:
        key = f"tw:{self.org_id}:{cache_key}" if cache_key else ""
        if key:
            v = _cache_get_json(key)
            if isinstance(v, (int, float)):
                return float(v)
        val = self._sum(table, field, where_sql, params)
        if key:
            _cache_set_json(key, val, ttl)
        return val

    def _avg(self, table: str, field: str, where_sql: Optional[str] = None, params: Tuple[Any, ...] = ()) -> float:
        q = f"SELECT AVG({field}) AS a FROM {table} WHERE org_id=?"
        args: List[Any] = [self.org_id]
        if where_sql:
            q += f" AND {where_sql}"
            args.extend(list(params or ()))
        row = query_db(q, tuple(args), one=True)
        return float((row or {}).get("a") or 0.0)

    # ---- KPI helpers ----
    def _avg_kpi(self, name: str, days: int, default: float = 0.0, clamp: Tuple[float, float] = (-1e9, 1e9)) -> float:
        row = query_db(
            "SELECT AVG(value_number) AS v FROM ai_kpis WHERE org_id=? AND name=? AND ts >= ?",
            (self.org_id, self._kpi_name(name), self._ts_minus_days(days)),
            one=True
        )
        v = float((row or {}).get("v") or default)
        return max(clamp[0], min(clamp[1], v))

    def _kpi_name(self, name: str) -> str:
        return name

    def _sales_target_month(self) -> float:
        row = query_db(
            "SELECT value_number FROM ai_kpis WHERE org_id=? AND name=? ORDER BY ts DESC LIMIT 1",
            (self.org_id, self._kpi_name("sales_target_month")), one=True
        )
        return float((row or {}).get("value_number") or 0.0)

    # ---- Time helpers ----
    def _ts_minus_days(self, days: int) -> str:
        dt = datetime.utcnow() - timedelta(days=int(days))
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    # ---- Sales metrics ----
    def _conversion_rate_days(self, days: int) -> float:
        won = self._count("deals", "status='won' AND won_at >= ?", (self._ts_minus_days(days),))
        started = self._count("deals", "created_at >= ?", (self._ts_minus_days(days),))
        return (won / started) if started > 0 else 0.0

    def _sales_velocity_days(self) -> float:
        rows = query_db(
            "SELECT created_at, COALESCE(won_at, updated_at) AS done_at FROM deals WHERE org_id=? AND status='won' AND won_at IS NOT NULL",
            (self.org_id,)
        ) or []
        diffs: List[float] = []
        for r in rows:
            try:
                c = datetime.strptime(r.get("created_at"), "%Y-%m-%d %H:%M:%S")
                w = datetime.strptime(r.get("done_at"), "%Y-%m-%d %H:%M:%S")
                diffs.append((w - c).total_seconds() / 86400.0)
            except Exception:
                continue
        return round(sum(diffs) / max(1, len(diffs)), 2) if diffs else 0.0

    # ---- Operations metrics ----
    def _avg_task_time_days(self) -> float:
        rows = query_db(
            "SELECT created_at, COALESCE(completed_at, updated_at) AS done_at FROM tasks WHERE org_id=? AND completed_at IS NOT NULL",
            (self.org_id,)
        ) or []
        vals: List[float] = []
        for r in rows:
            try:
                c = datetime.strptime(r.get("created_at"), "%Y-%m-%d %H:%M:%S")
                d = datetime.strptime(r.get("done_at"), "%Y-%m-%d %H:%M:%S")
                vals.append((d - c).total_seconds() / 86400.0)
            except Exception:
                continue
        return round(sum(vals) / max(1, len(vals)), 2) if vals else 0.0

    def _team_utilization_ratio(self) -> float:
        total_open = self._count_cached("tasks", "status NOT IN ('done','cancelled')", cache_key="ops:open_tasks", ttl=30)
        members_row = query_db("SELECT COUNT(*) AS c FROM users WHERE org_id=? AND active=1", (self.org_id,), one=True)
        cnt = int((members_row or {}).get("c") or 1)
        util = min(1.0, float(total_open) / max(1.0, cnt * 10.0))
        return round(util, 2)

    # ---- CS metrics ----
    def _active_customers_days(self, days: int) -> int:
        row = query_db(
            "SELECT COUNT(DISTINCT company_id) AS c FROM deals WHERE org_id=? AND company_id IS NOT NULL AND created_at >= ?",
            (self.org_id, self._ts_minus_days(days)), one=True
        )
        return int((row or {}).get("c") or 0)

    def _churn_rate_days(self, days: int) -> float:
        lost = self._count("deals", "status='lost' AND lost_at >= ?", (self._ts_minus_days(days),))
        total_row = query_db("SELECT COUNT(*) AS c FROM companies WHERE org_id=?", (self.org_id,), one=True)
        total = int((total_row or {}).get("c") or 0)
        return (lost / total) if total > 0 else 0.0

    def _avg_first_response_days(self) -> float:
        rows = query_db(
            "SELECT created_at, first_response_at FROM inbox_threads WHERE org_id=? AND first_response_at IS NOT NULL",
            (self.org_id,)
        ) or []
        vals: List[float] = []
        for r in rows:
            try:
                c = datetime.strptime(r.get("created_at"), "%Y-%m-%d %H:%M:%S")
                f = datetime.strptime(r.get("first_response_at"), "%Y-%m-%d %H:%M:%S")
                vals.append((f - c).total_seconds() / 86400.0)
            except Exception:
                continue
        return round(sum(vals) / max(1, len(vals)), 3) if vals else 0.0

    # ---- Finance metrics ----
    def _mrr_approx(self) -> float:
        won30 = self._sum("deals", "amount", "status='won' AND won_at >= ?", (self._ts_minus_days(30),))
        return round(float(won30) / 12.0, 2)

    def _arr_approx(self) -> float:
        return round(self._mrr_approx() * 12.0, 2)

    def _cash_flow_days(self, days: int) -> float:
        s = self._sum("deals", "amount", "status='won' AND won_at >= ?", (self._ts_minus_days(days),))
        return float(s or 0.0)

    # ---- Health score & insights ----
    def get_health_score(self) -> dict:
        s = self.state
        sales_health = min(100.0, (s["sales"]["pipeline_value"] / 1_000_000.0) * 20.0) + s["sales"]["conversion_rate_30d"] * 100.0
        sales_health /= 2.0
        ops_health = 0.0
        if s["operations"]["open_tasks"] > 0:
            ops_health = (1.0 - (s["operations"]["overdue_tasks"] / max(1.0, float(s["operations"]["open_tasks"])))) * 100.0
        cs_health = ((1.0 - s["customer_success"]["churn_rate_30d"]) * 100.0 + (s["customer_success"]["nps_score"] + 100.0) / 2.0) / 2.0
        fin_health = 0.0
        mrr = s["finance"]["mrr"]
        target = s["finance"]["target_month"]
        if mrr and target:
            fin_health = max(0.0, min(100.0, (mrr * 12.0) / max(1.0, target) * 100.0))
        elif mrr:
            fin_health = min(100.0, (mrr / 100_000.0) * 100.0)
        overall = sales_health * 0.3 + ops_health * 0.2 + cs_health * 0.3 + fin_health * 0.2
        return {
            "overall": round(overall, 1),
            "breakdown": {
                "sales": round(sales_health, 1),
                "operations": round(ops_health, 1),
                "customer_success": round(cs_health, 1),
                "finance": round(fin_health, 1)
            },
            "status": "healthy" if overall >= 70 else ("warning" if overall >= 50 else "critical")
        }

    def predict_next_30_days(self) -> dict:
        return {
            "deals_to_close": self._predict_deal_closures(),
            "revenue_forecast": self._forecast_revenue(),
            "churn_risk": self._predict_churn(),
            "team_capacity": self._forecast_team_capacity(),
        }

    def _predict_deal_closures(self) -> List[dict]:
        if DIALECT == "postgres":
            rows = query_db(
                """
                SELECT d.*, (EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - d.created_at))/86400.0) AS age_days
                FROM deals d
                WHERE d.org_id=? AND d.status='open'
                ORDER BY d.created_at DESC
                """,
                (self.org_id,)
            )
        else:
            rows = query_db(
                """
                SELECT d.*, (julianday('now') - julianday(d.created_at)) AS age_days
                FROM deals d
                WHERE d.org_id=? AND d.status='open'
                ORDER BY d.created_at DESC
                """,
                (self.org_id,)
            )
        out: List[dict] = []
        for d in rows or []:
            prob = float(_deal_close_probability(d))
            if prob > 0.5:
                out.append({
                    "deal_id": d["id"],
                    "title": d["title"],
                    "amount": float(d.get("amount") or 0),
                    "close_probability": round(prob, 2),
                    "expected_close_date": self._estimate_close(d, prob),
                    "recommended_actions": self._deal_recs(d, prob)
                })
        out.sort(key=lambda x: x["close_probability"], reverse=True)
        return out

    def _estimate_close(self, drow: dict, p: float) -> str:
        created = drow.get("created_at") or utc_now()
        try:
            dt = datetime.strptime(created, "%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = datetime.utcnow()
        days = max(1, int(30 * (1.0 - p)))
        return (dt + timedelta(days=days)).strftime("%Y-%m-%d")

    def _deal_recs(self, drow: dict, p: float) -> List[str]:
        recs: List[str] = []
        if p >= 0.8:
            recs.append("Подготовить финальное КП")
        if (drow.get("stage") or "") == "negotiation":
            recs.append("Запланировать звонок ЛПР")
        if p < 0.6:
            recs.append("Провести повторную квалификацию потребностей")
        return recs

    def _forecast_revenue(self) -> dict:
        deals = self._predict_deal_closures()
        expected = sum((d["amount"] * d["close_probability"]) for d in deals)
        baseline = self.state["finance"]["mrr"] * 12.0
        return {"expected_30d": round(expected, 2), "baseline_arr": round(baseline, 2)}

    def _predict_churn(self) -> dict:
        churn_rate = self._churn_rate_days(30)
        at_risk = max(0, int(self.state["customer_success"]["active_customers"] * churn_rate))
        return {"churn_rate_30d": round(churn_rate, 3), "at_risk_customers": at_risk}

    def _forecast_team_capacity(self) -> dict:
        open_tasks = self.state["operations"]["open_tasks"]
        members = query_db("SELECT COUNT(*) AS c FROM users WHERE org_id=? AND active=1", (self.org_id,), one=True)
        cap = int((members or {}).get("c") or 1) * 20
        backlog_days = (open_tasks / max(1, cap)) * 5.0
        return {"capacity_per_week": cap, "estimated_backlog_days": round(backlog_days, 1)}

# ===== Snapshots =====
def save_digital_twin_snapshot(org_id: int, twin: BusinessTwin):
    try:
        exec_db(
            "INSERT INTO digital_twin_snapshots (org_id, state_json, health_json, created_at) VALUES (?, ?, ?, ?)",
            (org_id, json.dumps(twin.state, ensure_ascii=False), json.dumps(twin.get_health_score(), ensure_ascii=False), utc_now())
        )
    except Exception as e:
        log("WARN", "save snapshot failed", error=str(e))
# ===== CORE PART 8/10 — часть 2/2 =====
# ===== Decision Center integration =====
class DecisionCenter:
    def consult(self, query: dict) -> dict:
        try:
            org_id = int(query.get("org_id") or 0)
            if not org_id:
                return {"ok": False, "error": "org_id required"}
            twin = BusinessTwin(org_id)
            kind = (query.get("kind") or "nba").lower()
            if kind == "nba":
                return {"ok": True, "nba": twin.next_best_actions()}
            if kind == "forecast":
                return {"ok": True, "forecast": twin.predict_next_30_days(), "health": twin.get_health_score()}
            if kind == "simulate":
                scenario = query.get("scenario") or {}
                return {"ok": True, "simulation": twin.simulate_scenario(scenario)}
            if kind == "rag_answer":
                qtext = (query.get("q") or "").strip()
                etype = (query.get("entity_type") or None)
                return rag_answer(org_id, qtext, entity_type=etype)
            return {"ok": False, "error": "unknown kind"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def publish_insight(self, user_id: int, payload: dict):
        try:
            sse_push(int(user_id), "twin.insight", payload)
            _increment_metric("api_calls_total", {"provider": "twin", "model": "insight"})
        except Exception as e:
            log("WARN", "DecisionCenter publish failed", error=str(e))

    def next_best_actions(self, twin: BusinessTwin, limit: int = 5) -> List[dict]:
        return twin.next_best_actions(limit=limit)

# Provide DECISION_CENTER singleton
if "DECISION_CENTER" not in globals():
    DECISION_CENTER = DecisionCenter()

# ===== Extend BusinessTwin with NBA + simulations =====
def _twin_nba(self: BusinessTwin, limit: int = 5) -> List[dict]:
    actions: List[dict] = []
    st = self.state
    if st["operations"]["overdue_tasks"] > 0:
        actions.append({"priority": "high", "text": f"Закрыть просроченные задачи: {st['operations']['overdue_tasks']}"})
    for d in self._predict_deal_closures()[:3]:
        actions.append({"priority": "high" if d["close_probability"] >= 0.8 else "normal",
                        "text": f"Сделка '{d['title']}' — {', '.join(d['recommended_actions'])}"})
    if st["customer_success"]["avg_response_time"] > 0.25:
        actions.append({"priority": "normal", "text": "Сократить среднее время первого ответа по тикетам"})
    if st["finance"]["target_month"] and (st["finance"]["mrr"] * 12.0) < 0.9 * st["finance"]["target_month"]:
        actions.append({"priority": "high", "text": "Риск недовыполнения плана: усилить генерацию лидов и переработать скрипты квалификации"})
    if not actions:
        actions.append({"priority": "low", "text": "Провести ревизию воронки и статусов задач"})
    actions.sort(key=lambda a: {"high": 0, "normal": 1, "low": 2}.get(a["priority"], 2))
    return actions[:limit]

def _twin_simulate(self: BusinessTwin, scenario: dict) -> dict:
    stype = (scenario.get("type") or "").lower()
    if stype == "hire_salesperson":
        deals_per_month = int(scenario.get("deals_per_month", 10))
        avg_size = self.state["sales"]["avg_deal_size"] or 0
        conv = self.state["sales"]["conversion_rate_30d"] or 0
        add_rev = deals_per_month * avg_size * conv
        cost = float(scenario.get("monthly_salary", 100000))
        profit = add_rev - cost
        roi_months = (cost / profit) if profit > 0 else None
        return {
            "scenario": "Наём менеджера по продажам",
            "monthly_cost": round(cost, 2),
            "expected_additional_revenue": round(add_rev, 2),
            "roi_months": round(roi_months, 1) if roi_months else None,
            "recommendation": "Выгодно" if roi_months and roi_months < 6 else "Требует анализа"
        }
    if stype == "increase_prices":
        inc_pct = float(scenario.get("increase_percent", 10))
        churn_inc = float(scenario.get("expected_churn_increase", 5))
        current_mrr = self.state["finance"]["mrr"]
        customers = self.state["customer_success"]["active_customers"] or 1
        current_arpu = (current_mrr / max(1, customers))
        new_arpu = current_arpu * (1 + inc_pct / 100.0)
        lost = int(customers * (churn_inc / 100.0))
        remaining = max(0, customers - lost)
        new_mrr = remaining * new_arpu
        delta = new_mrr - current_mrr
        return {
            "scenario": f"Повышение цен на {inc_pct}%",
            "current_mrr": round(current_mrr, 2),
            "projected_mrr": round(new_mrr, 2),
            "mrr_change": round(delta, 2),
            "lost_customers": lost,
            "recommendation": "Выгодно" if delta > 0 else "Невыгодно"
        }
    if stype == "increase_marketing_budget":
        budget_inc_pct = float(scenario.get("budget_increase_percent", 20))
        base_conv = self.state["sales"]["conversion_rate_30d"] or 0.0
        pipeline = self.state["sales"]["pipeline_value"] or 0.0
        conv_gain = min(0.15, base_conv * (budget_inc_pct / 200.0))
        new_conv = min(1.0, base_conv + conv_gain)
        new_pipeline = pipeline * (1.0 + budget_inc_pct / 100.0)
        expected_30d = new_pipeline * new_conv * 0.4
        return {
            "scenario": f"Увеличение маркетингового бюджета на {budget_inc_pct}%",
            "old_conversion": round(base_conv, 3),
            "new_conversion": round(new_conv, 3),
            "old_pipeline": round(pipeline, 2),
            "new_pipeline": round(new_pipeline, 2),
            "expected_30d": round(expected_30d, 2),
            "insight": "Увеличение бюджета повышает и конверсию (за счет качества трафика) и pipeline."
        }
    return {"scenario": "unknown", "message": "Сценарий не поддерживается"}

# Bind methods
BusinessTwin.next_best_actions = _twin_nba  # type: ignore
BusinessTwin.simulate_scenario = _twin_simulate  # type: ignore

# ===== Proactive scanner: push insights if risk detected =====
def twin_proactive_scan(org_id: int):
    try:
        twin = BusinessTwin(org_id)
        health = twin.get_health_score()
        st = twin.state
        target = st["finance"]["target_month"]
        plan_ratio = (st["finance"]["mrr"] * 12.0) / max(1.0, float(target)) if target else 1.0
        if target and plan_ratio < 0.9:
            admins = query_db("SELECT id FROM users WHERE org_id=? AND role='admin' AND active=1", (org_id,)) or []
            for a in admins:
                sse_push(
                    int(a["id"]),
                    "twin.insight",
                    {
                        "id": uuid.uuid4().hex,
                        "kind": "proactive",
                        "title": "Риск недовыполнения плана продаж",
                        "message": f"Прогноз выполнения плана: {int(plan_ratio*100)}%. Узкое место: проверьте квалификацию и предложение.",
                        "severity": "warn",
                        "tags": ["plan", "sales"],
                        "ts": utc_now(),
                        "payload": {"health": health, "nba": twin.next_best_actions()}
                    }
                )
        if st["operations"]["overdue_tasks"] > 0 and st["operations"]["open_tasks"] > 10 and st["operations"]["team_utilization"] >= 0.9:
            admins = query_db("SELECT id FROM users WHERE org_id=? AND role='admin' AND active=1", (org_id,)) or []
            for a in admins:
                sse_push(
                    int(a["id"]),
                    "twin.insight",
                    {
                        "id": uuid.uuid4().hex,
                        "kind": "proactive",
                        "title": "Перегруз команды",
                        "message": "Высокая утилизация и много просрочек. Рекомендуется выделить время на устранение долга.",
                        "severity": "info",
                        "tags": ["ops", "overdue"],
                        "ts": utc_now(),
                        "payload": {"open_tasks": st["operations"]["open_tasks"], "overdue": st["operations"]["overdue_tasks"]}
                    }
                )
    except Exception as e:
        log("WARN", "twin_proactive_scan failed", error=str(e))

def _mv_refresh_dashboard_early():
    """
    EARLY (deprecated) variant of mv_dashboard refresh kept for back-compat.
    Final implementation overrides in _mv_refresh_dashboard().
    """
    try:
        _ensure_mv_tables()
        orgs = query_db("SELECT id FROM orgs", ()) or []
        for o in orgs:
            oid = int(o["id"])
            open_tasks = query_db(
                "SELECT COUNT(*) AS c FROM tasks WHERE org_id=? AND status NOT IN ('done','cancelled')",
                (oid,), one=True
            )
            open_deals = query_db(
                "SELECT COUNT(*) AS c FROM deals WHERE org_id=? AND status='open'",
                (oid,), one=True
            )
            kv = [("open_tasks", int((open_tasks or {}).get("c") or 0)),
                  ("open_deals", int((open_deals or {}).get("c") or 0))]
            for k, v in kv:
                if DIALECT == "postgres":
                    exec_db(
                        "INSERT INTO mv_dashboard (org_id, key, value_number, updated_at) VALUES (?, ?, ?, NOW()) "
                        "ON CONFLICT (org_id, key) DO UPDATE SET value_number=EXCLUDED.value_number, updated_at=EXCLUDED.updated_at",
                        (oid, k, float(v))
                    )
                else:
                    exec_db(
                        "INSERT OR REPLACE INTO mv_dashboard (org_id, key, value_number, updated_at) VALUES (?, ?, ?, ?)",
                        (oid, k, float(v), utc_now())
                    )
    except Exception as e:
        log("WARN", "mv_refresh_dashboard_early failed", error=str(e))

def _mv_refresh_dashboard():
    """
    Full refresh for mv_dashboard (used by maintenance_worker).
    Computes key rollups: open_tasks, overdue_tasks, open_deals, pipeline_value, mrr, arr.
    """
    try:
        _ensure_mv_tables()
        orgs = query_db("SELECT id FROM orgs", ()) or []
        now = utc_now()
        for o in orgs:
            oid = int(o["id"])

            # Metrics
            open_tasks = query_db(
                "SELECT COUNT(*) AS c FROM tasks WHERE org_id=? AND status NOT IN ('done','cancelled')",
                (oid,), one=True
            )
            overdue_tasks = query_db(
                "SELECT COUNT(*) AS c FROM tasks WHERE org_id=? AND status NOT IN ('done','cancelled') AND due_at IS NOT NULL AND due_at < ?",
                (oid, now), one=True
            )
            open_deals = query_db(
                "SELECT COUNT(*) AS c FROM deals WHERE org_id=? AND status='open'",
                (oid,), one=True
            )
            pipeline_val = query_db(
                "SELECT COALESCE(SUM(amount),0) AS s FROM deals WHERE org_id=? AND status='open'",
                (oid,), one=True
            )
            won30 = query_db(
                "SELECT COALESCE(SUM(amount),0) AS s FROM deals WHERE org_id=? AND status='won' AND won_at >= ?",
                (oid, (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")), one=True
            )
            mrr = float((won30 or {}).get("s") or 0.0) / 12.0
            arr = mrr * 12.0

            pairs = [
                ("open_tasks", float((open_tasks or {}).get("c") or 0)),
                ("overdue_tasks", float((overdue_tasks or {}).get("c") or 0)),
                ("open_deals", float((open_deals or {}).get("c") or 0)),
                ("pipeline_value", float((pipeline_val or {}).get("s") or 0.0)),
                ("mrr", float(mrr)),
                ("arr", float(arr)),
            ]

            for k, v in pairs:
                if DIALECT == "postgres":
                    exec_db(
                        "INSERT INTO mv_dashboard (org_id, key, value_number, updated_at) VALUES (?, ?, ?, NOW()) "
                        "ON CONFLICT (org_id, key) DO UPDATE SET value_number=EXCLUDED.value_number, updated_at=EXCLUDED.updated_at",
                        (oid, k, v)
                    )
                else:
                    exec_db(
                        "INSERT OR REPLACE INTO mv_dashboard (org_id, key, value_number, updated_at) VALUES (?, ?, ?, ?)",
                        (oid, k, v, now)
                    )
    except Exception as e:
        log("WARN", "mv_refresh_dashboard failed", error=str(e))

# ==================== END OF CORE PART 8/10 ====================
# ==================== CORE PART 9/10 ====================
# ===== BLOCK: API ROUTES =====
from werkzeug.security import generate_password_hash, check_password_hash

# --- Password helpers ---
def hash_password(password: str) -> str:
    return generate_password_hash(password, method="pbkdf2:sha256")

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False

# --- Storage helpers (Local/S3) ---
def _safe_local_storage_path(upload_dir: str, key: str) -> str:
    """
    Normalize path and prevent traversal/symlink escape. Allow subdirs like "<org>/<uuid>.ext".
    """
    base = os.path.abspath(upload_dir)
    safe_key = (key or "").replace("\\", "/").strip().lstrip("/")
    parts = [p for p in safe_key.split("/") if p not in ("", ".", "..")]
    if not parts:
        raise ValueError("Empty/unsafe key")
    safe_key = "/".join(parts)
    path = os.path.abspath(os.path.join(base, safe_key))
    # Ensure within base
    if not (path == base or path.startswith(base + os.sep)):
        raise ValueError("Path escape detected")
    # Symlink check
    if os.path.lexists(path) and os.path.islink(path):
        real_path = os.path.realpath(path)
        real_base = os.path.realpath(base)
        if not (real_path == real_base or real_path.startswith(real_base + os.sep)):
            raise ValueError("Symlink escape detected")
    return path

def _store_file_local(key: str, data: bytes) -> str:
    os.makedirs(LOCAL_UPLOAD_DIR, exist_ok=True)
    path = _safe_local_storage_path(LOCAL_UPLOAD_DIR, key)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return key

def _get_file_local(key: str) -> Optional[bytes]:
    try:
        path = _safe_local_storage_path(LOCAL_UPLOAD_DIR, key)
        with open(path, "rb") as f:
            return f.read()
    except (FileNotFoundError, ValueError):
        return None

def _store_file_s3(key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
    try:
        import boto3  # type: ignore
    except Exception:
        raise RuntimeError("boto3 not installed for S3 storage")
    S3_BUCKET = os.getenv("S3_BUCKET", "")
    S3_REGION = os.getenv("S3_REGION", "us-east-1")
    S3_ENDPOINT = os.getenv("S3_ENDPOINT", "")
    s3 = boto3.client("s3", region_name=S3_REGION, endpoint_url=S3_ENDPOINT or None)  # type: ignore
    try:
        s3.put_object(Bucket=S3_BUCKET, Key=key, Body=data, ContentType=content_type)
    except Exception as e:
        log("ERROR", "S3 upload failed", error=str(e))
        raise
    return key

def _get_file_s3(key: str) -> Optional[bytes]:
    try:
        import boto3  # type: ignore
    except Exception:
        return None
    S3_BUCKET = os.getenv("S3_BUCKET", "")
    S3_REGION = os.getenv("S3_REGION", "us-east-1")
    S3_ENDPOINT = os.getenv("S3_ENDPOINT", "")
    s3 = boto3.client("s3", region_name=S3_REGION, endpoint_url=S3_ENDPOINT or None)  # type: ignore
    try:
        r = s3.get_object(Bucket=S3_BUCKET, Key=key)
        return r["Body"].read()
    except Exception:
        return None

def detect_mime_from_bytes(data: bytes, filename: str = "") -> Optional[str]:
    try:
        import magic  # type: ignore
        return magic.from_buffer(data, mime=True)  # type: ignore
    except Exception:
        import mimetypes
        if filename:
            m, _ = mimetypes.guess_type(filename)
            return m
        return None

def is_allowed_upload_type(content_type: Optional[str]) -> bool:
    if not content_type:
        return False
    allowed = {
        "image/jpeg", "image/png", "image/webp", "image/gif",
        "application/pdf",
        "text/plain", "text/csv",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip", "application/x-zip-compressed",
        "application/json",
        "audio/mpeg", "audio/mp3"
    }
    return content_type in allowed

def store_file(org_id: int, filename: str, data: bytes, content_type: str, user_id: Optional[int] = None) -> dict:
    ext = os.path.splitext(filename)[1][:10]
    storage_key = f"{org_id}/{uuid.uuid4().hex}{ext}"
    if STORAGE_BACKEND == "s3":
        _ = _store_file_s3(storage_key, data, content_type)
    else:
        _ = _store_file_local(storage_key, data)
    file_id = exec_db(
        "INSERT INTO files (org_id, storage_key, name, content_type, size_bytes, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (org_id, storage_key, filename, content_type, len(data), user_id, utc_now())
    )
    return {
        "id": int(file_id or 0),
        "name": filename,
        "url": f"/api/files/{int(file_id or 0)}/download",
        "content_type": content_type,
        "size_bytes": len(data),
    }

def get_file_by_id(file_id: int) -> Optional[Tuple[bytes, str, str]]:
    meta = query_db("SELECT * FROM files WHERE id=?", (file_id,), one=True)
    if not meta:
        return None
    if STORAGE_BACKEND == "s3":
        data = _get_file_s3(meta["storage_key"])
    else:
        data = _get_file_local(meta["storage_key"])
    if data is None:
        return None
    return (data, meta["name"], meta.get("content_type") or "application/octet-stream")

# --- Avatar processing ---
def process_avatar(data: bytes, filename: str) -> Tuple[bytes, str, str]:
    try:
        from PIL import Image  # type: ignore
    except Exception:
        raise ValueError("Image processing unavailable")
    detected = detect_mime_from_bytes(data, filename) or "application/octet-stream"
    allowed = {"image/jpeg", "image/png", "image/webp"}
    if detected not in allowed:
        raise ValueError(f"Unsupported avatar type: {detected}")
    max_size = int(os.getenv("AVATAR_MAX_SIZE", str(5 * 1024 * 1024)))
    resize_to = (256, 256)
    if len(data) > max_size:
        raise ValueError(f"Avatar too large: {len(data)} bytes")
    try:
        img = Image.open(BytesIO(data))
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGB")
        try:
            resampling = Image.Resampling.LANCZOS  # type: ignore
        except Exception:
            resampling = Image.LANCZOS  # type: ignore
        img.thumbnail(resize_to, resampling)
        buf = BytesIO()
        ext = ".jpg"; ctype = "image/jpeg"
        if detected == "image/png":
            img.save(buf, format="PNG", optimize=True); ext = ".png"; ctype = "image/png"
        elif detected == "image/webp":
            img.save(buf, format="WEBP", quality=85); ext = ".webp"; ctype = "image/webp"
        else:
            img.save(buf, format="JPEG", quality=85, optimize=True)
        return (buf.getvalue(), ctype, ext)
    except Exception as e:
        log("ERROR", "Avatar processing failed", error=str(e))
        raise ValueError("Invalid image file")

# --- HTML sanitization ---
def _sanitize_html_with_protocols(html: str, allowed_protocols: List[str]) -> str:
    try:
        import bleach  # type: ignore
        from bleach.css_sanitizer import CSSSanitizer  # type: ignore
    except Exception:
        # fallback - naive strip tags (fixed regex)
        return re.sub(r"<[^>]+>", "", html or "")
    ALLOWED_HTML_TAGS = [
        "p", "br", "strong", "em", "u", "h1", "h2", "h3", "h4", "h5", "h6",
        "ul", "ol", "li", "a", "img", "table", "thead", "tbody", "tr", "th", "td",
        "div", "span", "hr", "blockquote", "code", "pre"
    ]
    ALLOWED_HTML_ATTRS = {
        "a": ["href", "title", "target", "rel"],
        "img": ["src", "alt", "width", "height"],
        "table": ["border", "cellpadding", "cellspacing"],
        "*": ["class"]
    }
    css_sanitizer = CSSSanitizer(allowed_css_properties=[
        "color", "background-color", "font-weight", "font-style", "text-decoration"
    ])
    cleaner = bleach.Cleaner(
        tags=ALLOWED_HTML_TAGS,
        attributes=ALLOWED_HTML_ATTRS,
        strip=True,
        css_sanitizer=css_sanitizer,
        protocols=allowed_protocols
    )
    return cleaner.clean(html or "")

def sanitize_html(html: str, allow_external_images: bool = True) -> str:
    protocols = ["http", "https", "data"] if allow_external_images else ["data"]
    cleaned = _sanitize_html_with_protocols(html, protocols)
    if not allow_external_images:
        cleaned = re.sub(r'<img[^>]+\ssrc=["\']https?://[^"\']+["\'][^>]*>', "", cleaned, flags=re.IGNORECASE)
    return cleaned

def sanitize_document_html(html: str) -> str:
    return sanitize_html(html, allow_external_images=False)

# --- Notification channels (+ helpers) ---
def _notify_telegram(chat_id: Optional[str], text: str) -> bool:
    if not chat_id or not os.getenv("TELEGRAM_BOT_TOKEN"):
        return False
    if _rq is None:
        return False
    try:
        url = f"https://api.telegram.org/bot{os.getenv('TELEGRAM_BOT_TOKEN')}/sendMessage"
        payload = {"chat_id": chat_id, "text": text[:4096]}
        r = _rq.post(url, json=payload, timeout=10)
        return r.status_code == 200
    except Exception as e:
        log("WARN", "Telegram send failed", error=str(e))
        return False

def _notify_whatsapp(phone: Optional[str], text: str) -> bool:
    token = os.getenv("WHATSAPP_TOKEN", "")
    phone_id = os.getenv("WHATSAPP_PHONE_ID", "")
    if not (phone and token and phone_id):
        return False
    if _rq is None:
        return False
    try:
        url = f"https://graph.facebook.com/v17.0/{phone_id}/messages"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {"messaging_product": "whatsapp", "to": phone, "type": "text", "text": {"body": text[:4000]}}
        r = _rq.post(url, headers=headers, json=payload, timeout=10)
        return r.status_code in (200, 201)
    except Exception as e:
        log("WARN", "WhatsApp send failed", error=str(e))
        return False

def notify_user_channels(user_id: int, message: str) -> dict:
    res = {"sse": False, "telegram": False, "whatsapp": False}
    try:
        u = query_db("SELECT id, org_id, telegram_chat_id, whatsapp_phone FROM users WHERE id=?", (user_id,), one=True)
        if not u:
            return res
        try:
            sse_push(int(user_id), "notify.message", {"message": message})
            res["sse"] = True
        except Exception:
            pass
        if u.get("telegram_chat_id"):
            res["telegram"] = _notify_telegram(u["telegram_chat_id"], message)
        if u.get("whatsapp_phone"):
            res["whatsapp"] = _notify_whatsapp(normalize_phone(u["whatsapp_phone"]), message)
    except Exception as e:
        log("WARN", "notify_user_channels failed", error=str(e))
    return res

# Тест уведомления (для страницы Settings)
@app.route("/ui/notify/test", methods=["POST"])
@_login_required
@_csrf_protect
def ui_notify_test():
    data = request.get_json() or {}
    title = (data.get("title") or "Тест уведомления")
    body = (data.get("body") or "Проверка центра уведомлений")
    kind = (data.get("kind") or "info")
    try:
        sse_push(int(g.user["id"]), "notify.center", {"title": title, "body": body, "kind": kind, "ts": utc_now()})
        notify_user_channels(int(g.user["id"]), f"{title}: {body}")
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

# --- Idempotency helper ---
def _idempotency_guard(key: str, ttl: int = 60) -> bool:
    """
    Returns True if operation is allowed (not seen), False if duplicate.
    """
    ik = g.get("idempotency_key", "")
    if not ik:
        return True
    full = f"idemp:{key}:{ik}"
    r = get_redis()
    if r:
        try:
            added = _redis_cb.call(r.set, full, "1", ex=ttl, nx=True)
            return bool(added)
        except Exception:
            pass
    if _global_cache.get(full):
        return False
    _global_cache.set(full, True, ttl=ttl)
    return True

# --- AUTH & SESSION ROUTES ---
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_DURATION = int(os.getenv("LOCKOUT_DURATION", "900"))  # 15 min

def _login_attempts_key(username: str) -> str:
    return f"login_attempts:{username or ''}"

@app.route("/login", methods=["GET", "POST"])
@_rate_limit_ip("login", per_min=LOGIN_RATE_LIMIT_PER_MIN)
def login():
    if request.method == "GET":
        if _get_current_user():
            return redirect(url_for("index"))
        tmpl = """
        <form method="post" style="max-width:360px;margin:40px auto;font-family:sans-serif;">
        <h3>Вход</h3>
        <input name="org_slug" placeholder="org" autofocus class="input" style="width:100%;padding:8px;margin:6px 0;">
        <input name="username" placeholder="user" class="input" style="width:100%;padding:8px;margin:6px 0;">
        <input name="password" type="password" placeholder="password" class="input" style="width:100%;padding:8px;margin:6px 0;">
        <input name="totp" placeholder="2FA (если включено)" class="input" style="width:100%;padding:8px;margin:6px 0;">
        <button type="submit" class="button" style="padding:8px 12px;">Login</button>
        </form>
        """
        return Response(tmpl, 200)

    # POST
    org_slug = (request.form.get("org_slug") or "").strip().lower()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    totp_token = (request.form.get("totp") or "").strip()
    if not org_slug or not username or not password:
        return Response("Missing credentials", 400)

    # Account lockout
    r = get_redis()
    if r:
        try:
            attempts_key = _login_attempts_key(username)
            attempts = int(_redis_cb.call(r.get, attempts_key) or 0)
            if attempts >= MAX_LOGIN_ATTEMPTS:
                ttl = int(_redis_cb.call(r.ttl, attempts_key) or LOCKOUT_DURATION)
                return Response(f"Аккаунт заблокирован. Попробуйте через {max(1, ttl//60)} минут", 429)
        except Exception:
            pass

    org = query_db("SELECT id FROM orgs WHERE slug=?", (org_slug,), one=True)
    if not org:
        return Response("Org not found", 404)
    user = query_db("SELECT * FROM users WHERE org_id=? AND username=? AND active=1", (org["id"], username), one=True)
    if not user or not verify_password(password, user["password_hash"]):
        try:
            add_audit(int(org["id"]), None, "auth.login_failed", "user", None, {"username": username})  # type: ignore
        except Exception:
            pass
        # increment attempts
        if r:
            try:
                _redis_cb.call(r.incr, _login_attempts_key(username))
                _redis_cb.call(r.expire, _login_attempts_key(username), LOCKOUT_DURATION)
            except Exception:
                pass
        return Response("Invalid credentials", 401)

    # success -> reset attempts
    if r:
        try:
            _redis_cb.call(r.delete, _login_attempts_key(username))
        except Exception:
            pass

    is_admin = (user.get("role") or "") == "admin"
    if user.get("totp_enabled") and not (is_admin and os.getenv("ADMIN_2FA_BYPASS", "false").lower() == "true"):
        try:
            import pyotp  # type: ignore
            totp = pyotp.TOTP(user.get("totp_secret") or "")
            if not (totp_token and totp.verify(totp_token, valid_window=1)):
                try:
                    add_audit(user["org_id"], user["id"], "auth.login_2fa_failed", "user", user["id"], {})  # type: ignore
                except Exception:
                    pass
                return Response("2FA required/invalid", 401)
        except Exception:
            return Response("2FA module unavailable", 500)

    # Session fixation mitigation
    try:
        session.clear()
        session["user_id"] = user["id"]
        session["csrf_token"] = secrets.token_hex(32)
        session["issued_at"] = utc_now()
        session["role"] = user.get("role", "agent")
        session["org_id"] = user.get("org_id")
        session["username"] = user.get("username")
        session.permanent = True
        exec_db("UPDATE users SET last_login_at=? WHERE id=?", (utc_now(), user["id"]))
        add_audit(user["org_id"], user["id"], "auth.login", "user", user["id"], {})  # type: ignore
    except Exception:
        pass
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
@_login_required
@_csrf_protect
def logout():
    try:
        add_audit(g.user["org_id"], g.user["id"], "auth.logout", "user", g.user["id"], {})  # type: ignore
        session.clear()
    except Exception:
        pass
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if ENV == "production":
        return redirect(url_for("login"))
    if request.method == "GET":
        tmpl = """
        <form method="post" style="max-width:360px;margin:40px auto;font-family:sans-serif;">
        <h3>Регистрация</h3>
        <input name="org_slug" placeholder="org" class="input" style="width:100%;padding:8px;margin:6px 0;">
        <input name="username" placeholder="user" class="input" style="width:100%;padding:8px;margin:6px 0;">
        <input name="email" placeholder="email" class="input" style="width:100%;padding:8px;margin:6px 0;">
        <input name="password" type="password" placeholder="password (>=12)" class="input" style="width:100%;padding:8px;margin:6px 0;">
        <button type="submit" class="button" style="padding:8px 12px;">Register</button>
        </form>
        """
        return Response(tmpl, 200)
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""
    org_slug = (request.form.get("org_slug") or "").strip().lower()
    if not username or not password or not org_slug:
        return Response("Fill required fields", 400)
    if len(password) < 12:
        return Response("Weak password", 400)
    org = query_db("SELECT id FROM orgs WHERE slug=?", (org_slug,), one=True)
    if not org:
        org_id = exec_db("INSERT INTO orgs (slug, name, created_at) VALUES (?, ?, ?)", (org_slug, org_slug.title(), utc_now()))
    else:
        org_id = org["id"]
    existing = query_db("SELECT id FROM users WHERE org_id=? AND username=?", (org_id, username), one=True)
    if existing:
        return Response("User exists", 400)
    user_id = exec_db(
        "INSERT INTO users (org_id, username, email, password_hash, role, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (org_id, username, email, hash_password(password), "admin" if db_table_count("users", "org_id", org_id) == 0 else "agent", 1, utc_now())
    )
    session.clear()
    session["user_id"] = int(user_id or 0)
    session["csrf_token"] = secrets.token_hex(32)
    session["issued_at"] = utc_now()
    session["role"] = "admin"
    session["org_id"] = int(org_id or 0)
    session["username"] = username
    add_audit(int(org_id), int(user_id or 0), "auth.register", "user", int(user_id or 0), {})  # type: ignore
    return redirect(url_for("index"))

# --- Profile & tokens/system info ---
@app.route("/api/profile", methods=["GET"])
@_login_required
def api_profile():
    user = g.user
    org = query_db("SELECT * FROM orgs WHERE id=?", (user["org_id"],), one=True)
    return jsonify(ok=True, user={
        "id": user["id"], "username": user["username"], "email": user.get("email"), "role": user.get("role"),
        "first_name": user.get("first_name"), "last_name": user.get("last_name"), "phone": user.get("phone"),
        "avatar_url": user.get("avatar_url"), "timezone": user.get("timezone"), "locale": user.get("locale"),
        "theme": user.get("theme", "light"),
        "totp_enabled": bool(user.get("totp_enabled")), "department_id": user.get("department_id"),
        "job_title_id": user.get("job_title_id"), "telegram_chat_id": user.get("telegram_chat_id"),
        "whatsapp_phone": user.get("whatsapp_phone"),
    }, org={"id": org["id"], "slug": org["slug"], "name": org["name"]} if org else None)

@app.route("/api/profile", methods=["PATCH"])
@_login_required
@_csrf_protect
def api_profile_update():
    user = g.user
    data = request.get_json() or {}
    allowed = {"first_name", "last_name", "email", "phone", "timezone", "locale", "theme"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify(ok=False, error="No valid fields"), 400
    set_clause, params = _safe_update_clause(set(allowed), updates)
    if not set_clause:
        return jsonify(ok=False, error="No valid fields"), 400
    params.append(user["id"])
    exec_db(f"UPDATE users SET {set_clause} WHERE id=?", tuple(params))
    try:
        add_audit(user["org_id"], user["id"], "profile.updated", "user", user["id"], updates)  # type: ignore
    except Exception:
        pass
    return jsonify(ok=True)

@app.route("/api/profile/password", methods=["POST"])
@_login_required
@_csrf_protect
def api_profile_password():
    user = g.user
    data = request.get_json() or {}
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    ok, err = validate_password_strength(new_password)
    if not ok:
        return jsonify(ok=False, error=err), 400
    urow = query_db("SELECT password_hash FROM users WHERE id=?", (user["id"],), one=True)
    if not urow or not verify_password(current_password, urow["password_hash"]):
        return jsonify(ok=False, error="Current password incorrect"), 400
    exec_db("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_password), user["id"]))
    try:
        invalidate_user_sessions(user["id"])
    except Exception:
        pass
    try:
        add_audit(user["org_id"], user["id"], "profile.password_changed", "user", user["id"], {})  # type: ignore
    except Exception:
        pass
    return jsonify(ok=True)

@app.route("/api/profile/avatar", methods=["POST"])
@_login_required
@_csrf_protect
@_rate_limit("avatar_upload", per_min=5)
def api_profile_avatar():
    user = g.user
    if "file" not in request.files:
        return jsonify(ok=False, error="No file"), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify(ok=False, error="Empty filename"), 400
    try:
        raw = f.read()
        processed, content_type, ext = process_avatar(raw, f.filename)
        filename = f"avatar{user['id']}{uuid.uuid4().hex[:8]}{ext}"
        info = store_file(user["org_id"], filename, processed, content_type, user["id"])
        exec_db("UPDATE users SET avatar_url=? WHERE id=?", (info["url"], user["id"]))
        try:
            add_audit(user["org_id"], user["id"], "profile.avatar_updated", "user", user["id"], {"url": info["url"]})  # type: ignore
        except Exception:
            pass
        return jsonify(ok=True, url=info["url"])
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400
    except Exception as e:
        log("ERROR", "Avatar upload failed", error=str(e))
        return jsonify(ok=False, error="Upload failed"), 500

@app.route("/api/files/<int:file_id>/download", methods=["GET"])
@_auth_or_token
def api_file_download(file_id: int):
    user = g.user
    meta = query_db("SELECT * FROM files WHERE id=? AND org_id=?", (file_id, user["org_id"]), one=True)
    if not meta:
        return jsonify(ok=False, error="File not found"), 404
    res = get_file_by_id(file_id)
    if not res:
        return jsonify(ok=False, error="File data not found"), 404
    data, name_f, content_type = res
    etag = hashlib.sha256(data).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return Response(status=304)
    resp = send_file(BytesIO(data), mimetype=content_type or "application/octet-stream", as_attachment=True, download_name=name_f)
    resp.headers["ETag"] = etag
    return resp

@app.route("/api/tokens/list", methods=["GET"])
@_login_required
@_require_role("admin")
def api_tokens_list():
    user = g.user
    tokens = query_db("SELECT id, name, user_id, scopes, active, expires_at, created_at, last_used_at FROM api_tokens WHERE org_id=?", (user["org_id"],))
    return jsonify(ok=True, items=[dict(t) for t in tokens or []])

@app.route("/api/tokens/create", methods=["POST"])
@_login_required
@_csrf_protect
@_require_role("admin")
def api_tokens_create():
    user = g.user
    data = request.get_json() or {}
    name = data.get("name", "API Token")
    user_id = data.get("user_id")
    scopes = data.get("scopes", [])
    expires_at = data.get("expires_at")
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    exec_db(
        "INSERT INTO api_tokens (org_id, user_id, name, token_hash, scopes, active, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], user_id, name, token_hash, ",".join(scopes) if isinstance(scopes, list) else str(scopes),
         1, ensure_iso_datetime(expires_at) if expires_at else None, utc_now())
    )
    try:
        add_audit(user["org_id"], user["id"], "token.created", "token", None, {"name": name})  # type: ignore
    except Exception:
        pass
    return jsonify(ok=True, token=token)

@app.route("/api/tokens/toggle", methods=["POST"])
@_login_required
@_csrf_protect
@_require_role("admin")
def api_tokens_toggle():
    user = g.user
    data = request.get_json() or {}
    token_id = data.get("id")
    if not token_id:
        return jsonify(ok=False, error="Token ID required"), 400
    t = query_db("SELECT active FROM api_tokens WHERE id=? AND org_id=?", (token_id, user["org_id"]), one=True)
    if not t:
        return jsonify(ok=False, error="Token not found"), 404
    new_active = 0 if t["active"] else 1
    exec_db("UPDATE api_tokens SET active=? WHERE id=?", (new_active, token_id))
    try:
        add_audit(user["org_id"], user["id"], "token.toggled", "token", int(token_id), {"active": bool(new_active)})  # type: ignore
    except Exception:
        pass
    return jsonify(ok=True, active=bool(new_active))

@app.route("/api/system/info", methods=["GET"])
@_login_required
@_require_role("admin")
def api_system_info():
    info = {
        "version": int(os.getenv("SCHEMA_VERSION", "52020")),
        "debug": DEBUG,
        "env": ENV,
        "storage_backend": STORAGE_BACKEND,
        "ai_provider": AI_PROVIDER,
        "redis_available": bool(get_redis()),
        "sse_enabled": SSE_ENABLED,
        "rate_limit_enabled": RATE_LIMIT_ENABLED,
        "cache_enabled": CACHE_ENABLED,
        "dialect": DIALECT
    }
    return jsonify(ok=True, **info)

@app.route("/manifest.json")
def pwa_manifest():
    manifest = {
        "name": "AI-CRM",
        "short_name": "AI-CRM",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#2563eb",
        "icons": []
    }
    return jsonify(manifest)

@app.route("/sw.js")
def pwa_sw():
    js = """
self.addEventListener('install', (e)=>{ self.skipWaiting(); });
self.addEventListener('activate', (e)=>{ e.waitUntil(clients.claim()); });
self.addEventListener('fetch', (e)=>{ /* pass-through */ });
""".strip()
    return Response(js, mimetype="application/javascript")

# --- APPROVAL ROUTE (secure: GET=confirm, POST=apply) ---
@app.route("/approve/<path:token>", methods=["GET"])
def approve_token_page(token: str):
    # Parse token; do NOT mutate state on GET
    try:
        jti, secret = token.split(".", 1)
    except Exception:
        return Response("Invalid token", 400)
    row = query_db(
        "SELECT * FROM approval_tokens WHERE jti=? AND token_hash=? AND revoked=0 AND used=0 AND expires_at >= ?",
        (jti, hashlib.sha256(token.encode("utf-8")).hexdigest(), utc_now()),
        one=True
    )
    if not row:
        return Response("Token invalid/expired", 400)
    # Render confirm page with POST form (CSRF-protected via session token)
    tmpl = f"""
<html><head><meta charset="utf-8"><title>Подтверждение</title></head>
<body style="font-family:sans-serif;max-width:520px;margin:40px auto;">
<h3>Подтверждение действия</h3>
<p>Вы собираетесь подтвердить действие для: {row.get('entity_type')} #{row.get('entity_id')}</p>
<form method="post">
<input type="hidden" name="csrf_token" value="{{{{ session.get('csrf_token','') }}}}">
<button type="submit" style="padding:8px 12px;">Подтвердить</button>
</form>
</body></html>
"""
    return Response(render_template_string(tmpl), 200)

@app.route("/approve/<path:token>", methods=["POST"])
@_csrf_protect
def approve_token_apply(token: str):
    try:
        jti, secret = token.split(".", 1)
    except Exception:
        return Response("Invalid token", 400)
    th = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = query_db("SELECT * FROM approval_tokens WHERE jti=? AND token_hash=? AND revoked=0 AND used=0 AND expires_at >= ?",
                   (jti, th, utc_now()), one=True)
    if not row:
        return Response("Token invalid/expired", 400)
    exec_db("UPDATE approval_tokens SET used=1 WHERE jti=?", (jti,))
    return Response("Approved", 200)
# ===== END OF CORE PART 9/10 (часть 1/2) =====
# ==================== CORE PART 9/10 (часть 2/2) ====================

# --- COMPANIES LIST (added to match OpenAPI) ---
@app.route("/api/companies/list", methods=["GET"])
@_login_required
def api_companies_list():
    user = g.user
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(max(1, int(request.args.get("per_page", 50))), 200)
    offset = (page - 1) * per_page
    q = (request.args.get("q") or "").strip()
    where = ["org_id=?"]
    params: List[Any] = [user["org_id"]]
    if q:
        like = f"%{q}%"
        where.append("(name LIKE ? OR inn LIKE ? OR email LIKE ? OR phone LIKE ? OR phone_norm LIKE ?)")
        params.extend([like, like, like, like, like])
    wc = " AND ".join(where)
    total_row = query_db(f"SELECT COUNT(*) AS c FROM companies WHERE {wc}", tuple(params), one=True)
    items = query_db(
        f"""SELECT id, name, inn, phone, phone_norm, email, address, notes, industry, score, created_at, updated_at
FROM companies WHERE {wc} ORDER BY (updated_at IS NULL), updated_at DESC, id DESC LIMIT ? OFFSET ?""",
        (*params, per_page, offset)
    ) or []
    return jsonify(ok=True, items=items, page=page, per_page=per_page, total=int((total_row or {}).get("c") or 0))

# --- TASKS API ---
@app.route("/api/tasks/list", methods=["GET"])
@_login_required
def api_tasks_list():
    user = g.user
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(max(1, int(request.args.get("per_page", 50))), 200)
    offset = (page - 1) * per_page
    f = (request.args.get("f") or "").strip()  # open|today|overdue|done
    q = (request.args.get("q") or "").strip()
    assignee_id = request.args.get("assignee_id")
    status = request.args.get("status")
    department_id = request.args.get("department_id")
    where, params = ["t.org_id=?"], [user["org_id"]]
    if f == "done": where.append("t.status='done'")
    elif f == "overdue": where.append("t.status NOT IN ('done','cancelled') AND t.due_at IS NOT NULL AND t.due_at < ?"); params.append(utc_now())
    elif f == "today": where.append("t.status NOT IN ('done','cancelled') AND date(t.due_at)=date(?)"); params.append(utc_now())
    else: where.append("t.status NOT IN ('done','cancelled')")
    if q:
        like = f"%{q}%"; where.append("(t.title LIKE ? OR COALESCE(t.description,'') LIKE ?)"); params.extend([like, like])
    if assignee_id: where.append("t.assignee_id=?"); params.append(int(assignee_id))
    if status: where.append("t.status=?"); params.append(status)
    if department_id: where.append("t.department_id=?"); params.append(int(department_id))
    wc = " AND ".join(where)
    total_row = query_db(f"SELECT COUNT(*) AS c FROM tasks t WHERE {wc}", tuple(params), one=True)
    items = query_db(
        f"""SELECT t.*, u.username AS assignee_name, c.name AS company_name, d.name AS department_name
FROM tasks t
LEFT JOIN users u ON t.assignee_id=u.id
LEFT JOIN companies c ON t.company_id=c.id
LEFT JOIN departments d ON t.department_id=d.id
WHERE {wc} ORDER BY t.created_at DESC LIMIT ? OFFSET ?""",
        (*params, per_page, offset)
    ) or []
    for it in items:
        it["checklist_percent"] = get_task_checklist_progress(it["id"])
    return jsonify(ok=True, items=items, page=page, per_page=per_page, total=int((total_row or {}).get("c") or 0))

@app.route("/api/task/create", methods=["POST"])
@_login_required
@_csrf_protect
def api_task_create():
    user = g.user
    data = request.get_json() or {}
    # идемпотентность (по заголовку Idempotency-Key)
    if not _idempotency_guard(f"task_create:{user['org_id']}"):
        return jsonify(ok=True, duplicated=True)
    try:
        tid = create_task(user["org_id"], data.get("title",""), description=data.get("description",""),
                          assignee_id=data.get("assignee_id"), due_at=data.get("due_at"),
                          department_id=data.get("department_id"), priority=data.get("priority","normal"),
                          company_id=data.get("company_id"), contact_id=data.get("contact_id"))
        return jsonify(ok=True, id=int(tid or 0))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route("/api/task/update", methods=["POST"])
@_login_required
@_csrf_protect
def api_task_update():
    user = g.user
    data = request.get_json() or {}
    tid = int(data.get("id") or 0)
    if not tid: return jsonify(ok=False, error="id required"), 400
    updates = {k:v for k,v in data.items() if k!="id"}
    ok = update_task(tid, user["org_id"], updates)
    return jsonify(ok=ok) if ok else (jsonify(ok=False, error="update_failed"), 400)

@app.route("/api/task/toggle", methods=["POST"])
@_login_required
@_csrf_protect
def api_task_toggle():
    user = g.user
    tid = int((request.get_json() or {}).get("id") or 0)
    if not tid: return jsonify(ok=False, error="id required"), 400
    status = toggle_task_status(tid, user["org_id"])
    return jsonify(ok=True, status=status)

@app.route("/api/task/checklist", methods=["POST"])
@_login_required
@_csrf_protect
def api_task_checklist():
    data = request.get_json() or {}
    task_id = int(data.get("task_id") or 0)
    if not task_id: return jsonify(ok=False, error="task_id required"), 400
    update_task_checklist(task_id, data.get("items") or [])
    return jsonify(ok=True)

@app.route("/api/task/comment", methods=["POST"])
@_login_required
@_csrf_protect
def api_task_comment():
    user = g.user
    data = request.get_json() or {}
    tid = int(data.get("task_id") or 0)
    if not tid: return jsonify(ok=False, error="task_id required"), 400
    cid = add_task_comment(tid, user["id"], data.get("body",""), attachments=data.get("attachments") or [])
    return jsonify(ok=True, comment_id=int(cid or 0))

@app.route("/api/task/comment/upload", methods=["POST"])
@_login_required
@_csrf_protect
def api_task_comment_upload():
    user = g.user
    if "file" not in request.files: return jsonify(ok=False, error="No file"), 400
    f = request.files["file"]; raw=f.read()
    ctype = detect_mime_from_bytes(raw, f.filename) or "application/octet-stream"
    if not is_allowed_upload_type(ctype): return jsonify(ok=False, error="File type not allowed"), 400
    info = store_file(user["org_id"], secure_filename(f.filename), raw, ctype, user["id"])
    return jsonify(ok=True, file=info)

# --- API ROUTES - CALENDAR ---
@app.route('/api/calendar/events', methods=['GET'])
@_login_required
def api_calendar_list():
    user = g.user
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    view = request.args.get("view", "team")
    event_types = request.args.get("event_types", "")
    filters = {"start": start, "end": end, "view": view}
    if event_types:
        filters["event_types"] = event_types
    try:
        items = CalendarService.get_events(user["org_id"], user["id"], filters)
        return jsonify(ok=True, events=items, total=len(items))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route('/api/calendar/events', methods=['POST'])
@_login_required
@_csrf_protect
def api_calendar_create():
    user = g.user
    data = request.get_json() or {}
    if "organizer_id" not in data:
        data["organizer_id"] = user["id"]
    try:
        # Conflicts preview (optional)
        participants = [int(x) for x in (data.get("participants") or []) if x]
        conflicts = []
        for uid in participants:
            conflicts.extend(CalendarService.check_conflicts(uid, data.get("start_time", ""), data.get("end_time", "")))
        res = CalendarService.create_event(user["org_id"], data, user["id"])
        res["conflicts"] = conflicts
        return jsonify(ok=True, **res), 201
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route('/api/calendar/events/<int:event_id>', methods=['GET'])
@_login_required
def api_calendar_get(event_id: int):
    user = g.user
    ev = query_db("SELECT * FROM calendar_events WHERE id=? AND org_id=?", (event_id, user["org_id"]), one=True)
    if not ev:
        return jsonify(ok=False, error="not_found"), 404
    parts = query_db("SELECT user_id, response_status FROM event_participants WHERE event_id=?", (event_id,)) or []
    hist = query_db("SELECT * FROM activity_timeline WHERE org_id=? AND entity_type='calendar_event' AND entity_id=? ORDER BY created_at DESC LIMIT 100", (user["org_id"], event_id)) or []
    return jsonify(ok=True, event=ev, participants=parts, history=hist)

@app.route('/api/calendar/events/<int:event_id>', methods=['PUT'])
@_login_required
@_csrf_protect
def api_calendar_update(event_id: int):
    user = g.user
    data = request.get_json() or {}
    update_mode = request.args.get("update_mode", "single")
    try:
        res = CalendarService.update_event(event_id, data, user["id"], update_mode=update_mode)
        return jsonify(ok=True, **res)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route('/api/calendar/events/<int:event_id>', methods=['DELETE'])
@_login_required
@_csrf_protect
def api_calendar_delete(event_id: int):
    user = g.user
    delete_mode = request.args.get("delete_mode", "single")
    ok = CalendarService.delete_event(event_id, user["id"], delete_mode=delete_mode)
    if not ok:
        return jsonify(ok=False, error="delete_failed"), 400
    return jsonify(ok=True)

@app.route('/api/calendar/events/<int:event_id>/respond', methods=['POST'])
@_login_required
@_csrf_protect
def api_calendar_respond(event_id: int):
    user = g.user
    data = request.get_json() or {}
    try:
        ok = CalendarService.respond_to_event(event_id, user["id"], data.get("response", ""), data.get("comment"))
        return jsonify(ok=ok)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route('/api/calendar/conflicts', methods=['POST'])
@_login_required
@_csrf_protect
def api_calendar_check_conflicts():
    data = request.get_json() or {}
    participants = [int(x) for x in (data.get("participants") or []) if x]
    start_time = data.get("start_time", "")
    end_time = data.get("end_time", "")
    exclude_event_id = data.get("exclude_event_id")
    conflicts = []
    for uid in participants:
        conflicts.extend(CalendarService.check_conflicts(uid, start_time, end_time, exclude_event_id=exclude_event_id))
    return jsonify(ok=True, has_conflicts=bool(conflicts), conflicts=conflicts)

@app.route('/api/calendar/suggest-slots', methods=['POST'])
@_login_required
@_csrf_protect
def api_calendar_suggest_slots():
    data = request.get_json() or {}
    participants = [int(x) for x in (data.get("participants") or []) if x]
    duration_minutes = int(data.get("duration_minutes") or 60)
    start_date = data.get("start_date") or ""
    end_date = data.get("end_date") or ""
    try:
        suggestions = CalendarService.suggest_time_slots(participants, duration_minutes, start_date, end_date)
        return jsonify(ok=True, suggestions=suggestions)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route('/api/calendar/events/<int:event_id>/ics', methods=['GET'])
@_login_required
def api_calendar_export_ics(event_id: int):
    try:
        ics = CalendarService.generate_ics(event_id)
        return Response(ics, mimetype="text/calendar",
                        headers={"Content-Disposition": f'attachment; filename="event-{event_id}.ics"'})
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route('/api/calendar/views', methods=['GET', 'PUT'])
@_login_required
@_csrf_protect
def api_calendar_views():
    user = g.user
    if request.method == "GET":
        row = query_db("SELECT * FROM calendar_views WHERE user_id=?", (user["id"],), one=True)
        return jsonify(ok=True, view=row or {})
    # PUT
    data = request.get_json() or {}
    allowed = {
        "view_type", "default_duration", "work_hours_start", "work_hours_end",
        "work_days", "visible_calendars", "visible_event_types", "week_starts_on", "time_format"
    }
    updates = {k: v for k, v in data.items() if k in allowed}
    row = query_db("SELECT 1 AS x FROM calendar_views WHERE user_id=?", (user["id"],), one=True)
    if row:
        set_clause, params = _safe_update_clause(set(updates.keys()), updates)
        if set_clause:
            set_clause = f"{set_clause}, updated_at=?"
            params.append(utc_now())
            params.append(user["id"])
            exec_db_affect(f"UPDATE calendar_views SET {set_clause} WHERE user_id=?", tuple(params))
    else:
        exec_db("INSERT INTO calendar_views (user_id, updated_at) VALUES (?, ?)", (user["id"], utc_now()))
        if updates:
            set_clause, params = _safe_update_clause(set(updates.keys()), updates)
            set_clause = f"{set_clause}, updated_at=?"
            params.append(utc_now())
            params.append(user["id"])
            exec_db_affect(f"UPDATE calendar_views SET {set_clause} WHERE user_id=?", tuple(params))
    return jsonify(ok=True)

# --- EDO SIGNATURES (DIADOC/SBIS/ASTRAL) ---
def _edo_call(provider: str, endpoint: str, payload: dict, timeout: int = 10) -> dict:
    """
    Generic EDO call wrapper (stubs). Requires provider-specific ENV configuration.
    """
    if _rq is None:
        return {"ok": False, "error": "HTTP client unavailable"}
    try:
        if provider == "diadoc":
            base = os.getenv("DIADOC_API", "")
            token = os.getenv("DIADOC_TOKEN", "")
            if not (base and token):
                return {"ok": False, "error": "Diadoc not configured"}
            r = _rq.post(f"{base.rstrip('/')}/{endpoint.lstrip('/')}", json=payload,
                         headers={"Authorization": f"DiadocAuth ddauth_api_client_id={token}"}, timeout=timeout)
        elif provider == "sbis":
            base = os.getenv("SBIS_API", "")
            token = os.getenv("SBIS_TOKEN", "")
            if not (base and token):
                return {"ok": False, "error": "SBIS not configured"}
            r = _rq.post(f"{base.rstrip('/')}/{endpoint.lstrip('/')}", json=payload,
                         headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        elif provider == "astral":
            base = os.getenv("ASTRAL_API", "")
            token = os.getenv("ASTRAL_TOKEN", "")
            if not (base and token):
                return {"ok": False, "error": "Astral not configured"}
            r = _rq.post(f"{base.rstrip('/')}/{endpoint.lstrip('/')}", json=payload,
                         headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        else:
            return {"ok": False, "error": "Unknown provider"}
        if r.status_code not in (200, 201, 202):
            return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return {"ok": True, "data": r.json() if r.headers.get("Content-Type", "").startswith("application/json") else r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.route("/api/edo/sign", methods=["POST"])
@_login_required
@_csrf_protect
def api_edo_sign():
    user = g.user
    data = request.get_json() or {}
    provider = (data.get("provider") or "").lower()
    document_id = int(data.get("document_id") or 0)
    if not (provider and document_id):
        return jsonify(ok=False, error="provider and document_id required"), 400
    doc = query_db("SELECT * FROM documents WHERE id=? AND org_id=?", (document_id, user["org_id"]), one=True)
    if not doc:
        return jsonify(ok=False, error="document not found"), 404
    payload = data.get("payload") or {"title": doc.get("title")}
    res = _edo_call(provider, "sign", payload)
    if res.get("ok"):
        try:
            add_audit(user["org_id"], user["id"], "document.sign_requested", "document", document_id, {"provider": provider})  # type: ignore
        except Exception:
            pass
    return jsonify(res)

@app.route("/api/edo/status", methods=["GET"])
@_login_required
def api_edo_status():
    user = g.user
    provider = (request.args.get("provider") or "").lower()
    document_id = int(request.args.get("document_id") or 0)
    if not (provider and document_id):
        return jsonify(ok=False, error="provider and document_id required"), 400
    doc = query_db("SELECT * FROM documents WHERE id=? AND org_id=?", (document_id, user["org_id"]), one=True)
    if not doc:
        return jsonify(ok=False, error="document not found"), 404
    res = _edo_call(provider, f"status/{document_id}", {})
    return jsonify(res)

# ==================== END OF CORE PART 9/10 ====================
# ==================== CORE PART 10/10 (1/3-A) ====================
# ===== BLOCK: API ROUTES — INBOX, LOOKUPS, THREADS (PART A) =====

# --- Idempotency guard (Redis NX+EX with L1 fallback), uses Idempotency-Key header if present ---
def _idempotency_guard(scope_key: str, ttl: int = 60) -> bool:
    """
    Returns True if operation is allowed (first time), False if duplicate within TTL.
    Priority: Idempotency-Key header (set earlier in g.idempotency_key) → Redis NX+EX → L1 TTL cache.
    Without header: coarse guard by scope+client_ip for a short window.
    """
    try:
        idem = (getattr(g, "idempotency_key", "") or "").strip()
        if idem:
            key = f"idem:{scope_key}:{idem}"
            r = get_redis()
            if r:
                try:
                    ok = bool(_redis_cb.call(r.set, key, "1", nx=True, ex=int(ttl)))
                    if ok:
                        return True
                    return False
                except Exception:
                    pass
            # Fallback to L1
            if _global_cache.get(key):
                return False
            _global_cache.set(key, True, ttl)
            return True
        # No Idempotency-Key: coarse guard by IP for a short time
        ip = get_client_ip()
        key = f"idem:{scope_key}:{ip}"
        if _global_cache.get(key):
            return False
        _global_cache.set(key, True, min(5, int(ttl)))
        return True
    except Exception:
        # Fail-open to avoid blocking in case of guard failure
        return True

# --- Inbox helper logic used by agents/APIs ---
def create_inbox_thread(org_id: int, channel_id: Optional[int], subject: str,
                        company_id: Optional[int] = None, contact_id: Optional[int] = None) -> int:
    subject = (subject or "").strip()
    with db_transaction():
        tid = exec_db(
            "INSERT INTO inbox_threads (org_id, channel_id, subject, status, priority, company_id, contact_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, channel_id, subject, "open", "normal", company_id, contact_id, utc_now())
        )
        try:
            add_audit(org_id, g.get("user", {}).get("id"), "thread.created", "thread", int(tid or 0), {"subject": subject})  # type: ignore
        except Exception:
            pass
        return int(tid or 0)

def add_message(thread_id: int, sender_type: str, body: str, user_id: Optional[int] = None,
                external_user_id: str = "", internal_note: bool = False,
                attachments: Optional[List[dict]] = None) -> Optional[int]:
    """
    Adds message to inbox thread. Validates attachments belong to the same org as the thread.
    """
    if not thread_id or ((not body or not str(body).strip()) and not attachments):
        return None

    # Determine org of the thread for attachment/org consistency checks
    org_row = query_db("SELECT org_id FROM inbox_threads WHERE id=?", (thread_id,), one=True)
    org_id = int((org_row or {}).get("org_id") or 0)
    if not org_id:
        return None

    with db_transaction():
        mid = exec_db(
            "INSERT INTO inbox_messages (thread_id, sender_type, user_id, external_user_id, body, internal_note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (int(thread_id), (sender_type or "agent"), user_id, (external_user_id or ""), body or "", 1 if internal_note else 0, utc_now())
        )
        try:
            exec_db_affect("UPDATE inbox_threads SET last_message_at=? WHERE id=?", (utc_now(), thread_id))
            try:
                add_audit(org_id, user_id, "thread.message_added", "thread", int(thread_id),
                          {"message_id": int(mid or 0), "internal": bool(internal_note)})  # type: ignore
            except Exception:
                pass
        except Exception:
            pass

        # Attachments: secure check — file must belong to same org
        if attachments:
            for a in (attachments or []):
                try:
                    fid = int(a.get("file_id") or 0)
                except Exception:
                    fid = 0
                if not fid:
                    continue
                ok = query_db("SELECT 1 AS x FROM files WHERE id=? AND org_id=?", (fid, org_id), one=True)
                if ok:
                    exec_db(
                        "INSERT INTO message_attachments (message_id, file_id, created_at) VALUES (?, ?, ?)",
                        (mid, int(fid), utc_now())
                    )
                else:
                    log("WARN", "Attachment skipped due to org mismatch", file_id=fid, thread_id=thread_id, org_id=org_id)

    # Notify assignee via SSE (best-effort)
    try:
        thr = query_db("SELECT assignee_id FROM inbox_threads WHERE id=?", (thread_id,), one=True)
        if thr and thr.get("assignee_id"):
            sse_push(int(thr["assignee_id"]), "thread.message", {"thread_id": int(thread_id), "internal": bool(internal_note)})
    except Exception:
        pass
    return int(mid or 0)

# --- Lookups (by phone/email/inn) for CTI/Inbox ---
def lookup_by_phone(org_id: int, phone: str) -> dict:
    norm = normalize_phone(phone or "")
    companies = query_db("SELECT * FROM companies WHERE org_id=? AND (phone_norm=? OR phone=?)", (org_id, norm, phone)) or []
    contacts = query_db("SELECT * FROM contacts WHERE org_id=? AND (phone_norm=? OR phone=?)", (org_id, norm, phone)) or []
    return {"companies": [dict(c) for c in companies], "contacts": [dict(c) for c in contacts]}

def lookup_by_email(org_id: int, email: str) -> dict:
    email = (email or "").strip()
    companies = query_db("SELECT * FROM companies WHERE org_id=? AND email=?", (org_id, email)) or []
    contacts = query_db("SELECT * FROM contacts WHERE org_id=? AND email=?", (org_id, email)) or []
    return {"companies": [dict(c) for c in companies], "contacts": [dict(c) for c in contacts]}

def lookup_by_inn(org_id: int, inn: str) -> List[dict]:
    inn = (inn or "").strip()
    companies = query_db("SELECT * FROM companies WHERE org_id=? AND inn=?", (org_id, inn)) or []
    return [dict(c) for c in companies]

@app.route("/api/lookup", methods=["GET"])
@_login_required
def api_lookup():
    user = g.user
    org_id = user["org_id"]
    company_id = request.args.get("id")
    phone = request.args.get("phone")
    inn = request.args.get("inn")
    email_addr = request.args.get("email")
    result = {"companies": [], "contacts": []}
    if company_id:
        try:
            cid = int(company_id)
        except Exception:
            cid = 0
        c = query_db("SELECT * FROM companies WHERE id=? AND org_id=?", (cid, org_id), one=True)
        if c:
            result["companies"] = [dict(c)]
    elif phone:
        result = lookup_by_phone(org_id, phone)
    elif inn:
        result["companies"] = lookup_by_inn(org_id, inn)
    elif email_addr:
        result = lookup_by_email(org_id, email_addr)
    return jsonify(ok=True, **result)

@app.route("/api/lookup/multi", methods=["POST"])
@_login_required
@_csrf_protect
def api_lookup_multi():
    user = g.user
    data = request.get_json() or {}
    phones = list((data.get("phones") or [])[:10])
    emails = list((data.get("emails") or [])[:10])
    inns = list((data.get("inns") or [])[:10])
    results = {"companies": [], "contacts": [], "grouped": {}}
    for p in phones:
        lk = lookup_by_phone(user["org_id"], p)
        results["grouped"][p] = lk
        results["companies"].extend(lk["companies"])
        results["contacts"].extend(lk["contacts"])
    for e in emails:
        lk = lookup_by_email(user["org_id"], e)
        results["grouped"][e] = lk
        results["companies"].extend(lk["companies"])
        results["contacts"].extend(lk["contacts"])
    for i in inns:
        cs = lookup_by_inn(user["org_id"], i)
        results["grouped"][i] = {"companies": cs, "contacts": []}
        results["companies"].extend(cs)
    # deduplicate
    seen_c, uniq_c = set(), []
    for c in results["companies"]:
        if c["id"] not in seen_c:
            seen_c.add(c["id"]); uniq_c.append(c)
    seen_p, uniq_p = set(), []
    for c in results["contacts"]:
        if c["id"] not in seen_p:
            seen_p.add(c["id"]); uniq_p.append(c)
    results["companies"] = uniq_c
    results["contacts"] = uniq_p
    return jsonify(ok=True, **results)

# ----- INBOX API -----
@app.route("/api/inbox/list", methods=["GET"])
@_login_required
def api_inbox_list():
    user = g.user
    org_id = user["org_id"]
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(max(1, int(request.args.get("per_page", 50))), 100)
    except Exception:
        page, per_page = 1, 50
    offset = (page - 1) * per_page
    status = (request.args.get("status") or "").strip()
    channel = (request.args.get("channel") or "").strip()
    assignee = (request.args.get("assignee") or "").strip()
    who = (request.args.get("who") or "").strip()
    q = (request.args.get("q") or "").strip()
    where = ["t.org_id=?"]
    params: List[Any] = [org_id]
    if status:
        where.append("t.status=?"); params.append(status)
    if channel:
        try:
            where.append("t.channel_id=?"); params.append(int(channel))
        except Exception:
            pass
    if assignee:
        try:
            where.append("t.assignee_id=?"); params.append(int(assignee))
        except Exception:
            pass
    if who == "me":
        where.append("t.assignee_id=?"); params.append(user["id"])
    if q:
        where.append("(t.subject LIKE ?)"); params.append(f"%{q}%")
    wc = " AND ".join(where)
    total_row = query_db(f"SELECT COUNT(*) AS c FROM inbox_threads t WHERE {wc}", tuple(params), one=True)
    total = int((total_row or {}).get("c") or 0)
    threads = query_db(
        f"""
SELECT t.*, c.name AS channel_name, u.username AS assignee_name
FROM inbox_threads t
LEFT JOIN channels c ON t.channel_id=c.id
LEFT JOIN users u ON t.assignee_id=u.id
WHERE {wc}
ORDER BY (t.last_message_at IS NULL) ASC, t.last_message_at DESC, t.created_at DESC
LIMIT ? OFFSET ?
""",
        (*params, per_page, offset)
    ) or []
    return jsonify(ok=True, items=[dict(t) for t in threads], page=page, per_page=per_page, total=int(total or 0))

@app.route("/api/thread/update", methods=["POST"])
@_login_required
@_csrf_protect
def api_thread_update():
    user = g.user
    data = request.get_json() or {}
    thread_id = data.get("id")
    if not thread_id:
        return jsonify(ok=False, error="Thread ID required"), 400
    thr = query_db("SELECT id, org_id FROM inbox_threads WHERE id=? AND org_id=?", (thread_id, user["org_id"]), one=True)
    if not thr:
        return jsonify(ok=False, error="Thread not found"), 404
    updates = {k: v for k, v in data.items() if k != "id"}
    if "tags_json" in updates:
        tags = updates.pop("tags_json")
        updates["tags_csv"] = ",".join(tags) if isinstance(tags, list) else ""
    allowed = {"subject", "status", "priority", "assignee_id", "company_id", "contact_id", "tags_csv", "first_response_due_at"}
    set_clause, params = _safe_update_clause(set(allowed), updates)
    if not set_clause:
        return jsonify(ok=False, error="No valid updates"), 400
    params.append(thread_id); params.append(user["org_id"])
    with db_transaction():
        exec_db_affect(f"UPDATE inbox_threads SET {set_clause} WHERE id=? AND org_id=?", tuple(params))
        try:
            add_audit(user["org_id"], user["id"], "thread.updated", "thread", int(thread_id), updates)  # type: ignore
        except Exception:
            pass
    return jsonify(ok=True)

@app.route("/api/message/send", methods=["POST"])
@_login_required
@_csrf_protect
@_rate_limit("message_send", per_min=60)
def api_message_send():
    user = g.user
    data = request.get_json() or {}
    thread_id = data.get("thread_id")
    body = (data.get("body") or "").strip()
    internal_note = bool(data.get("internal_note", False))
    attachments = data.get("attachments", [])
    if not thread_id or (not body and not attachments):
        return jsonify(ok=False, error="Thread ID and body or attachment required"), 400
    thr = query_db("SELECT id FROM inbox_threads WHERE id=? AND org_id=?", (thread_id, user["org_id"]), one=True)
    if not thr:
        return jsonify(ok=False, error="Thread not found"), 404
    if not _idempotency_guard(f"msg_send:{thread_id}", ttl=60):
        return jsonify(ok=True, duplicated=True)
    mid = add_message(int(thread_id), "agent", body, user["id"], "", internal_note, attachments)
    if mid is None:
        return jsonify(ok=False, error="Message rejected"), 400
    return jsonify(ok=True, id=int(mid))

@app.route("/api/message/to_task", methods=["POST"])
@_login_required
@_csrf_protect
def api_message_to_task():
    user = g.user
    data = request.get_json() or {}
    message_id = data.get("message_id")
    title = (data.get("title") or "").strip()
    if not message_id or not title:
        return jsonify(ok=False, error="Message ID and title required"), 400
    msg = query_db(
        """
SELECT m.*, t.company_id, t.contact_id, t.org_id
FROM inbox_messages m
JOIN inbox_threads t ON m.thread_id=t.id
WHERE m.id=? AND t.org_id=?
""",
        (message_id, user["org_id"]), one=True
    )
    if not msg:
        return jsonify(ok=False, error="Message not found"), 404
    task_id = create_task(  # type: ignore
        org_id=user["org_id"],
        title=title,
        description=msg.get("body") or "",
        assignee_id=user["id"],
        due_at=data.get("due_at"),
        company_id=data.get("company_id") or msg.get("company_id"),
        contact_id=msg.get("contact_id"),
    )
    return jsonify(ok=True, task_id=task_id)
# ==================== END OF CORE PART 10/10 (1/3-A) ====================
# ==================== CORE PART 10/10 (1/3-B) ====================
# ===== BLOCK: API ROUTES — AI ASSISTS, COMMANDS, COLLAB, AGENTS, CHAT, BI, RAG, PAYROLL (PART B) =====

# ----- Optional helpers fallbacks (only if not defined globally) -----
if "detect_mime_from_bytes" not in globals():
    import mimetypes
    def detect_mime_from_bytes(data: bytes, filename: str = "") -> str:
        # naive guess by extension first
        if filename:
            guess = mimetypes.guess_type(filename)[0]
            if guess:
                return guess
        # simple magic fallback
        if data.startswith(b"\xFF\xD8\xFF"):
            return "image/jpeg"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if data[:4] in (b"%PDF",):
            return "application/pdf"
        return "application/octet-stream"

if "is_allowed_upload_type" not in globals():
    def is_allowed_upload_type(ct: str) -> bool:
        allowed = {
            "image/jpeg", "image/png", "image/gif",
            "application/pdf", "text/plain",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/msword",
        }
        return (ct or "").lower() in allowed

if "store_file" not in globals():
    def store_file(org_id: int, filename: str, data: bytes, content_type: str, uploaded_by: Optional[int]) -> dict:
        os.makedirs(LOCAL_UPLOAD_DIR, exist_ok=True)
        fid = exec_db(
            "INSERT INTO files (org_id, storage_key, name, content_type, size_bytes, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (org_id, "", filename, content_type, len(data or b""), uploaded_by, utc_now())
        )
        storage_name = f"{int(fid)}{uuid.uuid4().hex}{secure_filename(filename)}"
        path = os.path.join(LOCAL_UPLOAD_DIR, storage_name)
        with open(path, "wb") as f:
            f.write(data or b"")
        exec_db_affect("UPDATE files SET storage_key=? WHERE id=?", (storage_name, int(fid or 0)))
        return {"id": int(fid or 0), "name": filename, "url": f"/api/files/{int(fid)}/download", "content_type": content_type}

# ----- FILE UPLOAD FOR INBOX MESSAGES -----
@app.route("/api/message/upload", methods=["POST"])
@_login_required
@_csrf_protect
@_rate_limit("message_upload", per_min=30)
def api_message_upload():
    user = g.user
    if "file" not in request.files:
        return jsonify(ok=False, error="No file"), 400
    f = request.files["file"]
    if not f or not f.filename:
        return jsonify(ok=False, error="Empty filename"), 400
    data = f.read()
    if not data:
        return jsonify(ok=False, error="Empty file"), 400
    content_type = detect_mime_from_bytes(data, f.filename) or "application/octet-stream"
    if not is_allowed_upload_type(content_type):
        return jsonify(ok=False, error="File type not allowed"), 400
    info = store_file(user["org_id"], secure_filename(f.filename), data, content_type, user["id"])
    return jsonify(ok=True, file=info)

# ----- AI ASSIST ENDPOINTS -----
@app.route("/api/ai/summarize_thread", methods=["POST"])
@_login_required
@_csrf_protect
@_rate_limit("ai_summarize", per_min=10)
def api_ai_summarize_thread():
    user = g.user
    data = request.get_json() or {}
    thread_id = int(data.get("thread_id") or 0)
    if not thread_id:
        return jsonify(ok=False, error="thread_id required"), 400
    # queue job
    jid = exec_db(
        "INSERT INTO ai_jobs (org_id, user_id, job_type, entity_type, entity_id, input_text, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], user["id"], "summarize", "thread", thread_id, "", "pending", utc_now())
    )
    return jsonify(ok=True, job_id=int(jid or 0), status="queued")

@app.route("/api/ai/draft_reply", methods=["POST"])
@_login_required
@_csrf_protect
@_rate_limit("ai_draft", per_min=10)
def api_ai_draft_reply():
    user = g.user
    data = request.get_json() or {}
    thread_id = int(data.get("thread_id") or 0)
    if not thread_id:
        return jsonify(ok=False, error="thread_id required"), 400
    if AI_SYNC_MODE:
        try:
            msgs = query_db("SELECT body, sender_type FROM inbox_messages WHERE thread_id=? ORDER BY created_at DESC LIMIT 10", (thread_id,)) or []
            context = "\n".join([f"[{m['sender_type']}] {m['body']}" for m in reversed(list(msgs))])
            ctx = truncate_for_ai_context(context, 4000)
            draft = ai_provider_call(f"Сформируй профессиональный ответ на русском:\n\n{ctx}", system="Вежливый тон, фактологично.", temperature=0.4, max_tokens=400)
            return jsonify(ok=True, variants=[draft])
        except Exception as e:
            return jsonify(ok=False, error=str(e)), 500
    jid = exec_db(
        "INSERT INTO ai_jobs (org_id, user_id, job_type, entity_type, entity_id, input_text, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], user["id"], "draft_reply", "thread", thread_id, "", "pending", utc_now())
    )
    return jsonify(ok=True, job_id=int(jid or 0), status="queued")

@app.route("/api/ai/autotag", methods=["POST"])
@_login_required
@_csrf_protect
@_rate_limit("ai_autotag", per_min=10)
def api_ai_autotag():
    user = g.user
    data = request.get_json() or {}
    thread_id = int(data.get("thread_id") or 0)
    if not thread_id:
        return jsonify(ok=False, error="thread_id required"), 400
    jid = exec_db(
        "INSERT INTO ai_jobs (org_id, user_id, job_type, entity_type, entity_id, input_text, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], user["id"], "autotag", "thread", thread_id, "", "pending", utc_now())
    )
    return jsonify(ok=True, job_id=int(jid or 0), status="queued")

@app.route("/api/ai/job_status", methods=["GET"])
@_login_required
def api_ai_job_status():
    user = g.user
    job_id = int(request.args.get("id") or 0)
    if not job_id:
        return jsonify(ok=False, error="id required"), 400
    row = query_db("SELECT id, status, output_text, error FROM ai_jobs WHERE id=? AND org_id=?", (job_id, user["org_id"]), one=True)
    if not row:
        return jsonify(ok=False, error="not_found"), 404
    return jsonify(ok=True, **row)

# ----- COMMAND PALETTE -----
@app.route("/api/ai/command", methods=["POST"])
@_login_required
@_csrf_protect
def api_ai_command():
    user = g.user
    data = request.get_json() or {}
    cmd = (data.get("command") or "").strip()
    context = data.get("context") or {}
    if not cmd:
        return jsonify(ok=False, error="Command required"), 400
    try:
        prompt = f"""
Преобразуй пользовательскую команду в JSON-интент:
Команда: "{cmd}"
Контекст: {json.dumps(context, ensure_ascii=False)}
Допустимые intent: ["go","create_task","create_deal","search","summarize_thread","run_agent","orchestrate","bi_query","rag_answer"]
Верни JSON с полями:
intent, params (dict), ui_hint (короткая подсказка), requires_confirmation (bool)
""".strip()
        txt = ai_provider_call(prompt, system="Ты роутер команд в CRM. Отвечай только JSON.", temperature=0.2, max_tokens=300)
        obj = json.loads(txt) if (txt and txt.strip().startswith("{")) else {"intent": "search", "params": {"q": cmd}, "ui_hint": "Поиск", "requires_confirmation": False}
        intent = obj.get("intent", "search")
        params = obj.get("params", {})

        if intent == "go":
            return jsonify(ok=True, action="navigate", url=str(params.get("url", "/")))

        if intent == "create_task":
            title = (params.get("title") or cmd).strip()
            tid = create_task(user["org_id"], title=title, description=params.get("description", ""), assignee_id=user["id"])  # type: ignore
            return jsonify(ok=True, action="open", url=f"/task/{tid}", created_id=tid)

        if intent == "create_deal":
            title = (params.get("title") or cmd).strip()
            amount = 0.0
            try:
                amount = float(params.get("amount", 0) or 0)
            except Exception:
                amount = 0.0
            did = create_deal(user["org_id"], title=title, amount=amount, stage="new", assignee_id=user["id"])  # type: ignore
            return jsonify(ok=True, action="open", url=f"/deal/{did}", created_id=did)

        if intent == "search":
            q = params.get("q") or cmd
            return jsonify(ok=True, action="navigate", url=f"/search?q={q}")

        if intent == "summarize_thread":
            thread_id = int(params.get("thread_id") or 0)
            if not thread_id:
                return jsonify(ok=False, error="thread_id required"), 400
            jid = exec_db(
                "INSERT INTO ai_jobs (org_id, user_id, job_type, entity_type, entity_id, input_text, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user["org_id"], user["id"], "summarize", "thread", thread_id, "", "pending", utc_now())
            )
            return jsonify(ok=True, action="ai_job", job_id=int(jid or 0))

        if intent == "run_agent":
            agent_name = params.get("agent") or "sales"
            agent_ctx = params.get("context") or {}
            result = run_agent(agent_name, user["org_id"], user["id"], agent_ctx)  # type: ignore
            return jsonify(ok=True, action="agent_result", result=result)

        if intent == "orchestrate":
            plan = params.get("plan") or []
            orch = AgentOrchestrator(user["org_id"], user["id"], parallel=True, max_workers=4)  # type: ignore
            res = orch.run(plan, context={})
            return jsonify(ok=True, action="agent_orchestrator_result", result=res)

        if intent == "bi_query":
            nlq = params.get("q") or cmd
            res = conversational_bi_query(nlq, user["org_id"], user["id"])  # type: ignore
            return jsonify(ok=True, action="bi_result", result=res)

        if intent == "rag_answer":
            qtext = params.get("q") or cmd
            res = rag_answer(user["org_id"], qtext, entity_type=params.get("entity_type"))  # type: ignore
            return jsonify(ok=True, action="rag_result", result=res)

        return jsonify(ok=True, action="noop", info=obj)
    except Exception as e:
        log("ERROR", "AI command failed", error=str(e))
        return jsonify(ok=False, error="Command processing failed"), 500

# ----- LIVE COLLABORATION -----
@app.route("/api/collab/heartbeat", methods=["POST"])
@_login_required
@_csrf_protect
def api_collab_heartbeat():
    user = g.user
    data = request.get_json() or {}
    entity_type = (data.get("entity_type") or "").strip()
    entity_id = int(data.get("entity_id") or 0)
    cursor = data.get("cursor_position") or ""
    if not entity_type or not entity_id:
        return jsonify(ok=False, error="Invalid entity"), 400
    row = query_db("SELECT id FROM collaboration_sessions WHERE entity_type=? AND entity_id=? AND user_id=?", (entity_type, entity_id, user["id"]), one=True)
    if row:
        exec_db_affect("UPDATE collaboration_sessions SET cursor_position=?, last_heartbeat=? WHERE id=?", (cursor, utc_now(), row["id"]))
        sid = row["id"]
    else:
        sid = exec_db("INSERT INTO collaboration_sessions (entity_type, entity_id, user_id, cursor_position, last_heartbeat, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                      (entity_type, entity_id, user["id"], cursor, utc_now(), utc_now()))
    return jsonify(ok=True, session_id=int(sid or 0))

@app.route("/api/collab/change", methods=["POST"])
@_login_required
@_csrf_protect
def api_collab_change():
    user = g.user
    data = request.get_json() or {}
    entity_type = (data.get("entity_type") or "").strip()
    entity_id = int(data.get("entity_id") or 0)
    change_type = (data.get("change_type") or "").strip()
    change_data = json.dumps(data.get("change_data") or {}, ensure_ascii=False)
    if not entity_type or not entity_id or not change_type:
        return jsonify(ok=False, error="Invalid change"), 400
    exec_db("INSERT INTO collaboration_changes (entity_type, entity_id, user_id, change_type, change_data, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (entity_type, entity_id, user["id"], change_type, change_data, utc_now()))
    try:
        sessions = query_db("SELECT DISTINCT user_id FROM collaboration_sessions WHERE entity_type=? AND entity_id=? AND user_id<>?",
                            (entity_type, entity_id, user["id"])) or []
        for s in sessions:
            sse_push(int(s["user_id"]), "collab.change", {"entity_type": entity_type, "entity_id": entity_id, "by": user["id"], "type": change_type})
    except Exception:
        pass
    return jsonify(ok=True)

# ----- AGENTS API -----
@app.route("/api/agents/list", methods=["GET"])
@_login_required
def api_agents_list():
    rows = query_db(
        "SELECT id, name, description, graph_json, active, created_by, created_at, updated_at "
        "FROM agent_definitions WHERE org_id=? ORDER BY updated_at DESC NULLS LAST, created_at DESC",
        (g.user["org_id"],)
    ) or []
    return jsonify(ok=True, items=rows)

@app.route("/api/agent/definition/save", methods=["POST"])
@_login_required
@_csrf_protect
def api_agent_definition_save():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify(ok=False, error="name required"), 400
    desc = (data.get("description") or "").strip()
    active = bool(data.get("active", True))
    graph = data.get("graph") or data.get("definition") or {}
    try:
        existing = query_db("SELECT id FROM agent_definitions WHERE org_id=? AND name=?", (g.user["org_id"], name), one=True)
        if existing:
            exec_db_affect(
                "UPDATE agent_definitions SET description=?, graph_json=?, active=?, updated_at=? WHERE id=?",
                (desc, json.dumps(graph, ensure_ascii=False), int(active), utc_now(), int(existing["id"]))
            )
            aid = int(existing["id"])
        else:
            aid = exec_db(
                "INSERT INTO agent_definitions (org_id, name, description, graph_json, active, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (g.user["org_id"], name, desc, json.dumps(graph, ensure_ascii=False), int(active), g.user["id"], utc_now(), utc_now())
            )
        return jsonify(ok=True, id=int(aid or 0))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/api/agent/run", methods=["POST"])
@_login_required
@_csrf_protect
def api_agent_run():
    data = request.get_json() or {}
    agent = (data.get("agent") or data.get("name") or "").strip()
    ctx = data.get("context") or {}
    try:
        ag = get_agent(agent, g.user["org_id"], g.user["id"])
        if not ag:
            return jsonify(ok=False, error="unknown_agent"), 404
        res = ag.execute(ctx)
        return jsonify(ok=True, result=res)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/api/agent/test", methods=["POST"])
@_login_required
@_csrf_protect
def api_agent_test():
    data = request.get_json() or {}
    definition = data.get("definition") or data.get("graph") or {}
    context = data.get("context") or {"org_id": g.user["org_id"], "user_id": g.user["id"]}
    try:
        runner = CustomAgentRunner(definition)
        res = runner.execute(context)
        return jsonify(ok=True, result=res)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/api/agents/orchestrate", methods=["POST"])
@_login_required
@_csrf_protect
def api_agents_orchestrate():
    data = request.get_json() or {}
    plan = data.get("plan") or []
    ctx = data.get("context") or {}
    parallel = bool(data.get("parallel", False))
    max_workers = int(data.get("max_workers", 4))
    try:
        orch = AgentOrchestrator(g.user["org_id"], g.user["id"], parallel=parallel, max_workers=max_workers)
        res = orch.run(plan, ctx)
        return jsonify(ok=True, result=res)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

# ----- CHAT API -----
@app.route("/api/chat/create", methods=["POST"])
@_login_required
@_csrf_protect
def api_chat_create():
    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    ch_type = (data.get("type") or "public").strip()
    members = data.get("members") or []
    dept_ids = data.get("department_ids") or []
    if not title:
        return jsonify(ok=False, error="title required"), 400
    try:
        cid = exec_db(
            "INSERT INTO chat_channels (org_id, type, title, created_at) VALUES (?, ?, ?, ?)",
            (g.user["org_id"], ch_type, title, utc_now())
        )
        for uid in members:
            try:
                uid_i = int(uid)
                u = query_db("SELECT id FROM users WHERE id=? AND org_id=? AND active=1", (uid_i, g.user["org_id"]), one=True)
                if u:
                    exec_db("INSERT INTO chat_members (channel_id, user_id, created_at) VALUES (?, ?, ?)", (int(cid or 0), uid_i, utc_now()))
            except Exception:
                pass
        for did in dept_ids:
            try:
                did_i = int(did)
                exec_db("INSERT INTO chat_members (channel_id, department_id, created_at) VALUES (?, ?, ?)", (int(cid or 0), did_i, utc_now()))
            except Exception:
                pass
        return jsonify(ok=True, id=int(cid or 0))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/api/chat/send", methods=["POST"])
@_login_required
@_csrf_protect
def api_chat_send():
    data = request.get_json() or {}
    ch_id = int(data.get("channel_id") or 0)
    body = (data.get("body") or "").strip()
    if not ch_id or not body:
        return jsonify(ok=False, error="channel_id and body required"), 400
    # ensure channel belongs to org and user can post
    ch = query_db(
        """
SELECT c.* FROM chat_channels c
LEFT JOIN chat_members m ON c.id=m.channel_id AND m.user_id=?
LEFT JOIN chat_members dm ON c.id=dm.channel_id AND dm.department_id=(SELECT department_id FROM users WHERE id=?)
WHERE c.id=? AND c.org_id=? AND (c.type='public' OR m.user_id IS NOT NULL OR dm.department_id IS NOT NULL)
""",
        (g.user["id"], g.user["id"], ch_id, g.user["org_id"]), one=True
    )
    if not ch:
        return jsonify(ok=False, error="Channel not found or access denied"), 403
    msg_id = exec_db("INSERT INTO chat_messages (channel_id, user_id, body, created_at) VALUES (?, ?, ?, ?)", (ch_id, g.user["id"], body, utc_now()))
    try:
        members = query_db("SELECT DISTINCT user_id FROM chat_members WHERE channel_id=? AND user_id IS NOT NULL", (ch_id,)) or []
        for m in members:
            if m.get("user_id"):
                sse_push(int(m["user_id"]), "chat.message", {"channel_id": ch_id, "by": g.user["id"]})
    except Exception:
        pass
    return jsonify(ok=True, id=int(msg_id or 0))

@app.route("/api/chat/upload", methods=["POST"])
@_login_required
@_csrf_protect
def api_chat_upload():
    ch_id = int(request.form.get("channel_id") or 0)
    if not ch_id or "file" not in request.files:
        return jsonify(ok=False, error="channel_id and file required"), 400
    ch = query_db(
        """
SELECT c.* FROM chat_channels c
LEFT JOIN chat_members m ON c.id=m.channel_id AND m.user_id=?
LEFT JOIN chat_members dm ON c.id=dm.channel_id AND dm.department_id=(SELECT department_id FROM users WHERE id=?)
WHERE c.id=? AND c.org_id=? AND (c.type='public' OR m.user_id IS NOT NULL OR dm.department_id IS NOT NULL)
""",
        (g.user["id"], g.user["id"], ch_id, g.user["org_id"]), one=True
    )
    if not ch:
        return jsonify(ok=False, error="Channel not found or access denied"), 403
    f = request.files["file"]
    data = f.read()
    content_type = detect_mime_from_bytes(data, f.filename) or "application/octet-stream"
    if not is_allowed_upload_type(content_type):
        return jsonify(ok=False, error="File type not allowed"), 400
    info = store_file(g.user["org_id"], secure_filename(f.filename), data, content_type, g.user["id"])
    exec_db("INSERT INTO chat_messages (channel_id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
            (ch_id, g.user["id"], f"📎 {info['name']} ({info['url']})", utc_now()))
    return jsonify(ok=True, file_id=info["id"], url=info["url"])

@app.route("/api/chat/add_department", methods=["POST"])
@_login_required
@_csrf_protect
def api_chat_add_department():
    data = request.get_json() or {}
    ch_id = int(data.get("channel_id") or 0)
    dept_id = int(data.get("department_id") or 0)
    if not ch_id or not dept_id:
        return jsonify(ok=False, error="channel_id and department_id required"), 400
    ch = query_db("SELECT id FROM chat_channels WHERE id=? AND org_id=?", (ch_id, g.user["org_id"]), one=True)
    dep = query_db("SELECT id FROM departments WHERE id=? AND org_id=?", (dept_id, g.user["org_id"]), one=True)
    if not ch or not dep:
        return jsonify(ok=False, error="Not found"), 404
    exec_db("INSERT INTO chat_members (channel_id, department_id, created_at) VALUES (?, ?, ?)", (ch_id, dept_id, utc_now()))
    return jsonify(ok=True)

# ----- Conversational BI -----
@app.route("/api/bi/query", methods=["POST"])
@_login_required
@_csrf_protect
def api_bi_query():
    data = request.get_json() or {}
    qtext = (data.get("q") or data.get("query") or "").strip()
    if not qtext:
        return jsonify(ok=False, error="q required"), 400
    res = conversational_bi_query(qtext, g.user["org_id"], g.user["id"])  # type: ignore
    return jsonify(ok=True, result=res)

# ----- RAG endpoints -----
@app.route("/api/rag/index", methods=["POST"])
@_login_required
@_csrf_protect
def api_rag_index():
    data = request.get_json() or {}
    entity_type = (data.get("entity_type") or "").strip()
    entity_id = int(data.get("entity_id") or 0)
    text = (data.get("text") or "").strip()
    if not entity_type or not entity_id or not text:
        return jsonify(ok=False, error="entity_type, entity_id, text required"), 400
    rag_index_text(g.user["org_id"], entity_type, entity_id, text)  # type: ignore
    return jsonify(ok=True)

@app.route("/api/rag/answer", methods=["POST"])
@_login_required
@_csrf_protect
def api_rag_answer():
    data = request.get_json() or {}
    qtext = (data.get("q") or "").strip()
    if not qtext:
        return jsonify(ok=False, error="q required"), 400
    res = rag_answer(g.user["org_id"], qtext, entity_type=data.get("entity_type"))  # type: ignore
    return jsonify(ok=True, result=res)

# ----- PAYROLL API (минимально необходимый набор) -----
@app.route("/api/payroll/plan/list", methods=["GET"])
@_login_required
def api_payroll_plan_list():
    rows = query_db(
        "SELECT id, name, description, config_json, active, created_at, updated_at FROM payroll_plans WHERE org_id=? ORDER BY created_at DESC",
        (g.user["org_id"],)
    ) or []
    return jsonify(ok=True, items=rows)

@app.route("/api/payroll/plan/upsert", methods=["POST"])
@_login_required
@_csrf_protect
@_require_role("admin")
def api_payroll_plan_upsert():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify(ok=False, error="name required"), 400
    cfg = data.get("config") or data.get("config_json") or {}
    desc = (data.get("description") or "").strip()
    active = bool(data.get("active", True))
    ex = query_db("SELECT id FROM payroll_plans WHERE org_id=? AND name=?", (g.user["org_id"], name), one=True)
    if ex:
        exec_db_affect("UPDATE payroll_plans SET description=?, config_json=?, active=?, updated_at=? WHERE id=?",
                       (desc, json.dumps(cfg, ensure_ascii=False), int(active), utc_now(), int(ex["id"])))
        pid = int(ex["id"])
    else:
        pid = exec_db("INSERT INTO payroll_plans (org_id, name, description, config_json, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (g.user["org_id"], name, desc, json.dumps(cfg, ensure_ascii=False), int(active), utc_now(), utc_now()))
    return jsonify(ok=True, id=int(pid or 0))

@app.route("/api/payroll/assign/upsert", methods=["POST"])
@_login_required
@_csrf_protect
@_require_role("admin")
def api_payroll_assign_upsert():
    data = request.get_json() or {}
    uid = int(data.get("user_id") or 0)
    plan_id = int(data.get("plan_id") or 0)
    eff_from = ensure_iso_datetime(data.get("effective_from") or utc_now())
    eff_to = ensure_iso_datetime(data.get("effective_to")) if data.get("effective_to") else None
    quota = float(data.get("quota_number") or 0)
    leader = 1 if bool(data.get("team_leader", False)) else 0
    if not (uid and plan_id and eff_from):
        return jsonify(ok=False, error="user_id, plan_id, effective_from required"), 400
    rid = exec_db("INSERT INTO payroll_assignments (org_id, user_id, plan_id, effective_from, effective_to, quota_number, team_leader, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (g.user["org_id"], uid, plan_id, eff_from, eff_to, quota, leader, utc_now()))
    return jsonify(ok=True, id=int(rid or 0))

@app.route("/api/payroll/period/ensure", methods=["POST"])
@_login_required
@_csrf_protect
@_require_role("admin")
def api_payroll_period_ensure():
    data = request.get_json() or {}
    period_key = (data.get("period_key") or "").strip()
    date_start = ensure_iso_datetime(data.get("date_start") or "")
    date_end = ensure_iso_datetime(data.get("date_end") or "")
    if not (period_key and date_start and date_end):
        return jsonify(ok=False, error="period_key, date_start, date_end required"), 400
    pid = payroll_ensure_period(g.user["org_id"], period_key, date_start, date_end)
    return jsonify(ok=True, period_id=int(pid or 0))

@app.route("/api/payroll/period/recalc", methods=["POST"])
@_login_required
@_csrf_protect
@_require_role("admin")
def api_payroll_period_recalc():
    data = request.get_json() or {}
    period_key = (data.get("period_key") or "").strip()
    if not period_key:
        return jsonify(ok=False, error="period_key required"), 400
    res = payroll_recalculate_period(g.user["org_id"], period_key)
    return jsonify(res if isinstance(res, dict) else {"ok": False, "error": "calc_error"})

@app.route("/api/payroll/period/lock", methods=["POST"])
@_login_required
@_csrf_protect
@_require_role("admin")
def api_payroll_period_lock():
    data = request.get_json() or {}
    period_key = (data.get("period_key") or "").strip()
    lock = bool(data.get("lock", True))
    if not period_key:
        return jsonify(ok=False, error="period_key required"), 400
    ok = payroll_lock_period(g.user["org_id"], period_key, lock=lock)
    return jsonify(ok=bool(ok))

@app.route("/api/payroll/user/summary", methods=["GET"])
@_login_required
def api_payroll_user_summary():
    period_key = (request.args.get("period_key") or "").strip()
    uid = int(request.args.get("user_id") or g.user["id"])
    if not period_key:
        return jsonify(ok=False, error="period_key required"), 400
    res = payroll_user_summary(g.user["org_id"], uid, period_key)
    return jsonify(res if isinstance(res, dict) else {"ok": False, "error": "summary_error"})
# ==================== END OF CORE PART 10/10 (1/3-B) ====================
# ==================== CORE PART 10/10 (2/3) ====================
# ===== BLOCK: SSE STREAM ENDPOINT =====
@app.route("/sse")
@_login_required
def sse_stream():
    """
    Server-Sent Events stream:
    - ограничение на число подключений на пользователя (SSE_MAX_CONN_PER_USER),
    - heartbeat каждые ~25 секунд,
    - корректная отписка и очистка очереди при разрыве.
    """
    if not SSE_ENABLED:
        return Response("SSE disabled", status=503)
    user = g.user
    uid = int(user["id"])
    q = Queue(maxsize=100)

    with _sse_lock:
        lst = _sse_queues.setdefault(uid, [])
        if len(lst) >= SSE_MAX_CONN_PER_USER:
            return Response("Too many SSE connections", status=429)
        lst.append(q)

    @stream_with_context
    def _gen():
        # initial heartbeat сразу после подключения
        yield "event: ping\ndata: {}\n\n"
        try:
            while not _shutdown_event.is_set():
                try:
                    item = q.get(timeout=25)
                    ev = item.get("event") or "message"
                    data = json.dumps(item.get("data") or {}, ensure_ascii=False)
                    yield f"event: {ev}\ndata: {data}\n\n"
                except Empty:
                    # keep-alive
                    yield "event: ping\ndata: {}\n\n"
        finally:
            try:
                with _sse_lock:
                    lst = _sse_queues.get(uid, [])
                    if q in lst:
                        lst.remove(q)
                    if not lst:
                        _sse_queues.pop(uid, None)
            except Exception:
                pass

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive"
    }
    return Response(_gen(), mimetype="text/event-stream", headers=headers)

# ===== BLOCK: API ROUTES — CTI/CALLS, EXPORTS, OPENAPI (SECURE/OPTIMIZED) =====
# --- Phone extract (fixed RU regex) ---
def extract_phones_from_text(text: str) -> List[str]:
    """
    Extract phones in E.164-like and common Russian formats; normalized to +7... where applicable.
    """
    if not text:
        return []
    # International: +xxxxxxxx with separators/spaces/parentheses
    intl_re = re.compile(r"(?:\+?\d[\d\-\s\(\)]{9,}\d)")
    # RU: +7/8 (spaces/dashes/parentheses allowed), e.g. +7 (XXX) XXX-XX-XX or 8XXXXXXXXXX
    ru_re = re.compile(r"(?:\+?7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}")
    phones: List[str] = []
    for pat in (intl_re, ru_re):
        for m in pat.findall(text or ""):
            norm = normalize_phone(m)
            if norm and norm not in phones:
                phones.append(norm)
    return phones

# --- SSRF-safe helpers for recordings fetch ---
def _resolve_all_ips(hostname: str) -> List[str]:
    try:
        res = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in res})
    except socket.gaierror:
        return []

def _is_private_ip(ip: str) -> bool:
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
            ip_obj.is_reserved or ip_obj.is_multicast
        )
    except Exception:
        return True

def validate_public_url(url: str) -> bool:
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        ips = _resolve_all_ips(host)
        if not ips:
            return False
        for ip in ips:
            if _is_private_ip(ip):
                return False
        return True
    except Exception:
        return False

def http_stream_safe(url: str, timeout: int = 15, headers: Optional[dict] = None,
                     max_bytes: int = 100 * 1024 * 1024, allow_redirects: bool = False, max_redirects: int = 5):
    """
    SSRF‑safe HTTP streaming:
    - проверка URL/хоста на публичность (не приватные адреса),
    - контроль редиректов,
    - ограничение объема.
    """
    def _one(u):
        if not validate_public_url(u):
            raise ValueError("Untrusted URL")
        if _rq is None:
            raise RuntimeError("HTTP client unavailable")
        return _rq.get(u, timeout=timeout, stream=True, headers=headers or {}, allow_redirects=False)
    r = _one(url)
    try:
        redirects = 0
        while 300 <= r.status_code < 400:
            if not allow_redirects:
                raise ValueError("Redirects not allowed")
            loc = r.headers.get("Location", "")
            if not loc or redirects >= max_redirects:
                raise ValueError("Too many redirects")
            if not validate_public_url(loc):
                raise ValueError("Redirected to untrusted host")
            redirects += 1
            r.close()
            r = _one(loc)
        r.raise_for_status()
        read = 0
        for chunk in r.iter_content(chunk_size=8192):
            if not chunk:
                continue
            read += len(chunk)
            if read > max_bytes:
                raise ValueError("Content too large")
            yield chunk
    finally:
        try:
            r.close()
        except Exception:
            pass

# --- CTI Signature (HMAC-SHA256) ---
def _cti_check_signature(channel: dict, raw_body: bytes, provided: str) -> bool:
    if not channel or not (channel.get("secret") or "").strip():
        return False
    try:
        sig = provided or ""
        if sig.startswith("sha256="):
            sig = sig.split("=", 1)[1].strip()
        digest = hmac.new((channel["secret"] or "").encode("utf-8"), raw_body or b"", hashlib.sha256).hexdigest()
        return secure_equal(digest, sig)
    except Exception:
        return False

# ----- CTI Provider Webhook (secure) -----
@app.route("/cti/provider/<provider_name>", methods=["POST"])
@_rate_limit_ip("cti_provider_webhook", per_min=500)
def cti_provider_webhook(provider_name: str):
    """
    Normalizes incoming CTI payload and records call start/end.
    Security:
    - Channel selected by X-CTI-Channel (ID).
    - Signature X-CTI-Signature: HMAC-SHA256 over raw JSON body with channel.secret.
    """
    try:
        raw_body = request.get_data() or b""
        payload = request.get_json(silent=True) or {}
        # Channel selection and signature
        ch_id_hdr = request.headers.get("X-CTI-Channel") or request.args.get("channel_id") or payload.get("channel_id")
        try:
            ch_id = int(ch_id_hdr or 0)
        except Exception:
            ch_id = 0
        if not ch_id:
            return jsonify(ok=False, error="Missing X-CTI-Channel"), 400
        channel = query_db("SELECT * FROM channels WHERE id=? AND type='phone' AND active=1", (ch_id,), one=True)
        if not channel:
            return jsonify(ok=False, error="Channel not found"), 404
        sig = request.headers.get("X-CTI-Signature", "")
        allow_unsigned = os.getenv("CTI_ALLOW_UNSIGNED", "false").lower() == "true"
        if not allow_unsigned:
            if not sig or not _cti_check_signature(channel, raw_body, sig):
                return jsonify(ok=False, error="Invalid signature"), 401

        org_id = int(channel["org_id"])
        channel_id = int(channel["id"])

        # Normalize fields
        norm = {
            "call_id": str(payload.get("call_id") or payload.get("call_uuid") or payload.get("virtual_id") or ""),
            "from": payload.get("from") or payload.get("caller_number") or payload.get("src_num") or "",
            "to": payload.get("to") or payload.get("called_number") or payload.get("dst_num") or "",
            "duration": int(payload.get("duration") or payload.get("duration_sec") or payload.get("billsec") or 0)
        }

        cmd = str(payload.get("event") or payload.get("command_id") or "").lower()
        if cmd in ("call.incoming", "call.new", "call", "incoming"):
            _handle_call_incoming(org_id, channel_id, norm)
        elif cmd in ("call.ended", "call.completed", "summary", "ended"):
            _handle_call_ended(org_id, channel_id, norm)
        else:
            # unknown event: ignore silently
            pass
        return jsonify(ok=True)
    except Exception as e:
        log("ERROR", "CTI webhook failed", error=str(e))
        return jsonify(ok=False, error="Processing failed"), 500

def _handle_call_incoming(org_id: int, channel_id: int, data: dict):
    call_id_external = data.get("call_id", "")
    from_number = normalize_phone(data.get("from", ""))
    to_number = normalize_phone(data.get("to", ""))
    existing = query_db("SELECT id FROM calls WHERE org_id=? AND external_call_id=?", (org_id, call_id_external), one=True)
    if existing:
        return
    lk = lookup_by_phone(org_id, from_number)
    company_id = lk["companies"][0]["id"] if lk["companies"] else None
    contact_id = lk["contacts"][0]["id"] if lk["contacts"] else None
    call_id = exec_db(
        "INSERT INTO calls (org_id, channel_id, external_call_id, direction, from_e164, to_e164, agent_id, company_id, contact_id, status, started_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (org_id, channel_id, call_id_external, "inbound", from_number, to_number, None, company_id, contact_id, "ringing", utc_now(), utc_now())
    )
    agents = query_db("SELECT id FROM users WHERE org_id=? AND active=1", (org_id,)) or []
    for a in agents:
        try:
            sse_push(int(a["id"]), "call.incoming", {"call_id": int(call_id or 0), "from": from_number})
        except Exception:
            pass

def _handle_call_ended(org_id: int, channel_id: int, data: dict):
    call_id_external = data.get("call_id", "")
    duration_sec = int(data.get("duration", 0))
    call = query_db("SELECT id FROM calls WHERE org_id=? AND external_call_id=?", (org_id, call_id_external), one=True)
    if not call:
        return
    exec_db("UPDATE calls SET status='completed', duration_sec=?, ended_at=? WHERE id=?", (duration_sec, utc_now(), call["id"]))

# ----- Calls API -----
@app.route("/api/calls/list", methods=["GET"])
@_login_required
def api_calls_list():
    user = g.user
    org_id = user["org_id"]
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(max(1, int(request.args.get("per_page", 100))), 200)
    offset = (page - 1) * per_page
    mine = request.args.get("mine", "0") == "1"
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    company_id = request.args.get("company_id")
    contact_id = request.args.get("contact_id")
    where = ["c.org_id=?"]; params: List[Any] = [org_id]
    if mine:
        where.append("c.agent_id=?"); params.append(user["id"])
    if date_from:
        where.append("c.started_at >= ?"); params.append(ensure_iso_datetime(date_from))
    if date_to:
        where.append("c.started_at <= ?"); params.append(ensure_iso_datetime(date_to))
    if company_id:
        where.append("c.company_id=?"); params.append(int(company_id))
    if contact_id:
        where.append("c.contact_id=?"); params.append(int(contact_id))
    wc = " AND ".join(where)
    total_row = query_db(f"SELECT COUNT(*) AS c FROM calls c WHERE {wc}", tuple(params), one=True)
    total = int((total_row or {}).get("c") or 0)
    calls = query_db(
        f"""
SELECT c.*, u.username AS agent_name, comp.name AS company_name, cont.name AS contact_name
FROM calls c
LEFT JOIN users u ON c.agent_id=u.id
LEFT JOIN companies comp ON c.company_id=comp.id
LEFT JOIN contacts cont ON c.contact_id=cont.id
WHERE {wc}
ORDER BY c.started_at DESC
LIMIT ? OFFSET ?
""",
        (*params, per_page, offset)
    ) or []
    return jsonify(ok=True, items=[dict(c) for c in calls], page=page, per_page=per_page, total=int(total or 0))

@app.route("/api/cti/click_to_call", methods=["POST"])
@_login_required
@_csrf_protect
@_rate_limit("click_to_call", per_min=30)
def api_cti_click_to_call():
    user = g.user
    data = request.get_json() or {}
    to = (data.get("to") or "").strip()
    if not to:
        return jsonify(ok=False, error="Phone number required"), 400
    to_e164 = normalize_phone(to)
    channel = query_db("SELECT * FROM channels WHERE org_id=? AND type='phone' AND active=1 LIMIT 1", (user["org_id"],), one=True)
    if not channel:
        return jsonify(ok=False, error="Phone channel not configured"), 400
    call_id = exec_db(
        "INSERT INTO calls (org_id, channel_id, direction, from_e164, to_e164, agent_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], channel["id"], "outbound", user.get("phone", ""), to_e164, user["id"], "initiated", utc_now())
    )
    try:
        sse_push(int(user["id"]), "call.started", {"call_id": int(call_id or 0), "to": to_e164})
    except Exception:
        pass
    return jsonify(ok=True, call_id=int(call_id or 0), message=f"Calling {to_e164}...")

@app.route("/cti/recording/<int:rec_id>", methods=["GET"])
@_login_required
@_rate_limit("cti_recording", per_min=30)
def cti_recording(rec_id: int):
    user = g.user
    call = query_db("SELECT * FROM calls WHERE id=? AND org_id=?", (rec_id, user["org_id"]), one=True)
    if not call or not call.get("recording_url"):
        return jsonify(ok=False, error="Recording not found"), 404
    rec_url = call["recording_url"]
    if not validate_public_url(rec_url):
        return jsonify(ok=False, error="Untrusted recording host"), 400
    try:
        def gen():
            for chunk in http_stream_safe(rec_url, timeout=20, allow_redirects=True):
                yield chunk
        return Response(gen(), mimetype="audio/mpeg", headers={"Content-Disposition": f'attachment; filename=\"recording{rec_id}.mp3\""})
    except Exception as e:
        log("ERROR", "Recording fetch failed", error=str(e))
        return jsonify(ok=False, error="Failed to fetch recording"), 500

# ---- Exports (CSV with injection protection + ETag) ----
def _csv_safe_cell(val: Any) -> Any:
    """Prevent CSV formula injection by prefixing dangerous leading chars with apostrophe."""
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ("=", "+", "-", "@"):
        return "'" + s
    return s

@app.route("/api/export/calls/csv", methods=["GET"])
@_login_required
def export_calls_csv():
    user = g.user
    rows = query_db(
        "SELECT c.id, c.direction, c.from_e164, c.to_e164, u.username AS agent, c.status, c.duration_sec, c.started_at, co.name AS company "
        "FROM calls c LEFT JOIN users u ON c.agent_id=u.id LEFT JOIN companies co ON c.company_id=co.id "
        "WHERE c.org_id=? ORDER BY c.started_at DESC LIMIT 5000",
        (user["org_id"],)
    ) or []
    import csv
    from io import StringIO
    out = StringIO()
    w = csv.writer(out, delimiter=';')
    w.writerow(['ID', 'Direction', 'From', 'To', 'Agent', 'Status', 'Duration', 'Started', 'Company'])
    for r in rows:
        w.writerow([_csv_safe_cell(r["id"]), _csv_safe_cell(r.get("direction") or ""), _csv_safe_cell(r.get("from_e164") or ""),
                    _csv_safe_cell(r.get("to_e164") or ""), _csv_safe_cell(r.get("agent") or ""), _csv_safe_cell(r.get("status") or ""),
                    _csv_safe_cell(r.get("duration_sec") or 0), _csv_safe_cell(r.get("started_at") or ""), _csv_safe_cell(r.get("company") or "")])
    out.seek(0)
    payload = out.getvalue().encode("utf-8", errors="ignore")
    etag = hashlib.sha256(payload).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return Response(status=304)
    resp = Response(payload, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=calls_export.csv"})
    resp.headers["ETag"] = etag
    return resp

@app.route("/api/export/inbox/csv", methods=["GET"])
@_login_required
def export_inbox_csv():
    user = g.user
    rows = query_db(
        "SELECT t.id, t.subject, t.status, t.priority, c.name AS channel_name, u.username AS assignee, t.created_at, t.last_message_at "
        "FROM inbox_threads t LEFT JOIN channels c ON t.channel_id=c.id LEFT JOIN users u ON t.assignee_id=u.id "
        "WHERE t.org_id=? ORDER BY t.last_message_at DESC LIMIT 5000",
        (user["org_id"],)
    ) or []
    import csv
    from io import StringIO
    out = StringIO()
    w = csv.writer(out, delimiter=';')
    w.writerow(['ID', 'Subject', 'Status', 'Priority', 'Channel', 'Assignee', 'Created', 'Last Message'])
    for r in rows:
        w.writerow([_csv_safe_cell(r["id"]), _csv_safe_cell(r.get("subject") or ""), _csv_safe_cell(r.get("status") or ""),
                    _csv_safe_cell(r.get("priority") or ""), _csv_safe_cell(r.get("channel_name") or ""),
                    _csv_safe_cell(r.get("assignee") or ""), _csv_safe_cell(r.get("created_at") or ""), _csv_safe_cell(r.get("last_message_at") or "")])
    out.seek(0)
    payload = out.getvalue().encode("utf-8", errors="ignore")
    etag = hashlib.sha256(payload).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return Response(status=304)
    resp = Response(payload, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=inbox_export.csv"})
    resp.headers["ETag"] = etag
    return resp

@app.route("/api/export/tasks/csv", methods=["GET"])
@_login_required
def export_tasks_csv():
    user = g.user
    rows = query_db(
        "SELECT t.id, t.title, t.status, t.priority, u.username AS assignee, c.name AS company, t.due_at, t.created_at, t.completed_at "
        "FROM tasks t LEFT JOIN users u ON t.assignee_id=u.id LEFT JOIN companies c ON t.company_id=c.id "
        "WHERE t.org_id=? ORDER BY t.created_at DESC LIMIT 5000",
        (user["org_id"],)
    ) or []
    import csv
    from io import StringIO
    out = StringIO()
    w = csv.writer(out, delimiter=';')
    w.writerow(['ID', 'Title', 'Status', 'Priority', 'Assignee', 'Company', 'Due Date', 'Created', 'Completed'])
    for r in rows:
        w.writerow([_csv_safe_cell(r["id"]), _csv_safe_cell(r.get("title") or ""), _csv_safe_cell(r.get("status") or ""),
                    _csv_safe_cell(r.get("priority") or ""), _csv_safe_cell(r.get("assignee") or ""),
                    _csv_safe_cell(r.get("company") or ""), _csv_safe_cell(r.get("due_at") or ""),
                    _csv_safe_cell(r.get("created_at") or ""), _csv_safe_cell(r.get("completed_at") or "")])
    out.seek(0)
    payload = out.getvalue().encode("utf-8", errors="ignore")
    etag = hashlib.sha256(payload).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return Response(status=304)
    resp = Response(payload, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=tasks_export.csv"})
    resp.headers["ETag"] = etag
    return resp

@app.route("/api/export/deals/csv", methods=["GET"])
@_login_required
def export_deals_csv():
    user = g.user
    rows = query_db(
        "SELECT d.id, d.title, d.amount, d.currency, d.status, d.stage, u.username AS assignee, c.name AS company, d.created_at "
        "FROM deals d LEFT JOIN users u ON d.assignee_id=u.id LEFT JOIN companies c ON d.company_id=c.id "
        "WHERE d.org_id=? ORDER BY d.created_at DESC LIMIT 5000",
        (user["org_id"],)
    ) or []
    import csv
    from io import StringIO
    out = StringIO()
    w = csv.writer(out, delimiter=';')
    w.writerow(['ID', 'Title', 'Amount', 'Currency', 'Status', 'Stage', 'Assignee', 'Company', 'Created'])
    for d in rows:
        w.writerow([_csv_safe_cell(d["id"]), _csv_safe_cell(d.get("title") or ""), _csv_safe_cell(d.get("amount") or 0),
                    _csv_safe_cell(d.get("currency") or "RUB"), _csv_safe_cell(d.get("status") or ""),
                    _csv_safe_cell(d.get("stage") or ""), _csv_safe_cell(d.get("assignee") or ""),
                    _csv_safe_cell(d.get("company") or ""), _csv_safe_cell(d.get("created_at") or "")])
    out.seek(0)
    payload = out.getvalue().encode("utf-8", errors="ignore")
    etag = hashlib.sha256(payload).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return Response(status=304)
    resp = Response(payload, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=deals_export.csv"})
    resp.headers["ETag"] = etag
    return resp

# ----- OpenAPI minimal (aligned to actual routes) -----
@app.route("/api/openapi.json", methods=["GET"])
def api_openapi():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "CRM API", "version": VERSION},
        "paths": {
            "/api/profile": {"get": {"summary": "Get profile"}, "patch": {"summary": "Update profile"}},
            "/api/profile/password": {"post": {"summary": "Change password"}},
            "/api/tasks/list": {"get": {"summary": "List tasks"}},
            "/api/companies/list": {"get": {"summary": "List companies"}},
            "/api/inbox/list": {"get": {"summary": "List inbox threads"}},
            "/api/calls/list": {"get": {"summary": "List calls"}},
            "/api/ai/command": {"post": {"summary": "AI Command Palette"}},
            "/api/bi/query": {"post": {"summary": "Conversational BI query"}},
            "/api/calendar/events": {"get": {"summary": "List calendar events"}, "post": {"summary": "Create calendar event"}},
            "/api/payroll/plan/list": {"get": {"summary": "List payroll plans"}},
            "/api/payroll/user/summary": {"get": {"summary": "User payroll summary"}},
            "/api/agents/list": {"get": {"summary": "List agent definitions"}},
            "/api/rag/answer": {"post": {"summary": "RAG answer"}},
        }
    }
    return jsonify(spec)

# ==================== END OF CORE PART 10/10 (2/3) ====================
# ==================== CORE PART 10/10 (3/3) ====================
# ===== BLOCK: WORKERS (DLQ, EXECUTORS, SCHEDULERS) =====
# Workers globals
_workers_lock = threading.Lock()
_workers_started = False
_workers_last_tick: Dict[str, float] = {"webhook": 0.0, "maintenance": 0.0, "calendar_reminders": 0.0}

# DLQ ensure
_DLQ_READY = False
def _ensure_dlq_tables():
    """Create DLQ tables for webhook and ai_jobs if not exists (idempotent)."""
    global _DLQ_READY
    if _DLQ_READY:
        return
    try:
        if DIALECT == "postgres":
            exec_db("""
CREATE TABLE IF NOT EXISTS webhook_dlq (
    id INTEGER PRIMARY KEY,
    webhook_id INTEGER,
    event TEXT,
    payload_json TEXT,
    last_error TEXT,
    attempts INTEGER,
    dead_at TIMESTAMP WITHOUT TIME ZONE
)
""", ())
            exec_db("""
CREATE TABLE IF NOT EXISTS ai_jobs_dlq (
    id INTEGER PRIMARY KEY,
    org_id INTEGER,
    user_id INTEGER,
    job_type TEXT,
    entity_type TEXT,
    entity_id INTEGER,
    input_text TEXT,
    error TEXT,
    attempts INTEGER,
    dead_at TIMESTAMP WITHOUT TIME ZONE
)
""", ())
        else:
            exec_db("""
CREATE TABLE IF NOT EXISTS webhook_dlq (
    id INTEGER PRIMARY KEY,
    webhook_id INTEGER,
    event TEXT,
    payload_json TEXT,
    last_error TEXT,
    attempts INTEGER,
    dead_at TEXT
)
""", ())
            exec_db("""
CREATE TABLE IF NOT EXISTS ai_jobs_dlq (
    id INTEGER PRIMARY KEY,
    org_id INTEGER,
    user_id INTEGER,
    job_type TEXT,
    entity_type TEXT,
    entity_id INTEGER,
    input_text TEXT,
    error TEXT,
    attempts INTEGER,
    dead_at TEXT
)
""", ())
        _DLQ_READY = True
    except Exception as e:
        log("WARN", "DLQ tables ensure failed", error=str(e))

def _move_to_dlq(kind: str, row: dict, error: str, attempts: int):
    """Store failed item to DLQ for inspection."""
    _ensure_dlq_tables()
    try:
        if kind == "webhook":
            exec_db(
                "INSERT OR REPLACE INTO webhook_dlq (id, webhook_id, event, payload_json, last_error, attempts, dead_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (row["id"], row.get("webhook_id"), row.get("event"), row.get("payload_json"), (error or "")[:500], attempts, utc_now())
            )
        elif kind == "ai_job":
            exec_db(
                "INSERT OR REPLACE INTO ai_jobs_dlq (id, org_id, user_id, job_type, entity_type, entity_id, input_text, error, attempts, dead_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row["id"], row.get("org_id"), row.get("user_id"), row.get("job_type"), row.get("entity_type"), row.get("entity_id"),
                 row.get("input_text") or "", (error or "")[:500], attempts, utc_now())
            )
    except Exception as e:
        log("WARN", "move_to_dlq failed", error=str(e))

def _webhook_deliver_once():
    """Deliver pending webhooks with backoff and DLQ after max attempts."""
    _ensure_dlq_tables()
    now_ts = utc_now()
    rows = query_db(
        "SELECT wq.id, wq.webhook_id, wq.event, wq.payload_json, wq.status, wq.attempts, wq.next_try_at, w.url, w.secret "
        "FROM webhook_queue wq JOIN webhooks w ON wq.webhook_id=w.id "
        "WHERE wq.status='pending' AND (wq.next_try_at IS NULL OR wq.next_try_at <= ?) "
        "ORDER BY wq.id ASC LIMIT 10",
        (now_ts,)
    ) or []
    if _rq is None:
        return
    for t in rows:
        try:
            payload_json = t["payload_json"]
            headers = {"Content-Type": "application/json"}
            if t.get("secret"):
                sig = hmac.new((t["secret"] or "").encode(), (payload_json or "").encode(), hashlib.sha256).hexdigest()
                headers["X-Webhook-Signature"] = f"sha256={sig}"
            headers["X-Webhook-Event"] = t.get("event") or ""
            r = _rq.post(t["url"], data=payload_json, headers=headers, timeout=10)
            if r.status_code in (200, 201, 202, 204):
                exec_db("UPDATE webhook_queue SET status='delivered' WHERE id=?", (t["id"],))
            else:
                raise RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            attempts = int(t.get("attempts") or 0) + 1
            base_delay = min(3600, int((2 ** min(6, attempts)) * 5))
            jitter = int(uuid.uuid4().int % 7)
            delay = base_delay + jitter
            next_try_dt = datetime.utcnow() + timedelta(seconds=delay)
            next_try = next_try_dt.strftime("%Y-%m-%d %H:%M:%S")
            if attempts >= 10:
                exec_db("UPDATE webhook_queue SET status='failed', attempts=?, last_error=? WHERE id=?", (attempts, str(e)[:500], t["id"]))
                _move_to_dlq("webhook", t, str(e), attempts)
            else:
                exec_db("UPDATE webhook_queue SET attempts=?, next_try_at=?, last_error=? WHERE id=?", (attempts, next_try, str(e)[:500], t["id"]))

def _email_sequence_worker():
    """Send next step emails for active enrollments when due (best-effort)."""
    rows = query_db(
        "SELECT e.id, e.email, e.sequence_id, e.current_step, e.last_sent_at, s.step_num, s.delay_hours, s.subject, s.body_template "
        "FROM sequence_enrollments e "
        "JOIN sequence_steps s ON s.sequence_id=e.sequence_id AND s.step_num=e.current_step + 1 "
        "WHERE e.status='active' "
        "ORDER BY e.id ASC LIMIT 100"
    ) or []
    for r in rows:
        try:
            due = True
            if r.get("last_sent_at") and r.get("delay_hours") is not None:
                last = datetime.strptime(ensure_iso_datetime(r["last_sent_at"]), "%Y-%m-%d %H:%M:%S")
                due = (datetime.utcnow() - last) >= timedelta(hours=int(r["delay_hours"] or 0))
            if not due:
                continue
            subj = r.get("subject") or "Update"
            body = (r.get("body_template") or "").replace("{{ email }}", r.get("email") or "")
            _send_mail_helper(r["email"], subj, body)
            exec_db("UPDATE sequence_enrollments SET current_step=current_step+1, last_sent_at=? WHERE id=?", (utc_now(), r["id"]))
        except Exception as e:
            log("WARN", "email sequence send failed", error=str(e))

def _ai_job_process_pending():
    """Process queued AI jobs with error handling and DLQ after max attempts."""
    _ensure_dlq_tables()
    jobs = query_db("SELECT * FROM ai_jobs WHERE status='pending' ORDER BY id ASC LIMIT 5") or []
    for j in jobs:
        try:
            exec_db("UPDATE ai_jobs SET status='processing' WHERE id=?", (j["id"],))
            result = ""
            jtype = j.get("job_type")
            if jtype == "summarize":
                msgs = query_db("SELECT body, sender_type, created_at FROM inbox_messages WHERE thread_id=? ORDER BY created_at ASC LIMIT 100", (j.get("entity_id"),)) or []
                context = "\n".join([f"[{m['sender_type']}] {m['body']}" for m in msgs])
                ctx = truncate_for_ai_context(context, 6000)
                result = ai_provider_call(f"Суммируй разговор кратко, тезисно, на русском:\n\n{ctx}", system="Ты помощник по суммированию диалогов.")
            elif jtype == "draft_reply":
                msgs = query_db("SELECT body, sender_type FROM inbox_messages WHERE thread_id=? ORDER BY created_at DESC LIMIT 10", (j.get("entity_id"),)) or []
                context = "\n".join([f"[{m['sender_type']}] {m['body']}" for m in reversed(list(msgs))])
                ctx = truncate_for_ai_context(context, 4000)
                result = ai_provider_call(f"Сформируй профессиональный ответ на русском:\n\n{ctx}", system="Вежливый тон, фактологично.", temperature=0.4, max_tokens=400)
            elif jtype == "autotag":
                msgs = query_db("SELECT body FROM inbox_messages WHERE thread_id=? ORDER BY created_at DESC LIMIT 30", (j.get("entity_id"),)) or []
                context = truncate_for_ai_context(" ".join([(m.get("body") or "") for m in msgs]), 2000)
                tags_text = ai_provider_call(f"Выдели 3-5 коротких тэгов через запятую:\n\n{context}", temperature=0.1, max_tokens=60)
                tags = [t.strip() for t in (tags_text or "").split(",") if t.strip()][:5]
                exec_db("UPDATE inbox_threads SET tags_csv=? WHERE id=?", (",".join(tags), int(j.get("entity_id") or 0)))
                result = ",".join(tags)
            else:
                raise ValueError("Unknown job type")
            exec_db("UPDATE ai_jobs SET status='completed', output_text=?, completed_at=? WHERE id=?", (result, utc_now(), j["id"]))
        except Exception as e:
            attempts = int(j.get("attempts") or 0) + 1
            if attempts >= 10:
                exec_db("UPDATE ai_jobs SET status='failed', error=?, attempts=? WHERE id=?", (str(e)[:500], attempts, j["id"]))
                _move_to_dlq("ai_job", j, str(e), attempts)
            else:
                exec_db("UPDATE ai_jobs SET status='failed', error=?, attempts=? WHERE id=?", (str(e)[:500], attempts, j["id"]))

def _wf_execute_once():
    """Minimal workflow executor placeholder (idempotent switch to processing then to completed)."""
    rows = query_db("SELECT * FROM workflow_tasks WHERE status='pending' AND (scheduled_at IS NULL OR scheduled_at <= ?) ORDER BY id ASC LIMIT 10", (utc_now(),)) or []
    for t in rows:
        try:
            rc = exec_db_affect("UPDATE workflow_tasks SET status='processing', started_at=? WHERE id=? AND status='pending'", (utc_now(), t["id"]))
            if rc == 0:
                continue
            # Placeholder for node execution (future)
            exec_db("UPDATE workflow_tasks SET status='completed', completed_at=? WHERE id=?", (utc_now(), t["id"]))
        except Exception as e:
            exec_db("UPDATE workflow_tasks SET status='failed', error=?, completed_at=? WHERE id=?", (str(e)[:500], utc_now(), t["id"]))

def _process_task_reminders():
    """Push reminders to assignees (SSE + optional notify shim)."""
    rows = query_db(
        "SELECT r.id, r.task_id, r.user_id, r.message, t.title FROM task_reminders r JOIN tasks t ON r.task_id=t.id WHERE r.sent=0 AND r.remind_at <= ? LIMIT 100",
        (utc_now(),)
    ) or []
    for r in rows:
        try:
            payload = {"reminder_id": r["id"], "task_id": r["task_id"], "task_title": r["title"], "message": r.get("message") or f"Напоминание: {r['title']}"}
            sse_push(int(r["user_id"]), "task.reminder", payload)
            try:
                # optional shim from CORE 6/10
                if "notify" in globals() and callable(globals().get("notify")):
                    notify(int(r["user_id"]), f"Напоминание по задаче #{r['task_id']}", r.get("message") or r["title"], kind="info")  # type: ignore
            except Exception:
                pass
            exec_db("UPDATE task_reminders SET sent=1 WHERE id=?", (r["id"],))
        except Exception as e:
            log("WARN", "reminder failed", error=str(e))

def webhook_worker():
    log("INFO", "webhook_worker started")
    with app.app_context():
        _workers_last_tick["webhook"] = time.time()
        while not _shutdown_event.is_set():
            try:
                _webhook_deliver_once()
            except Exception as e:
                log("ERROR", "webhook_worker error", error=str(e))
            _workers_last_tick["webhook"] = time.time()
            _shutdown_event.wait(5)
    log("INFO", "webhook_worker stopped")

def maintenance_worker():
    log("INFO", "maintenance_worker started")
    with app.app_context():
        tick = 0
        _workers_last_tick["maintenance"] = time.time()
        while not _shutdown_event.is_set():
            try:
                # cleanup old rows
                cutoff30 = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
                cutoff365 = (datetime.utcnow() - timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
                exec_db("DELETE FROM webhook_queue WHERE status IN ('delivered','failed') AND created_at < ?", (cutoff30,))
                exec_db("DELETE FROM audit_logs WHERE created_at < ?", (cutoff365,))

                _process_task_reminders()
                _wf_execute_once()
                _ai_job_process_pending()
                _email_sequence_worker()

                if tick % 10 == 0:
                    _mv_refresh_dashboard()

                # Renew leader TTL to avoid split-brain (every ~2 minutes)
                if tick % 2 == 0:
                    r = get_redis()
                    if r:
                        try:
                            _redis_cb.call(r.expire, "workers:leader", 120)
                        except Exception:
                            pass

                if DIALECT == "sqlite":
                    wal_checkpoint_if_needed()

                if tick % 5 == 0:
                    _ratelimit_housekeeping()

                # L1 cache cleanup
                _global_cache.cleanup()
            except Exception as e:
                log("ERROR", "maintenance_worker error", error=str(e))
            tick += 1
            _workers_last_tick["maintenance"] = time.time()
            _shutdown_event.wait(60)
    log("INFO", "maintenance_worker stopped")

def calendar_reminders_worker():
    log("INFO", "calendar_reminders_worker started")
    with app.app_context():
        _workers_last_tick["calendar_reminders"] = time.time()
        while not _shutdown_event.is_set():
            try:
                # Send reminders due in next 5 minutes (buffer)
                now_dt = datetime.utcnow()
                window_end = now_dt + timedelta(minutes=5)
                win_s = window_end.strftime("%Y-%m-%d %H:%M:%S")
                rows = query_db(
                    "SELECT r.id, r.event_id, r.user_id, r.minutes_before, e.title, e.start_time "
                    "FROM event_reminders r JOIN calendar_events e ON r.event_id=e.id "
                    "WHERE r.status='pending' AND r.reminder_time <= ? ORDER BY r.reminder_time ASC LIMIT 200",
                    (win_s,)
                ) or []
                for r in rows:
                    try:
                        minutes_left = max(0, int((CalendarService._dt_from_iso(r["start_time"]) - now_dt).total_seconds() // 60))
                        sse_push(int(r["user_id"]), "calendar.reminder", {"event_id": r["event_id"], "minutes_left": minutes_left, "event": {"title": r["title"]}})
                        exec_db("UPDATE event_reminders SET status='sent', sent_at=? WHERE id=?", (utc_now(), r["id"]))
                    except Exception as e:
                        attempts_row = query_db("SELECT attempts FROM event_reminders WHERE id=?", (r["id"],), one=True) or {"attempts": 0}
                        attempts = int(attempts_row.get("attempts") or 0) + 1
                        if attempts >= 3:
                            exec_db("UPDATE event_reminders SET status='failed', attempts=?, last_error=? WHERE id=?", (attempts, str(e)[:200], r["id"]))
                        else:
                            exec_db("UPDATE event_reminders SET attempts=?, last_error=? WHERE id=?", (attempts, str(e)[:200], r["id"]))
            except Exception as e:
                log("ERROR", "calendar_reminders_worker error", error=str(e))
            _workers_last_tick["calendar_reminders"] = time.time()
            _shutdown_event.wait(60)
    log("INFO", "calendar_reminders_worker stopped")

def start_workers_once():
    global _workers_started
    with _workers_lock:
        if _workers_started:
            return
        # single-leader guard via Redis (optional)
        leader_ok = True
        r = get_redis()
        if r:
            try:
                leader_ok = bool(_redis_cb.call(r.set, "workers:leader", "1", nx=True, ex=120))
            except Exception:
                leader_ok = True
        if not leader_ok:
            log("INFO", "Workers not started in this process (leader active elsewhere)")
            _workers_started = True
            return
        threading.Thread(target=webhook_worker, daemon=True, name="webhook_worker").start()
        threading.Thread(target=maintenance_worker, daemon=True, name="maintenance_worker").start()
        threading.Thread(target=calendar_reminders_worker, daemon=True, name="calendar_reminders_worker").start()
        _workers_started = True
        log("INFO", "Background workers started")

# ===== BLOCK: SYSTEM ENDPOINTS (METRICS/HEALTH/READY) =====
def db_health_check() -> bool:
    """Simple DB health probe with 3 retries."""
    for attempt in range(3):
        try:
            _ = query_db("SELECT 1 AS x", (), one=True)
            return True
        except Exception:
            time.sleep(0.5 * (attempt + 1))
    return False

def check_workers_alive() -> Dict[str, bool]:
    now = time.time()
    return {k: (now - v < 300) for k, v in _workers_last_tick.items()}

@app.route("/metrics")
def metrics():
    def _esc_label(v: str) -> str:
        s = str(v)
        s = s.replace("\\", "\\\\").replace("\"", "\\\"")
        return s

    out = []
    with _metrics_lock:
        # requests total
        out.append("# HELP crm_requests_total Total HTTP requests")
        out.append("# TYPE crm_requests_total counter")
        out.append(f"crm_requests_total {_metrics.get('requests_total', 0)}")

        # errors total
        out.append("# HELP crm_errors_total Total errors")
        out.append("# TYPE crm_errors_total counter")
        out.append(f"crm_errors_total {_metrics.get('errors_total', 0)}")

        # by endpoint
        out.append("# HELP crm_requests_by_endpoint Requests by endpoint")
        out.append("# TYPE crm_requests_by_endpoint counter")
        for key, count in (_metrics.get("requests_by_endpoint") or {}).items():
            labels = dict(key) if isinstance(key, frozenset) else {}
            endpoint = _esc_label(labels.get("endpoint", "unknown"))
            out.append(f'crm_requests_by_endpoint{{endpoint="{endpoint}"}} {count}')

        # by status
        out.append("# HELP crm_requests_by_status Requests by HTTP status")
        out.append("# TYPE crm_requests_by_status counter")
        for key, count in (_metrics.get("requests_by_status") or {}).items():
            labels = dict(key) if isinstance(key, frozenset) else {}
            status = _esc_label(labels.get("status", "0"))
            out.append(f'crm_requests_by_status{{status="{status}"}} {count}')

        # rate limit exceeded
        out.append("# HELP crm_rate_limit_exceeded_total Rate limit exceeded events")
        out.append("# TYPE crm_rate_limit_exceeded_total counter")
        out.append(f"crm_rate_limit_exceeded_total {_metrics.get('rate_limit_exceeded', 0)}")

        # SSE drops
        out.append("# HELP crm_sse_dropped_total Dropped SSE messages")
        out.append("# TYPE crm_sse_dropped_total counter")
        out.append(f"crm_sse_dropped_total {_metrics.get('sse_dropped_total', 0)}")

        # SSE connections gauge (by user)
        out.append("# HELP crm_sse_connections Number of active SSE connections per user")
        out.append("# TYPE crm_sse_connections gauge")
        try:
            with _sse_lock:
                for uid, qs in _sse_queues.items():
                    out.append(f'crm_sse_connections{{user="{int(uid)}"}} {len(qs)}')
        except Exception:
            pass

    return Response("\n".join(out), mimetype="text/plain")

@app.route("/health")
def health():
    status = {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "checks": {}}
    status["checks"]["database"] = "ok" if db_health_check() else "fail"
    r = get_redis()
    if r:
        try:
            _redis_cb.call(r.ping)
            status["checks"]["redis"] = "ok"
        except Exception:
            status["checks"]["redis"] = "fail"
    else:
        status["checks"]["redis"] = "skip"
    status["checks"]["workers"] = "ok" if all(check_workers_alive().values()) else "degraded"
    overall_healthy = (status["checks"]["database"] == "ok")
    status["status"] = "healthy" if overall_healthy else "degraded"
    return jsonify(status), 200 if overall_healthy else 503

@app.route("/readyz")
def readyz():
    try:
        db_ok = db_health_check()
        r = get_redis()
        red_ok = True
        if r:
            try:
                _redis_cb.call(r.ping)
            except Exception:
                red_ok = False
        live = check_workers_alive()
        # Be lenient unless READY_REQUIRE_WORKERS=true
        require_workers = os.getenv("READY_REQUIRE_WORKERS", "false").lower() == "true"
        ready = db_ok and red_ok and (any(live.values()) or not require_workers)
        return jsonify(ok=ready, ready=ready, workers=live)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 503
# ==================== END OF CORE PART 10/10 (3/3) ====================
# ===== START OF STYLES PART 1/10 =====
# coding: utf-8
# ==================== STYLES PART 1/10 ====================
# ===== BLOCK: TEMPLATES =====

DESIGN_SYSTEM_CSS = r"""
:root{
  --bg:#ffffff;--fg:#111827;--surface:#f7f7f7;--panel:#f3f4f6;--panel-strong:#e5e7eb;--border:#e5e7eb;
  --muted:#6b7280;--primary:#2563eb;--accent:#22c55e;--ok:#10b981;--info:#0ea5e9;--warn:#f59e0b;--err:#ef4444;
  --focus-ring:0 0 0 3px rgba(34,197,94,.35);
  --radius-1:6px;--radius-2:10px;--radius-3:14px;--shadow-sm:0 1px 2px rgba(0,0,0,.06);--shadow-md:0 4px 12px rgba(0,0,0,.08);
  --z-nav:100;--z-modal:1000;--z-toast:2000;--z-palette:3000;--z-notif:3500;
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif;background:var(--bg);color:var(--fg);line-height:1.6}
a{color:var(--primary);text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:0 16px}
.topbar{position:sticky;top:0;background:var(--surface);border-bottom:1px solid var(--border);z-index:var(--z-nav)}
.topbar-inner{display:flex;align-items:center;gap:12px;padding:10px 0}
.topbar .brand{font-weight:800;display:inline-flex;align-items:center;gap:8px}
.nav{display:flex;gap:8px;overflow:auto;padding:8px 0;margin:0;list-style:none}
.nav a{display:inline-flex;gap:8px;align-items:center;padding:8px 12px;border:1px solid transparent;border-radius:10px;color:inherit;white-space:nowrap}
.nav a:hover{background:var(--panel)}
.nav a.active{background:var(--accent);color:#052e16}
.input,.select,textarea.input{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:#fff;color:inherit}
.input:focus,.select:focus,textarea.input:focus{outline:none;box-shadow:var(--focus-ring);border-color:var(--accent)}
.button{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:8px;border:1px solid transparent;background:var(--primary);color:#fff;cursor:pointer}
.button.secondary{background:var(--accent);color:#052e16}
.button.ghost{background:transparent;border-color:var(--border);color:inherit}
.button.warn{background:var(--warn);color:#111}
.button.small{padding:6px 10px;font-size:.9rem}
.card{background:#fff;border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow-sm);padding:14px}
.smart{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border-radius:999px;background:var(--panel)}
.badge.ok{background:#d1fae5;color:#065f46}
.badge.err{background:#fee2e2;color:#991b1b}
.badge.warn{background:#fef3c7;color:#92400e}
.badge.info{background:#e0f2fe;color:#075985}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:10px;border-bottom:1px solid var(--border);text-align:left}
.table thead{background:var(--panel)}
.toast{position:fixed;right:20px;bottom:20px;z-index:var(--z-toast);background:#111;color:#fff;padding:10px 12px;border-radius:8px;box-shadow:var(--shadow-md)}
#notifBell{position:relative}
.dot{position:absolute;top:-6px;right:-6px;min-width:18px;height:18px;border-radius:50%;background:var(--err);color:#fff;display:flex;align-items:center;justify-content:center;font-size:12px}
#notifDrawer{position:fixed;top:56px;right:16px;width:360px;max-height:70vh;overflow:auto;background:#fff;border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow-md);display:none;z-index:var(--z-notif)}
#notifDrawer.show{display:block}
.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:var(--z-modal);align-items:center;justify-content:center;padding:16px}
.modal-backdrop.show{display:flex}
.modal{background:#fff;border:1px solid var(--border);border-radius:12px;max-width:760px;width:100%;max-height:90vh;overflow:auto;box-shadow:var(--shadow-md);padding:20px}
.kbd{font-family:ui-monospace,Menlo,Monaco,Consolas,monospace;background:var(--panel);padding:2px 6px;border-radius:6px;border:1px solid var(--border)}
.muted{color:var(--muted)}
"""

BASE_JS = r"""
(function(){
  // utils
  window.ESC = function(s){ if(s==null) return ''; const d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; };
  window.toast = function(msg, dur){ const t=document.createElement('div'); t.className='toast'; t.textContent=msg; document.body.appendChild(t); setTimeout(()=>t.remove(), dur||2800); };

  // CSRF
  window.CSRF = (document.querySelector('meta[name="csrf-token"]')||{}).content || '';

  // Idempotency-Key (client generator for sensitive POST operations)
  window.IDK = function(){
    try{ return crypto.randomUUID(); }catch(e){ return String(Date.now())+'-'+Math.random().toString(16).slice(2); }
  };

  // Notifications store
  const NOTIF = {
    key(){ return 'notif_'+(window.USER_ID||0); },
    all(){ try{ return JSON.parse(localStorage.getItem(NOTIF.key())||'[]'); }catch(e){ return []; } },
    push(ev){ try{ const a=NOTIF.all(); a.unshift(ev); while(a.length>500) a.pop(); localStorage.setItem(NOTIF.key(), JSON.stringify(a)); NOTIF.render(); }catch(e){} },
    render(){
      const box=document.getElementById('notifList'); const badge=document.getElementById('notifDot');
      if(!box||!badge) return;
      const items=NOTIF.all(); const unread=items.filter(x=>!x.read).length;
      badge.textContent = String(unread||0);
      badge.style.display = unread?'flex':'none';
      box.innerHTML = items.slice(0,100).map(x => (
        '<div class="card" style="margin:6px 0;"><div style="font-weight:700;">'+ESC(x.title||'')+'</div>' +
        '<div>'+ESC(x.body||'')+(x.link?' — <a href="'+ESC(x.link)+'">Открыть</a>':'')+'</div>' +
        '<div class="badge info" style="margin-top:6px;">'+ESC(x.kind||'info')+'</div></div>'
      )).join('');
    }
  };
  window.NOTIF = NOTIF;

  // SSE
  function sseConnect(){
    if(!window.EventSource) return;
    try{
      const es = new EventSource('/sse');
      const handled = [
        'notify.message','notify.center','twin.insight','task.created','task.updated','task.status_changed',
        'task.reminder','deal.created','deal.updated','deal.stage_changed','chat.message','thread.message',
        'call.started','call.incoming','collab.change','calendar.event.created','calendar.event.updated','calendar.reminder',
        'meeting.notes_ready','agent.approval_requested'
      ];
      handled.forEach(ev=>{
        es.addEventListener(ev, function(e){
          try{
            const data = JSON.parse(e.data||'{}');
            if(ev==='notify.center'){
              NOTIF.push({kind:data.kind||'info', title:data.title||'Уведомление', body:data.body||'', link:data.link||null, ts:data.ts||new Date().toLocaleString(), read:false});
            } else if (ev==='twin.insight'){
              NOTIF.push({kind:'insight', title:data.title||'Insight', body:data.message||'', link:null, ts:data.ts||new Date().toLocaleString(), read:false});
            } else if (ev==='calendar.reminder'){
              NOTIF.push({kind:'calendar', title:'Напоминание о событии', body:(data.event&&data.event.title)||'', link:'/calendar', ts:new Date().toLocaleString(), read:false});
            } else {
              NOTIF.push({kind:'event', title:ev, body:JSON.stringify(data), ts:new Date().toLocaleString(), read:false});
            }
          }catch(er){}
        });
      });
    }catch(e){}
  }

  // Drawer and palette
  document.addEventListener('DOMContentLoaded', function(){
    window.USER_ID = Number((document.body||{}).getAttribute('data-userid')||0);
    sseConnect();
    const bell=document.getElementById('notifBell');
    const drawer=document.getElementById('notifDrawer');
    bell && bell.addEventListener('click', ()=>{ drawer && drawer.classList.toggle('show'); NOTIF.render(); });
    document.addEventListener('click', (e)=>{ if(!drawer) return; if(drawer.classList.contains('show')){ const p=e.target.closest('#notifDrawer'); const b=e.target.closest('#notifBell'); if(!p && !b) drawer.classList.remove('show'); } });
    NOTIF.render();
  });
})();
"""

LAYOUT_TMPL = """
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <meta name="csrf-token" content="{{ session.get('csrf_token','') }}">
  <title>{% block title %}Singularity CRM{% endblock %}</title>
  <style>{{ css }}</style>
</head>
<body data-userid="{{ user.id if user else 0 }}">
  {% if user %}
  <div class="topbar">
    <div class="container topbar-inner">
      <a class="brand" href="/">✨ Singularity</a>
      <form action="/search" method="get" style="margin-left:12px;flex:1;max-width:420px;">
        <input class="input" name="q" placeholder="Поиск… (Ctrl+K)">
      </form>
      <a class="button ghost small" href="/profile">{{ user.username }}</a>
      {% if user.role == 'admin' %}
      <a class="button ghost small" href="/settings">Настройки</a>
      {% endif %}
      <div id="notifBell" class="button ghost small" style="position:relative;">🔔<span id="notifDot" class="dot" style="display:none;">0</span></div>
      <form method="post" action="/logout" style="margin:0 0 0 4px;">
        <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token','') }}">
        <button class="button small" type="submit">Выход</button>
      </form>
    </div>
    <nav class="container">
      <ul class="nav">
        <li><a href="/" class="{{ 'active' if request.path=='/' else '' }}">Главная</a></li>
        <li><a href="/inbox" class="{{ 'active' if request.path.startswith('/inbox') or request.path.startswith('/thread') else '' }}">Inbox</a></li>
        <li><a href="/tasks" class="{{ 'active' if request.path.startswith('/tasks') or request.path.startswith('/task') else '' }}">Задачи</a></li>
        <li><a href="/deals" class="{{ 'active' if request.path.startswith('/deals') or request.path.startswith('/deal') else '' }}">Сделки</a></li>
        <li><a href="/clients" class="{{ 'active' if request.path.startswith('/clients') or request.path.startswith('/client') else '' }}">Клиенты</a></li>
        <li><a href="/calls" class="{{ 'active' if request.path.startswith('/calls') else '' }}">Звонки</a></li>
        <li><a href="/chat" class="{{ 'active' if request.path.startswith('/chat') else '' }}">Чат</a></li>
        <li><a href="/documents" class="{{ 'active' if request.path.startswith('/documents') or request.path.startswith('/document') else '' }}">Документы</a></li>
        <li><a href="/analytics" class="{{ 'active' if request.path.startswith('/analytics') else '' }}">Аналитика</a></li>
        <li><a href="/digital_twin" class="{{ 'active' if request.path.startswith('/digital_twin') else '' }}">Digital Twin</a></li>
        <li><a href="/agents" class="{{ 'active' if request.path.startswith('/agents') else '' }}">Агенты</a></li>
        <li><a href="/calendar" class="{{ 'active' if request.path.startswith('/calendar') else '' }}">Календарь</a></li>
        <li><a href="/payroll" class="{{ 'active' if request.path.startswith('/payroll') else '' }}">Зарплата</a></li>
        <li><a href="/settings" class="{{ 'active' if request.path.startswith('/settings') else '' }}">Настройки</a></li>
      </ul>
    </nav>
  </div>
  {% endif %}
  <main class="container" style="padding:16px 0;">
    {% block content %}{% endblock %}
  </main>
  <!-- Notifications Drawer -->
  <div id="notifDrawer">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px;border-bottom:1px solid var(--border);position:sticky;top:0;background:#fff;">
      <div style="font-weight:800;">Уведомления</div>
      <div>
        <button class="button ghost small" onclick="NOTIF && NOTIF.render()">Обновить</button>
        <button class="button ghost small" onclick="try{ localStorage.removeItem('notif_'+(window.USER_ID||0)); }catch(e){}; NOTIF && NOTIF.render();">Очистить</button>
      </div>
    </div>
    <div id="notifList" style="padding:10px;"></div>
  </div>
  <script nonce="{{ csp_nonce }}">{{ js }}</script>
</body>
</html>
"""

DASHBOARD_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", """
{% block content %}
<div class="smart" style="margin-bottom:12px;">
  <div style="font-weight:800;font-size:18px;">Добро пожаловать, {{ user.username }}!</div>
  <div class="badge info" style="margin-top:8px;">Используйте <span class="kbd">Ctrl</span>+<span class="kbd">K</span> для командной палитры</div>
</div>
<div class="card" style="margin-bottom:12px;">
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;">
    <div class="smart">
      <div style="font-weight:700;">📋 Задачи</div>
      <div class="badge info">Открытые: {{ open_tasks }}</div>
      <div class="badge warn" style="margin-left:6px;">Мои: {{ my_tasks }}</div>
      <div style="margin-top:8px;display:flex;gap:8px;">
        <a class="button secondary" href="/tasks">Перейти</a>
        <a class="button ghost" href="/tasks?f=overdue">Просроченные</a>
      </div>
    </div>
    <div class="smart">
      <div style="font-weight:700;">💼 Сделки</div>
      <div class="badge ok">Активных: {{ open_deals }}</div>
      <div style="margin-top:8px;display:flex;gap:8px;">
        <a class="button secondary" href="/deals">Канбан</a>
        <a class="button ghost" href="/clients">Клиенты</a>
      </div>
    </div>
    <div class="smart">
      <div style="font-weight:700;">🧠 Next Best Actions</div>
      <ul style="padding-left:18px;margin:6px 0 0 0;">
        {% for a in nba %}<li>{{ a.text }}</li>{% else %}<li class="muted">Нет рекомендаций</li>{% endfor %}
      </ul>
      <div style="margin-top:8px;"><a class="button ghost" href="/digital_twin">Digital Twin</a></div>
    </div>
  </div>
</div>
{% endblock %}
""")

PROFILE_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", """
{% block content %}
<h2 style="margin:0 0 10px 0;">Профиль</h2>
<div style="display:grid;grid-template-columns:1fr 320px;gap:12px;">
  <div class="card">
    <h3 style="margin:0 0 8px 0;">Основная информация</h3>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div><label class="muted">Логин</label><div>{{ user.username }}</div></div>
      <div><label class="muted">Роль</label><div>{{ user.role }}</div></div>
      <div><label class="muted">Email</label><input class="input" id="email" value="{{ user.email or '' }}"></div>
      <div><label class="muted">Телефон</label><input class="input" id="phone" value="{{ user.phone or '' }}"></div>
      <div><label class="muted">Часовой пояс</label><input class="input" id="timezone" value="{{ user.timezone or 'UTC' }}"></div>
      <div>
        <label class="muted">Язык</label>
        <select class="select" id="locale">
          <option value="ru" {% if user.locale=='ru' %}selected{% endif %}>Русский</option>
          <option value="en" {% if user.locale=='en' %}selected{% endif %}>English</option>
        </select>
      </div>
      <div>
        <label class="muted">Тема</label>
        <select class="select" id="theme">
          <option value="light" {% if user.theme=='light' %}selected{% endif %}>Светлая</option>
          <option value="dark" {% if user.theme=='dark' %}selected{% endif %}>Тёмная</option>
        </select>
      </div>
    </div>
    <div style="margin-top:10px;"><button class="button" id="btnSaveProfile">Сохранить</button></div>
  </div>
  <div class="card">
    <h3 style="margin:0 0 8px 0;">Аватар</h3>
    <div style="text-align:center;">
      {% if user.avatar_url %}
      <img src="{{ user.avatar_url }}" alt="Avatar" style="width:120px;height:120px;object-fit:cover;border-radius:50%;border:1px solid var(--border);">
      {% else %}
      <div style="width:120px;height:120px;border-radius:50%;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:48px;margin:0 auto;">{{ (user.username or 'U')[0] }}</div>
      {% endif %}
      <input type="file" id="avatarFile" accept="image/*" style="display:none;">
      <div style="margin-top:8px;"><button class="button secondary" id="btnAvatarPick">Загрузить</button></div>
    </div>
    <div style="margin-top:12px;">
      <h4 style="margin:0 0 6px 0;">Смена пароля</h4>
      <input class="input" type="password" id="currentPassword" placeholder="Текущий пароль">
      <input class="input" type="password" id="newPassword" placeholder="Новый пароль (минимум 12 символов)" style="margin-top:6px;">
      <div style="margin-top:8px;"><button class="button ghost" id="btnChangePassword">Изменить пароль</button></div>
    </div>
  </div>
</div>
<script nonce="{{ csp_nonce }}">
(function(){
  const $=id=>document.getElementById(id);
  $('btnSaveProfile')?.addEventListener('click', async ()=>{
    const data={ email:$('email').value, phone:$('phone').value, timezone:$('timezone').value, locale:$('locale').value, theme:$('theme').value };
    try{
      const r=await fetch('/api/profile', {method:'PATCH', headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'}, body:JSON.stringify(data)});
      const j=await r.json();
      if(j.ok) toast('Сохранено'); else toast(j.error||'Ошибка');
    }catch(e){ toast('Ошибка сети'); }
  });
  $('btnAvatarPick')?.addEventListener('click', ()=> $('avatarFile')?.click());
  $('avatarFile')?.addEventListener('change', async (e)=>{
    const f=e.target.files[0]; if(!f) return;
    const fd=new FormData(); fd.append('file', f);
    try{
      const r=await fetch('/api/profile/avatar',{method:'POST',headers:{'X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:fd});
      const j=await r.json();
      if(j.ok){ toast('Аватар обновлен'); location.reload(); } else toast(j.error||'Ошибка');
    }catch(e){ toast('Ошибка загрузки'); }
  });
  $('btnChangePassword')?.addEventListener('click', async ()=>{
    const cur=$('currentPassword').value, np=$('newPassword').value;
    if(!cur||!np) return toast('Заполните оба поля');
    try{
      const r=await fetch('/api/profile/password',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:JSON.stringify({current_password:cur,new_password:np})});
      const j=await r.json();
      if(j.ok){ toast('Пароль изменен'); $('currentPassword').value=''; $('newPassword').value=''; } else toast(j.error||'Ошибка');
    }catch(e){ toast('Ошибка сети'); }
  });
})();
</script>
{% endblock %}
""")

# ----- Page routes: index (dashboard) and profile -----
@app.route("/")
@_login_required
def index():
    user = g.user
    # FIX: COUNT(*) for Postgres compatibility
    open_tasks = query_db("SELECT COUNT(*) AS c FROM tasks WHERE org_id=? AND status NOT IN ('done','cancelled')", (user["org_id"],), one=True)["c"] or 0
    my_tasks = query_db("SELECT COUNT(*) AS c FROM tasks WHERE org_id=? AND assignee_id=? AND status NOT IN ('done','cancelled')", (user["org_id"], user["id"]), one=True)["c"] or 0
    open_deals = query_db("SELECT COUNT(*) AS c FROM deals WHERE org_id=? AND status='open'", (user["org_id"],), one=True)["c"] or 0
    try:
        nba = BusinessTwin(user["org_id"]).next_best_actions(limit=3)  # type: ignore
    except Exception:
        nba = []
    return render_template_string(DASHBOARD_TMPL, user=user, open_tasks=int(open_tasks), my_tasks=int(my_tasks),
                                  open_deals=int(open_deals), nba=nba, css=DESIGN_SYSTEM_CSS, js=BASE_JS,
                                  csp_nonce=g.get("csp_nonce",""))

@app.route("/profile")
@_login_required
def profile_page():
    user = g.user
    return render_template_string(PROFILE_TMPL, user=user, css=DESIGN_SYSTEM_CSS, js=BASE_JS, csp_nonce=g.get("csp_nonce",""))

# ===== END OF STYLES PART 1/10 =====
# ===== START OF STYLES PART 2/10 =====
# coding: utf-8

# ==================== STYLES PART 2/10 ====================
# ===== BLOCK: TEMPLATES — TASKS PAGES (LIST + VIEW) =====

# Tasks list template
TASKS_LIST_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Задачи</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
    <div>
      <label class="muted">Фильтр</label>
      <select id="flt" class="select" style="min-width:160px;">
        <option value="open" {{ 'selected' if (request.args.get('f') or 'open')=='open' else '' }}>Открытые</option>
        <option value="today" {{ 'selected' if request.args.get('f')=='today' else '' }}>На сегодня</option>
        <option value="overdue" {{ 'selected' if request.args.get('f')=='overdue' else '' }}>Просроченные</option>
        <option value="done" {{ 'selected' if request.args.get('f')=='done' else '' }}>Выполненные</option>
      </select>
    </div>
    <div style="flex:1;min-width:200px;">
      <label class="muted">Поиск</label>
      <input id="q" class="input" placeholder="Название или описание" value="{{ request.args.get('q','') }}">
    </div>
    <div>
      <label class="muted">Статус</label>
      <select id="status" class="select" style="min-width:140px;">
        <option value="">Любой</option>
        <option>open</option>
        <option>in_progress</option>
        <option>blocked</option>
        <option>done</option>
        <option>cancelled</option>
      </select>
    </div>
    <div>
      <label class="muted">Отдел (ID)</label>
      <input id="department_id" class="input" placeholder="например, 1" style="min-width:120px;">
    </div>
    <div>
      <button id="btnSearch" class="button">Показать</button>
      <button id="btnNewTask" class="button secondary">Новая задача</button>
    </div>
  </div>
</div>

<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div class="muted">Результаты</div>
    <div>
      <button id="btnPrev" class="button ghost small">Назад</button>
      <button id="btnNext" class="button ghost small">Вперёд</button>
    </div>
  </div>
  <table class="table" id="tblTasks">
    <thead>
      <tr>
        <th>ID</th>
        <th>Название</th>
        <th>Назначена</th>
        <th>Статус</th>
        <th>Приоритет</th>
        <th>Срок</th>
        <th>Компания</th>
        <th>Чек‑лист</th>
        <th></th>
      </tr>
    </thead>
    <tbody id="tasksBody">
      <tr><td colspan="9" class="muted">Загрузка…</td></tr>
    </tbody>
  </table>
  <div id="pagerInfo" class="muted" style="margin-top:8px;">Стр. 1</div>
</div>

<!-- Modal создания задачи -->
<div class="modal-backdrop" id="modalNew">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3 style="margin:0;">Создать задачу</h3>
      <button class="button ghost small" onclick="closeNewModal()">Закрыть</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;">
      <div style="grid-column:1/3;">
        <label class="muted">Заголовок</label>
        <input id="new_title" class="input" placeholder="Например: Позвонить клиенту">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Описание</label>
        <textarea id="new_desc" class="input" rows="4" placeholder="Кратко опишите задачу"></textarea>
      </div>
      <div>
        <label class="muted">Приоритет</label>
        <select id="new_priority" class="select">
          <option>normal</option>
          <option>high</option>
          <option>urgent</option>
        </select>
      </div>
      <div>
        <label class="muted">Срок (локальное время)</label>
        <input id="new_due" type="datetime-local" class="input">
      </div>
      <div>
        <label class="muted">Компания (ID)</label>
        <input id="new_company" class="input" placeholder="например, 1">
      </div>
      <div>
        <label class="muted">Контакт (ID)</label>
        <input id="new_contact" class="input" placeholder="например, 5">
      </div>
      <div style="grid-column:1/3;display:flex;gap:8px;align-items:center;">
        <input id="new_assign_me" type="checkbox" checked>
        <label for="new_assign_me">Назначить мне</label>
      </div>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">
      <button class="button ghost" onclick="closeNewModal()">Отмена</button>
      <button class="button" onclick="createTask()">Создать</button>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const Q = (id)=>document.getElementById(id);
  let page = 1, perPage = 50, total = 0;

  function fetchTasks(){
    const f = Q('flt').value || 'open';
    const q = Q('q').value || '';
    const status = Q('status').value || '';
    const dept = Q('department_id').value || '';
    const params = new URLSearchParams({page: String(page), per_page: String(perPage), f});
    if(q) params.set('q', q);
    if(status) params.set('status', status);
    if(dept) params.set('department_id', dept);
    fetch('/api/tasks/list?'+params.toString())
      .then(r=>r.json()).then(j=>{
        if(!j.ok){ Q('tasksBody').innerHTML = '<tr><td colspan="9">Ошибка загрузки</td></tr>'; return; }
        total = j.total||0;
        Q('tasksBody').innerHTML = (j.items||[]).map(it=>{
          const due = it.due_at ? String(it.due_at).replace('T',' ') : '';
          const comp = it.company_name || '';
          const pr = it.priority || '';
          const chk = (it.checklist_percent!=null)? String(it.checklist_percent)+'%' : '';
          return '<tr>'
            + '<td>'+ESC(it.id)+'</td>'
            + '<td>'+ESC(it.title||'')+'</td>'
            + '<td>'+ESC(it.assignee_name||'')+'</td>'
            + '<td><span class="badge">'+ESC(it.status||'')+'</span></td>'
            + '<td>'+ESC(pr)+'</td>'
            + '<td>'+ESC(due)+'</td>'
            + '<td>'+ESC(comp)+'</td>'
            + '<td>'+ESC(chk)+'</td>'
            + '<td><a class="button ghost small" href="/task/'+ESC(it.id)+'">Открыть</a></td>'
            + '</tr>';
        }).join('') || '<tr><td colspan="9" class="muted">Нет задач</td></tr>';
        const pages = Math.ceil((j.total||0)/perPage)||1;
        Q('pagerInfo').textContent = 'Стр. '+page+' / '+pages+' (всего: '+(j.total||0)+')';
      }).catch(()=>{ Q('tasksBody').innerHTML = '<tr><td colspan="9">Сеть недоступна</td></tr>';});
  }

  Q('btnSearch')?.addEventListener('click', ()=>{ page=1; fetchTasks(); });
  Q('flt')?.addEventListener('change', ()=>{ page=1; fetchTasks(); });
  Q('q')?.addEventListener('keydown', (e)=>{ if(e.key==='Enter'){ page=1; fetchTasks(); } });
  Q('btnPrev')?.addEventListener('click', ()=>{ if(page>1){ page--; fetchTasks(); } });
  Q('btnNext')?.addEventListener('click', ()=>{ page++; fetchTasks(); });

  // Modal
  window.closeNewModal = ()=> Q('modalNew')?.classList.remove('show');
  Q('btnNewTask')?.addEventListener('click', ()=> Q('modalNew')?.classList.add('show'));

  function toServerDT(val){ if(!val) return null; return val.replace('T',' ')+":00"; }

  // Используем Idempotency-Key для защиты от дублей создания
  window.createTask = async ()=>{
    const title = Q('new_title').value.trim(); if(!title){ toast('Укажите заголовок'); return; }
    const body = {
      title,
      description: Q('new_desc').value||'',
      priority: Q('new_priority').value||'normal',
      due_at: toServerDT(Q('new_due').value)||null,
      company_id: Q('new_company').value? Number(Q('new_company').value): null,
      contact_id: Q('new_contact').value? Number(Q('new_contact').value): null,
      assignee_id: Q('new_assign_me').checked ? (Number((document.body||{}).getAttribute('data-userid'))||null) : null
    };
    try{
      const r=await fetch('/api/task/create',{
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken':'{{ session.get("csrf_token","") }}',
          'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
        },
        body: JSON.stringify(body)
      });
      const j=await r.json();
      if(j.ok){ toast(j.duplicated? 'Дубликат: операция уже выполнена' : 'Задача создана'); closeNewModal();
        Q('new_title').value=''; Q('new_desc').value=''; Q('new_due').value=''; Q('new_company').value=''; Q('new_contact').value='';
        fetchTasks();
      } else { toast(j.error||'Не удалось создать'); }
    }catch(e){ toast('Ошибка сети'); }
  };

  fetchTasks();
})();
</script>
{% endblock %}
""")

# Task view template
TASK_VIEW_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Задача #{{ task.id }}</h2>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;">
  <!-- LEFT: Основные поля -->
  <div class="card">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div style="grid-column:1/3;">
        <label class="muted">Название</label>
        <input id="t_title" class="input" value="{{ task.title|e }}">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Описание</label>
        <textarea id="t_desc" class="input" rows="5">{{ task.description or '' }}</textarea>
      </div>
      <div>
        <label class="muted">Статус</label>
        <select id="t_status" class="select">
          {% set st = (task.status or 'open') %}
          <option value="open" {{ 'selected' if st=='open' else '' }}>open</option>
          <option value="in_progress" {{ 'selected' if st=='in_progress' else '' }}>in_progress</option>
          <option value="blocked" {{ 'selected' if st=='blocked' else '' }}>blocked</option>
          <option value="done" {{ 'selected' if st=='done' else '' }}>done</option>
          <option value="cancelled" {{ 'selected' if st=='cancelled' else '' }}>cancelled</option>
        </select>
      </div>
      <div>
        <label class="muted">Приоритет</label>
        <select id="t_priority" class="select">
          {% set pr = (task.priority or 'normal') %}
          <option {{ 'selected' if pr=='normal' else '' }}>normal</option>
          <option {{ 'selected' if pr=='high' else '' }}>high</option>
          <option {{ 'selected' if pr=='urgent' else '' }}>urgent</option>
        </select>
      </div>
      <div>
        <label class="muted">Срок</label>
        <input id="t_due" type="datetime-local" class="input" value="{{ (task.due_at or '').replace(' ','T')[:16] }}">
      </div>
      <div>
        <label class="muted">Телефон контакта</label>
        <input id="t_phone" class="input" value="{{ task.contact_phone or '' }}">
      </div>
      <div>
        <label class="muted">Компания</label>
        <div>{{ task.company_name or '—' }}</div>
      </div>
      <div>
        <label class="muted">Назначена</label>
        <div>{{ task.assignee_name or '—' }}</div>
      </div>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;">
      <button id="btnSave" class="button">Сохранить</button>
      <button id="btnToggle" class="button ghost">{{ 'Сделать открытой' if (task.status or '')=='done' else 'Отметить выполненной' }}</button>
      <a class="button ghost" href="/tasks">К списку</a>
    </div>
  </div>

  <!-- RIGHT: Чек‑лист и прогресс -->
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div>
        <div style="font-weight:700;">Чек‑лист</div>
        <div class="muted">Прогресс: <span id="chkProgress">{{ task.checklist_percent }}%</span></div>
      </div>
      <button id="btnSaveChecklist" class="button ghost small">Сохранить</button>
    </div>
    <div id="chkList" style="margin-top:10px;">
      {% for it in checklist %}
      <div class="smart" data-id="{{ it.id }}" style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <input type="checkbox" class="chk" {{ 'checked' if it.checked in (1,True) else '' }}>
        <input class="input txt" value="{{ it.item|e }}" placeholder="Пункт">
        <input class="input ord" value="{{ it.sort_order or 0 }}" style="max-width:80px;" placeholder="Порядок">
        <button class="button ghost small btnDel">Удалить</button>
      </div>
      {% endfor %}
    </div>
    <div style="margin-top:8px;">
      <button id="btnAddItem" class="button secondary small">Добавить пункт</button>
    </div>
  </div>
</div>

<!-- Комментарии -->
<div class="card" style="margin-top:12px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div style="font-weight:700;">Комментарии</div>
  </div>
  <div id="comments">
    {% for c in comments %}
    <div class="smart" style="margin:6px 0;">
      <div style="display:flex;gap:8px;align-items:center;">
        <div class="badge">{{ c.username or ('user#' ~ (c.user_id or '')) }}</div>
        <div class="muted">{{ c.created_at }}</div>
      </div>
      <div style="margin-top:6px;white-space:pre-wrap;">{{ c.body or '' }}</div>
      {% if c.attachments %}
      <div style="margin-top:6px;">
        {% for a in c.attachments %}
        <a class="badge info" href="{{ a.url }}">{{ a.name }}</a>
        {% endfor %}
      </div>
      {% endif %}
    </div>
    {% else %}
    <div class="muted">Пока нет комментариев</div>
    {% endfor %}
  </div>
  <div style="margin-top:10px;">
    <textarea id="cm_body" class="input" rows="3" placeholder="Оставить комментарий"></textarea>
    <div style="display:flex;align-items:center;gap:8px;margin-top:6px;">
      <input id="cm_file" type="file">
      <button id="btnAttach" class="button ghost small">Прикрепить</button>
      <div id="cm_files" class="muted" style="flex:1;"></div>
      <button id="btnSendComment" class="button">Отправить</button>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const TID = {{ task.id }};
  const Q = (s)=>document.querySelector(s);
  const QA = (s)=>Array.from(document.querySelectorAll(s));
  let pendingFiles = []; // {file_id, name, url}

  function toServerDT(val){ if(!val) return null; return val.replace('T',' ')+":00"; }

  async function saveTask(){
    const updates = {
      title: Q('#t_title').value || '',
      description: Q('#t_desc').value || '',
      status: Q('#t_status').value || 'open',
      priority: Q('#t_priority').value || 'normal',
      due_at: toServerDT(Q('#t_due').value) || null,
      contact_phone: Q('#t_phone').value || ''
    };
    try{
      const r = await fetch('/api/task/update', { method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({id: TID, ...updates}) });
      const j = await r.json();
      toast(j.ok? 'Сохранено' : (j.error||'Ошибка'));
    }catch(e){ toast('Ошибка сети'); }
  }

  async function toggleTask(){
    try{
      const r = await fetch('/api/task/toggle', { method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({id: TID}) });
      const j = await r.json();
      if(j.ok){
        toast('Статус: '+(j.status||''));
        Q('#btnToggle').textContent = (j.status==='done') ? 'Сделать открытой' : 'Отметить выполненной';
      }else{
        toast(j.error||'Ошибка');
      }
    }catch(e){ toast('Ошибка сети'); }
  }

  function getChecklistPayload(){
    const items = [];
    QA('#chkList .smart').forEach(row=>{
      const id = Number(row.getAttribute('data-id')||0)||null;
      const checked = row.querySelector('.chk')?.checked || false;
      const item = row.querySelector('.txt')?.value || '';
      const ord = Number(row.querySelector('.ord')?.value || 0);
      items.push({id, item, checked, sort_order: ord});
    });
    return items;
  }

  async function saveChecklist(){
    try{
      const r = await fetch('/api/task/checklist', { method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({task_id: TID, items: getChecklistPayload()}) });
      const j = await r.json();
      if(j.ok){
        toast('Чек‑лист сохранён');
        const rows = QA('#chkList .smart');
        const total = rows.length||0;
        const done = rows.filter(x=>x.querySelector('.chk')?.checked).length;
        const pct = total? Math.round((done/total)*100):0;
        Q('#chkProgress').textContent = pct+'%';
      }else{
        toast(j.error||'Ошибка');
      }
    }catch(e){ toast('Ошибка сети'); }
  }

  function addChecklistRow(data){
    const cont = Q('#chkList');
    const div = document.createElement('div');
    div.className = 'smart';
    div.setAttribute('data-id', data?.id||'');
    div.style.display='flex';
    div.style.alignItems='center';
    div.style.gap='8px';
    div.style.marginBottom='6px';
    div.innerHTML = `
      <input type="checkbox" class="chk" ${data?.checked?'checked':''}>
      <input class="input txt" value="${ESC(data?.item||'')}" placeholder="Пункт">
      <input class="input ord" value="${Number(data?.sort_order||0)}" style="max-width:80px;" placeholder="Порядок">
      <button class="button ghost small btnDel">Удалить</button>`;
    cont.appendChild(div);
    div.querySelector('.btnDel').addEventListener('click', ()=>{ div.remove(); });
  }

  async function attachFile(){
    const f = Q('#cm_file').files[0];
    if(!f){ toast('Файл не выбран'); return; }
    const fd = new FormData(); fd.append('file', f);
    try{
      const r = await fetch('/api/task/comment/upload',{method:'POST', headers:{'X-CSRFToken':CSRF}, body:fd});
      const j = await r.json();
      if(j.ok && j.file){
        pendingFiles.push(j.file);
        renderPendingFiles();
        Q('#cm_file').value = '';
        toast('Файл загружен');
      }else{
        toast(j.error||'Ошибка загрузки');
      }
    }catch(e){ toast('Ошибка сети'); }
  }

  function renderPendingFiles(){
    Q('#cm_files').innerHTML = pendingFiles.map(f=> (f.name||('file#'+f.id))).join(', ');
  }

  async function sendComment(){
    const body = Q('#cm_body').value || '';
    if(!body && pendingFiles.length===0){ toast('Пустой комментарий'); return; }
    try{
      const r = await fetch('/api/task/comment', { method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({task_id: TID, body, attachments: pendingFiles.map(x=>({file_id:x.id}))}) });
      const j = await r.json();
      if(j.ok){
        toast('Комментарий добавлен');
        const card = document.createElement('div'); card.className='smart'; card.style.margin='6px 0';
        const filesHtml = pendingFiles.map(x=>`<a class="badge info" href="${ESC(x.url)}">${ESC(x.name||'file')}</a>`).join(' ');
        card.innerHTML = `
          <div style="display:flex;gap:8px;align-items:center;">
            <div class="badge">Вы</div>
            <div class="muted">только что</div>
          </div>
          <div style="margin-top:6px;white-space:pre-wrap;">${ESC(body)}</div>
          ${ filesHtml? `<div style="margin-top:6px;">${filesHtml}</div>` : '' }`;
        Q('#comments').insertBefore(card, Q('#comments').firstChild);
        Q('#cm_body').value = '';
        pendingFiles = []; renderPendingFiles();
      }else{
        toast(j.error||'Ошибка');
      }
    }catch(e){ toast('Ошибка сети'); }
  }

  Q('#btnSave')?.addEventListener('click', saveTask);
  Q('#btnToggle')?.addEventListener('click', toggleTask);
  Q('#btnAddItem')?.addEventListener('click', ()=> addChecklistRow({item:'',checked:false,sort_order:0}));
  Q('#btnSaveChecklist')?.addEventListener('click', saveChecklist);
  Q('#btnAttach')?.addEventListener('click', attachFile);
  Q('#btnSendComment')?.addEventListener('click', sendComment);
})();
</script>
{% endblock %}
""")

# ===== BLOCK: PAGE ROUTES — TASKS LIST & TASK VIEW =====
@app.route("/tasks")
@_login_required
def tasks_page():
    return render_template_string(
        TASKS_LIST_TMPL,
        user=g.user,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

@app.route("/task/<int:task_id>")
@_login_required
def task_view_page(task_id: int):
    org_id = g.user["org_id"]
    task = get_task(task_id, org_id)
    if not task:
        return Response("Задача не найдена", 404)
    checklist = query_db("SELECT id, item, checked, sort_order FROM task_checklists WHERE task_id=? ORDER BY sort_order, id", (task_id,)) or []
    comments = get_task_comments(task_id)
    return render_template_string(
        TASK_VIEW_TMPL,
        user=g.user,
        task=task,
        checklist=checklist,
        comments=comments,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

# ===== END OF STYLES PART 2/10 =====
# ===== START OF STYLES PART 3/10 =====
# coding: utf-8

# ==================== STYLES PART 3/10 ====================
# ===== BLOCK: TEMPLATES — DEALS (KANBAN + VIEW) =====

DEALS_KANBAN_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Сделки</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
    <div>
      <label class="muted">Воронка</label>
      <select id="pipeline" class="select" style="min-width:180px;">
        {% for p in pipelines %}
          <option value="{{ p }}" {{ 'selected' if p==current_pipeline else '' }}>{{ p }}</option>
        {% endfor %}
      </select>
    </div>
    <div style="flex:1;min-width:240px;">
      <label class="muted">Поиск</label>
      <input id="q" class="input" placeholder="Название, компания…" value="{{ request.args.get('q','') }}">
    </div>
    <div>
      <button id="btnRefresh" class="button ghost">Обновить</button>
      <button id="btnNewDeal" class="button secondary">Новая сделка</button>
    </div>
  </div>
</div>

<div class="card">
  <div class="muted" style="margin-bottom:8px;">Перетащите карточку между колонками, чтобы изменить стадию</div>
  <div id="board" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;"></div>
</div>

<!-- Modal создания сделки -->
<div class="modal-backdrop" id="modalNewDeal">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3 style="margin:0;">Создать сделку</h3>
      <button class="button ghost small" onclick="closeDealModal()">Закрыть</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;">
      <div style="grid-column:1/3;">
        <label class="muted">Название</label>
        <input id="nd_title" class="input" placeholder="Например: Подписка на 100 лицензий">
      </div>
      <div>
        <label class="muted">Сумма</label>
        <input id="nd_amount" class="input" type="number" step="0.01" placeholder="0">
      </div>
      <div>
        <label class="muted">Валюта</label>
        <input id="nd_currency" class="input" value="RUB">
      </div>
      <div>
        <label class="muted">Компания (ID)</label>
        <input id="nd_company" class="input" placeholder="например, 1">
      </div>
      <div>
        <label class="muted">Ответственный (ID)</label>
        <input id="nd_assignee" class="input" placeholder="например, 2">
      </div>
      <div>
        <label class="muted">Воронка</label>
        <input id="nd_pipeline" class="input" value="{{ current_pipeline }}">
      </div>
      <div>
        <label class="muted">Стадия</label>
        <select id="nd_stage" class="select">
          {% for st in stages %}
            <option value="{{ st.key }}">{{ st.name }}</option>
          {% endfor %}
        </select>
      </div>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">
      <button class="button ghost" onclick="closeDealModal()">Отмена</button>
      <button class="button" onclick="createDeal()">Создать</button>
    </div>
  </div>
</div>

<style>
  .kan-col{background:#fff;border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow-sm);display:flex;flex-direction:column;max-height:70vh;}
  .kan-col-header{padding:10px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:8px;position:sticky;top:0;background:#fff;border-top-left-radius:12px;border-top-right-radius:12px;}
  .kan-col-title{font-weight:700}
  .kan-col-body{padding:10px;overflow:auto;min-height:120px}
  .kan-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:10px;margin-bottom:8px;cursor:grab}
  .kan-card:active{cursor:grabbing}
  .kan-drop{outline:2px dashed transparent;transition:all .12s}
  .kan-drop.over{outline-color:var(--accent);background:var(--surface)}
</style>

<script nonce="{{ csp_nonce }}">
(function(){
  const Q = (s)=>document.querySelector(s);
  const QA = (s)=>Array.from(document.querySelectorAll(s));
  const CSRF = '{{ session.get("csrf_token","") }}';
  let DATA = { stages: [], items_by_stage: {} };

  function fmtMoney(v){ try{ return new Intl.NumberFormat('ru-RU').format(Number(v||0)); }catch(e){ return String(v||0); } }

  function renderBoard(){
    const q = (Q('#q')?.value||'').trim().toLowerCase();
    const board = Q('#board');
    board.innerHTML = (DATA.stages||[]).map(st=>{
      const items = (DATA.items_by_stage?.[st.key]||[]).filter(it=>{
        if(!q) return true;
        const hay = ((it.title||'')+' '+(it.company_name||'')).toLowerCase();
        return hay.includes(q);
      });
      return `
        <div class="kan-col" data-stage="${st.key}">
          <div class="kan-col-header">
            <div class="kan-col-title">${ESC(st.name||st.key)}</div>
            <div class="badge">${items.length}</div>
          </div>
          <div class="kan-col-body kan-drop" data-stage="${st.key}">
            ${ items.map(it=>`
              <div class="kan-card" draggable="true" data-id="${it.id}">
                <div style="display:flex;justify-content:space-between;gap:8px;">
                  <div style="font-weight:700;max-width:70%;">${ESC(it.title||'')}</div>
                  <div class="badge ok">${fmtMoney(it.amount||0)} ${ESC(it.currency||'RUB')}</div>
                </div>
                <div class="muted">${ESC(it.company_name||'—')}</div>
                <div style="margin-top:6px;display:flex;gap:8px;align-items:center;">
                  <a class="button ghost small" href="/deal/${it.id}">Открыть</a>
                  <span class="badge">${ESC(it.assignee_name||'—')}</span>
                </div>
              </div>
            `).join('') }
          </div>
        </div>`;
    }).join('') || '<div class="muted">Нет стадий/сделок</div>';

    // Drag & Drop
    QA('.kan-card').forEach(card=>{
      card.addEventListener('dragstart', (e)=>{
        e.dataTransfer.setData('text/plain', card.getAttribute('data-id'));
        e.dataTransfer.effectAllowed = 'move';
      });
    });
    QA('.kan-drop').forEach(zone=>{
      zone.addEventListener('dragover', (e)=>{ e.preventDefault(); zone.classList.add('over'); e.dataTransfer.dropEffect='move'; });
      zone.addEventListener('dragleave', ()=> zone.classList.remove('over'));
      zone.addEventListener('drop', async (e)=>{
        e.preventDefault(); zone.classList.remove('over');
        const id = Number(e.dataTransfer.getData('text/plain')||0); if(!id) return;
        const newStage = zone.getAttribute('data-stage');
        try{
          const r = await fetch(`/ui/deal/${id}/stage`, {
            method:'POST',
            headers:{
              'Content-Type':'application/json',
              'X-CSRFToken': CSRF,
              'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
            },
            body: JSON.stringify({stage:newStage})
          });
          const j = await r.json();
          if(j.ok){ toast('Стадия изменена'); loadData(); } else { toast(j.error||'Ошибка'); }
        }catch(_){ toast('Сеть недоступна'); }
      });
    });
  }

  async function loadData(){
    const pipeline = Q('#pipeline')?.value || 'default';
    try{
      const r = await fetch(`/ui/deals/kanban_data?pipeline=${encodeURIComponent(pipeline)}`);
      const j = await r.json();
      if(j.ok){ DATA = j; renderBoard(); } else { Q('#board').innerHTML='<div class="muted">Ошибка загрузки</div>'; }
    }catch(_){ Q('#board').innerHTML='<div class="muted">Сеть недоступна</div>'; }
  }

  // Modal controls
  window.closeDealModal = ()=> Q('#modalNewDeal')?.classList.remove('show');
  Q('#btnNewDeal')?.addEventListener('click', ()=> Q('#modalNewDeal')?.classList.add('show'));

  // Создание сделки — с Idempotency-Key
  window.createDeal = async ()=>{
    const title = Q('#nd_title').value.trim(); if(!title){ toast('Укажите название'); return; }
    const payload = {
      title,
      amount: Number(Q('#nd_amount').value||0),
      currency: Q('#nd_currency').value || 'RUB',
      company_id: Q('#nd_company').value? Number(Q('#nd_company').value): null,
      assignee_id: Q('#nd_assignee').value? Number(Q('#nd_assignee').value): null,
      pipeline_key: Q('#nd_pipeline').value || 'default',
      stage: Q('#nd_stage').value || 'new'
    };
    try{
      const r=await fetch('/ui/deal/create', {
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken': CSRF,
          'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
        },
        body: JSON.stringify(payload)
      });
      const j=await r.json();
      if(j.ok){ toast('Сделка создана'); closeDealModal(); loadData(); } else { toast(j.error||'Не удалось создать'); }
    }catch(_){ toast('Сеть недоступна'); }
  };

  Q('#btnRefresh')?.addEventListener('click', loadData);
  Q('#pipeline')?.addEventListener('change', loadData);
  Q('#q')?.addEventListener('keydown', (e)=>{ if(e.key==='Enter') renderBoard(); });

  loadData();
})();
</script>
{% endblock %}
""")

DEAL_VIEW_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Сделка #{{ deal.id }}</h2>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;">
  <!-- LEFT: Карточка сделки -->
  <div class="card">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div style="grid-column:1/3;">
        <label class="muted">Название</label>
        <input id="d_title" class="input" value="{{ deal.title|e }}">
      </div>
      <div>
        <label class="muted">Сумма</label>
        <input id="d_amount" class="input" type="number" step="0.01" value="{{ deal.amount or 0 }}">
      </div>
      <div>
        <label class="muted">Валюта</label>
        <input id="d_currency" class="input" value="{{ deal.currency or 'RUB' }}">
      </div>
      <div>
        <label class="muted">Статус</label>
        {% set st = (deal.status or 'open') %}
        <select id="d_status" class="select">
          <option value="open" {{ 'selected' if st=='open' else '' }}>open</option>
          <option value="won" {{ 'selected' if st=='won' else '' }}>won</option>
          <option value="lost" {{ 'selected' if st=='lost' else '' }}>lost</option>
          <option value="cancelled" {{ 'selected' if st=='cancelled' else '' }}>cancelled</option>
        </select>
      </div>
      <div>
        <label class="muted">Срок (due_at)</label>
        <input id="d_due" class="input" type="datetime-local" value="{{ (deal.due_at or '').replace(' ','T')[:16] }}">
      </div>
      <div>
        <label class="muted">Ответственный (ID)</label>
        <input id="d_assignee" class="input" value="{{ deal.assignee_id or '' }}">
      </div>
      <div>
        <label class="muted">Компания (ID)</label>
        <input id="d_company" class="input" value="{{ deal.company_id or '' }}">
      </div>
      <div>
        <label class="muted">Контакт (ID)</label>
        <input id="d_contact" class="input" value="{{ deal.contact_id or '' }}">
      </div>
      <div>
        <label class="muted">Воронка</label>
        <input id="d_pipeline" class="input" value="{{ deal.pipeline_key or 'default' }}">
      </div>
      <div>
        <label class="muted">Стадия</label>
        <select id="d_stage" class="select">
          {% for s in stages %}
            <option value="{{ s.key }}" {{ 'selected' if (deal.stage or 'new')==s.key else '' }}>{{ s.name }}</option>
          {% endfor %}
        </select>
      </div>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;">
      <button id="btnSaveDeal" class="button">Сохранить</button>
      <button id="btnChangeStage" class="button ghost">Сменить стадию</button>
      <a class="button ghost" href="/deals">К Канбан</a>
    </div>
  </div>

  <!-- RIGHT: История/хронология -->
  <div class="card">
    <div style="font-weight:700;margin-bottom:6px;">Активность</div>
    <div id="timeline">
      {% for e in history %}
        <div class="smart" style="margin:6px 0;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div class="badge">{{ e.action }}</div>
            <div class="muted">{{ e.created_at }}</div>
          </div>
          {% if e.data_json %}
            <pre style="white-space:pre-wrap;background:#f8fafc;border:1px solid var(--border);border-radius:8px;padding:8px;margin-top:6px;">{{ e.data_json }}</pre>
          {% endif %}
        </div>
      {% else %}
        <div class="muted">Пока нет событий</div>
      {% endfor %}
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const DID = {{ deal.id }};

  function toServerDT(val){ if(!val) return null; return val.replace('T',' ')+":00"; }

  async function saveDeal(){
    const payload = {
      title: document.getElementById('d_title').value || '',
      amount: Number(document.getElementById('d_amount').value||0),
      currency: document.getElementById('d_currency').value || 'RUB',
      status: document.getElementById('d_status').value || 'open',
      due_at: toServerDT(document.getElementById('d_due').value)||null,
      assignee_id: document.getElementById('d_assignee').value? Number(document.getElementById('d_assignee').value): null,
      company_id: document.getElementById('d_company').value? Number(document.getElementById('d_company').value): null,
      contact_id: document.getElementById('d_contact').value? Number(document.getElementById('d_contact').value): null,
      pipeline_key: document.getElementById('d_pipeline').value || 'default',
      stage: document.getElementById('d_stage').value || 'new'
    };
    try{
      const r = await fetch(`/ui/deal/${DID}/update`, {
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken': CSRF
        },
        body: JSON.stringify(payload)
      });
      const j = await r.json();
      toast(j.ok? 'Сохранено' : (j.error||'Ошибка'));
    }catch(_){ toast('Сеть недоступна'); }
  }

  async function changeStage(){
    const stage = document.getElementById('d_stage').value || 'new';
    try{
      const r = await fetch(`/ui/deal/${DID}/stage`, {
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken': CSRF,
          'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
        },
        body: JSON.stringify({stage})
      });
      const j = await r.json();
      if(j.ok){ toast('Стадия изменена'); } else { toast(j.error||'Ошибка'); }
    }catch(_){ toast('Сеть недоступна'); }
  }

  document.getElementById('btnSaveDeal')?.addEventListener('click', saveDeal);
  document.getElementById('btnChangeStage')?.addEventListener('click', changeStage);
})();
</script>
{% endblock %}
""")

# ===== BLOCK: PAGE ROUTES — DEALS KANBAN & DEAL VIEW =====
@app.route("/deals")
@_login_required
def deals_page():
    user = g.user
    pipeline = request.args.get("pipeline", "default")
    # Ensure default stages exist and load stages list
    try:
        ensure_default_deal_stages(user["org_id"], pipeline_key=pipeline)
    except Exception:
        pass
    rows = query_db(
        "SELECT key, name, sort_order FROM workflow_stages WHERE org_id=? AND entity_type='deal' AND pipeline_key=? ORDER BY sort_order, key",
        (user["org_id"], pipeline)
    ) or []
    stages = rows or [{"key": k, "name": n, "sort_order": i} for (k, n, i) in DEFAULT_DEAL_STAGES]
    # Pipelines list
    pls_rows = query_db("SELECT DISTINCT pipeline_key FROM workflow_stages WHERE org_id=? AND entity_type='deal' ORDER BY pipeline_key", (user["org_id"],)) or []
    pipelines = [r["pipeline_key"] for r in pls_rows] or ["default"]
    if pipeline not in pipelines:
        pipelines = [pipeline] + [p for p in pipelines if p != pipeline]
    return render_template_string(
        DEALS_KANBAN_TMPL,
        user=user,
        stages=stages,
        pipelines=pipelines,
        current_pipeline=pipeline,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

@app.route("/deal/<int:deal_id>")
@_login_required
def deal_view_page(deal_id: int):
    user = g.user
    deal = get_deal(deal_id, user["org_id"])
    if not deal:
        return Response("Сделка не найдена", 404)
    pipeline = deal.get("pipeline_key") or "default"
    st = query_db(
        "SELECT key, name, sort_order FROM workflow_stages WHERE org_id=? AND entity_type='deal' AND pipeline_key=? ORDER BY sort_order, key",
        (user["org_id"], pipeline)
    ) or []
    stages = st or [{"key": k, "name": n, "sort_order": i} for (k, n, i) in DEFAULT_DEAL_STAGES]
    history = query_db(
        "SELECT action, data_json, created_at FROM activity_timeline WHERE org_id=? AND entity_type='deal' AND entity_id=? ORDER BY created_at DESC LIMIT 100",
        (user["org_id"], deal_id)
    ) or []
    return render_template_string(
        DEAL_VIEW_TMPL,
        user=user,
        deal=deal,
        stages=stages,
        history=history,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

# ===== BLOCK: UI ENDPOINTS — DEALS KANBAN DATA & MUTATIONS =====
@app.route("/ui/deals/kanban_data", methods=["GET"])
@_login_required
def ui_deals_kanban_data():
    user = g.user
    pipeline = request.args.get("pipeline", "default")
    try:
        sts, items = deals_kanban(user["org_id"], pipeline_key=pipeline)  # type: ignore
        # Ensure JSON-serializable keys
        serial_stages = [{"key": s.get("key"), "name": s.get("name"), "sort_order": s.get("sort_order")} for s in (sts or [])]
        serial_items = {k: [dict(x) for x in (v or [])] for k, v in (items or {}).items()}
        return jsonify(ok=True, stages=serial_stages, items_by_stage=serial_items, pipeline=pipeline)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route("/ui/deal/create", methods=["POST"])
@_login_required
@_csrf_protect
def ui_deal_create():
    user = g.user
    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify(ok=False, error="title required"), 400
    try:
        did = create_deal(
            user["org_id"],
            title=title,
            amount=float(data.get("amount") or 0),
            currency=(data.get("currency") or "RUB"),
            status="open",
            stage=(data.get("stage") or "new"),
            pipeline_key=(data.get("pipeline_key") or "default"),
            assignee_id=(int(data.get("assignee_id")) if data.get("assignee_id") else None),
            company_id=(int(data.get("company_id")) if data.get("company_id") else None),
            contact_id=(int(data.get("contact_id")) if data.get("contact_id") else None),
            due_at=None
        )  # type: ignore
        return jsonify(ok=True, id=int(did or 0))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route("/ui/deal/<int:deal_id>/update", methods=["POST"])
@_login_required
@_csrf_protect
def ui_deal_update(deal_id: int):
    user = g.user
    data = request.get_json() or {}
    # Только поля, поддерживаемые бизнес-логикой
    allowed = {"title","amount","currency","status","stage","pipeline_key","assignee_id","company_id","contact_id","due_at","won_at","lost_at","score"}
    updates = {k: v for k, v in data.items() if k in allowed}
    # Типизация
    for k in ("amount","score"):
        if k in updates and updates[k] is not None:
            try: updates[k] = float(updates[k])
            except Exception: pass
    for k in ("assignee_id","company_id","contact_id"):
        if k in updates and updates[k] not in (None,""):
            try: updates[k] = int(updates[k])
            except Exception: pass
    try:
        ok = update_deal(deal_id, user["org_id"], updates)  # type: ignore
        return jsonify(ok=bool(ok))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route("/ui/deal/<int:deal_id>/stage", methods=["POST"])
@_login_required
@_csrf_protect
def ui_deal_change_stage(deal_id: int):
    user = g.user
    data = request.get_json() or {}
    stage = (data.get("stage") or "").strip()
    if not stage:
        return jsonify(ok=False, error="stage required"), 400
    try:
        ok = change_deal_stage(deal_id, user["org_id"], stage, user_id=user["id"])  # type: ignore
        return jsonify(ok=bool(ok))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

# ===== END OF STYLES PART 3/10 =====
# ===== START OF STYLES PART 4/10 =====
# coding: utf-8

# ==================== STYLES PART 4/10 ====================
# ===== BLOCK: TEMPLATES — INBOX (LIST + THREAD VIEW) =====

INBOX_LIST_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Inbox</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
    <div>
      <label class="muted">Статус</label>
      <select id="status" class="select" style="min-width:140px;">
        <option value="">Любой</option>
        <option value="open">open</option>
        <option value="pending">pending</option>
        <option value="closed">closed</option>
      </select>
    </div>
    <div>
      <label class="muted">Канал (ID)</label>
      <input id="channel" class="input" placeholder="например, 1" style="min-width:120px;">
    </div>
    <div>
      <label class="muted">Ответственный (ID)</label>
      <input id="assignee" class="input" placeholder="например, 2" style="min-width:120px;">
    </div>
    <div>
      <label class="muted">Только мои</label>
      <select id="who" class="select" style="min-width:120px;">
        <option value="">Нет</option>
        <option value="me">Да</option>
      </select>
    </div>
    <div style="flex:1;min-width:220px;">
      <label class="muted">Поиск</label>
      <input id="q" class="input" placeholder="Тема">
    </div>
    <div>
      <button id="btnSearch" class="button">Показать</button>
    </div>
  </div>
</div>

<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div class="muted">Потоки</div>
    <div>
      <button id="btnPrev" class="button ghost small">Назад</button>
      <button id="btnNext" class="button ghost small">Вперёд</button>
    </div>
  </div>
  <table class="table" id="tblInbox">
    <thead>
      <tr>
        <th>ID</th>
        <th>Тема</th>
        <th>Статус</th>
        <th>Приоритет</th>
        <th>Канал</th>
        <th>Ответственный</th>
        <th>Последнее сообщение</th>
        <th></th>
      </tr>
    </thead>
    <tbody id="inboxBody">
      <tr><td colspan="8" class="muted">Загрузка…</td></tr>
    </tbody>
  </table>
  <div id="pagerInfo" class="muted" style="margin-top:8px;">Стр. 1</div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const Q = (id)=>document.getElementById(id);
  let page = 1, perPage = 50, total = 0;

  function fetchInbox(){
    const status = Q('status').value || '';
    const channel = Q('channel').value || '';
    const assignee = Q('assignee').value || '';
    const who = Q('who').value || '';
    const q = Q('q').value || '';
    const params = new URLSearchParams({page:String(page), per_page:String(perPage)});
    if(status) params.set('status', status);
    if(channel) params.set('channel', channel);
    if(assignee) params.set('assignee', assignee);
    if(who) params.set('who', who);
    if(q) params.set('q', q);
    fetch('/api/inbox/list?'+params.toString())
      .then(r=>r.json())
      .then(j=>{
        if(!j.ok){ Q('inboxBody').innerHTML = '<tr><td colspan="8">Ошибка загрузки</td></tr>'; return; }
        total = j.total||0;
        Q('inboxBody').innerHTML = (j.items||[]).map(t=>{
          return `<tr>
            <td>${ESC(t.id)}</td>
            <td>${ESC(t.subject||'')}</td>
            <td><span class="badge">${ESC(t.status||'')}</span></td>
            <td>${ESC(t.priority||'')}</td>
            <td>${ESC(t.channel_name||'')}</td>
            <td>${ESC(t.assignee_name||'')}</td>
            <td>${ESC(t.last_message_at||'')}</td>
            <td><a class="button ghost small" href="/thread/${ESC(t.id)}">Открыть</a></td>
          </tr>`;
        }).join('') || '<tr><td colspan="8" class="muted">Нет потоков</td></tr>';
        const pages = Math.ceil((j.total||0)/perPage)||1;
        Q('pagerInfo').textContent = 'Стр. '+page+' / '+pages+' (всего: '+(j.total||0)+')';
      })
      .catch(()=>{ Q('inboxBody').innerHTML = '<tr><td colspan="8">Сеть недоступна</td></tr>';});
  }

  Q('btnSearch')?.addEventListener('click', ()=>{ page=1; fetchInbox(); });
  Q('q')?.addEventListener('keydown', (e)=>{ if(e.key==='Enter'){ page=1; fetchInbox(); }});
  Q('btnPrev')?.addEventListener('click', ()=>{ if(page>1){ page--; fetchInbox(); }});
  Q('btnNext')?.addEventListener('click', ()=>{ page++; fetchInbox(); });

  fetchInbox();
})();
</script>
{% endblock %}
""")

THREAD_VIEW_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Тема #{{ thread.id }} — {{ thread.subject or 'Без темы' }}</h2>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;">
  <!-- LEFT: Сообщения -->
  <div class="card">
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <div><span class="badge">Статус: {{ thread.status }}</span></div>
      <div><span class="badge">Приоритет: {{ thread.priority }}</span></div>
      <button id="btnRefresh" class="button ghost small">Обновить</button>
      <button id="btnSummarize" class="button ghost small">AI: Суммаризация</button>
      <button id="btnDraft" class="button ghost small">AI: Черновик ответа</button>
      <button id="btnAutotag" class="button ghost small">AI: Теги</button>
    </div>

    <div id="msgs" style="margin-top:10px;"></div>
    <div style="margin-top:8px;text-align:center;">
      <button id="btnMore" class="button ghost small">Загрузить ещё</button>
    </div>

    <div class="smart" style="margin-top:12px;">
      <h3 style="margin:0 0 8px 0;">Написать сообщение</h3>
      <textarea id="body" class="input" rows="4" placeholder="Текст сообщения…"></textarea>
      <div style="display:flex;gap:8px;align-items:center;margin-top:6px;flex-wrap:wrap;">
        <input id="file" type="file">
        <button id="btnAttach" class="button ghost small">Прикрепить</button>
        <div id="files" class="muted" style="flex:1;"></div>
        <label style="display:flex;gap:6px;align-items:center;">
          <input type="checkbox" id="internal">Внутренняя заметка
        </label>
        <button id="btnSend" class="button">Отправить</button>
      </div>
    </div>
  </div>

  <!-- RIGHT: Детали -->
  <div class="card">
    <div style="font-weight:700;margin-bottom:6px;">Свойства темы</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
      <div><label class="muted">Канал</label><div>{{ channel_name or '—' }}</div></div>
      <div><label class="muted">Ответственный</label><div>{{ assignee_name or '—' }}</div></div>
      <div style="grid-column:1/3;"><label class="muted">Компания</label><div>{{ company_name or '—' }}</div></div>
      <div style="grid-column:1/3;"><label class="muted">Контакт</label><div>{{ contact_name or '—' }}</div></div>
      <div style="grid-column:1/3;">
        <label class="muted">Теги</label>
        <input id="tags" class="input" value="{{ (thread.tags_csv or '') }}">
      </div>
      <div>
        <label class="muted">Статус</label>
        <select id="statusSel" class="select">
          {% set st = (thread.status or 'open') %}
          <option value="open" {{ 'selected' if st=='open' else '' }}>open</option>
          <option value="pending" {{ 'selected' if st=='pending' else '' }}>pending</option>
          <option value="closed" {{ 'selected' if st=='closed' else '' }}>closed</option>
        </select>
      </div>
      <div>
        <label class="muted">Приоритет</label>
        <select id="prioSel" class="select">
          {% set pr = (thread.priority or 'normal') %}
          <option value="low" {{ 'selected' if pr=='low' else '' }}>low</option>
          <option value="normal" {{ 'selected' if pr=='normal' else '' }}>normal</option>
          <option value="high" {{ 'selected' if pr=='high' else '' }}>high</option>
          <option value="urgent" {{ 'selected' if pr=='urgent' else '' }}>urgent</option>
        </select>
      </div>
      <div style="grid-column:1/3;display:flex;gap:8px;margin-top:6px;">
        <button id="btnSaveThread" class="button">Сохранить</button>
        <button id="btnAssignMe" class="button ghost">Назначить мне</button>
      </div>
    </div>
    <div id="aiBox" class="smart" style="margin-top:12px;display:none;">
      <div style="font-weight:700;margin-bottom:6px;">AI результат</div>
      <div id="aiText" style="white-space:pre-wrap;"></div>
    </div>
  </div>
</div>

<style>
  .msg{border:1px solid var(--border);border-radius:10px;padding:10px;margin:8px 0;background:#fff}
  .msg.agent{background:#eef2ff}
  .msg.customer{background:#f0fdf4}
  .msg.internal{background:#fff7ed;border-style:dashed}
</style>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const TID = {{ thread.id }};
  let offset = 0, limit = 30, loading = false, allLoaded = false;
  let pendingFiles = []; // {id,name,url}

  const elMsgs = document.getElementById('msgs');
  const elMore = document.getElementById('btnMore');

  function msgClass(m){
    if(m.internal_note) return 'msg internal';
    return (m.sender_type==='agent')? 'msg agent' : 'msg customer';
    }

  function renderMsgs(items, prepend=false){
    const html = items.map(m=>{
      const who = m.sender_type==='agent' ? (m.user_name||'agent') : (m.external_user_id||'client');
      const attach = (m.attachments||[]).map(a=>`<a class="badge info" href="${ESC(a.url)}">${ESC(a.name)}</a>`).join(' ');
      return `<div class="${msgClass(m)}">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div><span class="badge">${ESC(m.sender_type)}</span> <span class="muted">${ESC(who)}</span></div>
          <div class="muted">${ESC(m.created_at||'')}</div>
        </div>
        <div style="margin-top:6px;white-space:pre-wrap;">${ESC(m.body||'')}</div>
        ${attach? `<div style="margin-top:6px;">${attach}</div>` : ''}
        <div style="margin-top:6px;">
          <button class="button ghost small" data-mid="${m.id}" data-act="task">Создать задачу</button>
        </div>
      </div>`;
    }).join('');
    const wrap = document.createElement('div');
    wrap.innerHTML = html;
    if(prepend){
      elMsgs.insertBefore(wrap, elMsgs.firstChild);
    }else{
      elMsgs.appendChild(wrap);
    }
    // bind task buttons
    wrap.querySelectorAll('button[data-act="task"]').forEach(btn=>{
      btn.addEventListener('click', ()=>toTask(Number(btn.getAttribute('data-mid')||0)));
    });
  }

  async function loadMore(){
    if(loading || allLoaded) return;
    loading = true;
    try{
      const r=await fetch(`/ui/thread/${TID}/messages?offset=${offset}&limit=${limit}`);
      const j=await r.json();
      if(j.ok){
        const items = j.items||[];
        if(items.length===0){ allLoaded = true; elMore.disabled = true; elMore.textContent = 'Больше нет'; }
        else{
          renderMsgs(items);
          offset += items.length;
        }
      }
    }catch(_){ /* ignore */ }
    loading = false;
  }

  async function refreshTop(){
    // naive refresh: re-render from scratch
    elMsgs.innerHTML = '';
    offset = 0; allLoaded=false; elMore.disabled=false; elMore.textContent='Загрузить ещё';
    await loadMore();
  }

  async function uploadFile(){
    const f = document.getElementById('file').files[0];
    if(!f){ toast('Файл не выбран'); return; }
    const fd=new FormData(); fd.append('file', f);
    try{
      const r=await fetch('/api/message/upload',{method:'POST', headers:{'X-CSRFToken':CSRF}, body:fd});
      const j=await r.json();
      if(j.ok && j.file){ pendingFiles.push(j.file); renderPendingFiles(); toast('Файл загружен'); }
      else toast(j.error||'Ошибка загрузки');
    }catch(_){ toast('Ошибка сети'); }
  }

  function renderPendingFiles(){
    document.getElementById('files').textContent = pendingFiles.map(f=> (f.name||('file#'+f.id))).join(', ');
  }

  async function sendMsg(){
    const body = (document.getElementById('body').value||'').trim();
    const internal = document.getElementById('internal').checked;
    if(!body && pendingFiles.length===0){ toast('Пустое сообщение'); return; }
    try{
      const r = await fetch('/api/message/send', {
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken':CSRF,
          'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
        },
        body: JSON.stringify({thread_id: TID, body, internal_note: internal, attachments: pendingFiles.map(x=>({file_id:x.id}))})
      });
      const j = await r.json();
      if(j.ok){
        toast(j.duplicated? 'Дубликат: сообщение уже отправлено' : 'Отправлено');
        document.getElementById('body').value=''; pendingFiles=[]; renderPendingFiles();
        // optimistic prepend
        renderMsgs([{id:j.id, sender_type:'agent', user_name:'Вы', external_user_id:'', body, internal_note:internal, created_at:new Date().toLocaleString(), attachments:[]}], true);
      }else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  }

  async function saveThread(){
    const tags = (document.getElementById('tags').value||'').split(',').map(s=>s.trim()).filter(Boolean);
    const status = document.getElementById('statusSel').value;
    const priority = document.getElementById('prioSel').value;
    try{
      const r=await fetch('/api/thread/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},
        body: JSON.stringify({id: TID, status, priority, tags_json: tags})});
      const j=await r.json();
      toast(j.ok? 'Сохранено' : (j.error||'Ошибка'));
    }catch(_){ toast('Ошибка сети'); }
  }

  async function assignMe(){
    try{
      const r=await fetch('/api/thread/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},
        body: JSON.stringify({id: TID, assignee_id: Number((document.body||{}).getAttribute('data-userid')||0)})});
      const j=await r.json(); toast(j.ok? 'Назначено' : (j.error||'Ошибка'));
    }catch(_){ toast('Ошибка сети'); }
  }

  async function toTask(mid){
    const title = prompt('Заголовок задачи', 'Обработать обращение');
    if(!title) return;
    try{
      const r=await fetch('/api/message/to_task',{
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken':CSRF,
          'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
        },
        body: JSON.stringify({message_id: mid, title})
      });
      const j=await r.json();
      toast(j.ok? ('Задача #'+j.task_id) : (j.error||'Ошибка'));
    }catch(_){ toast('Ошибка сети'); }
  }

  // AI helpers
  function showAI(text){ const box=document.getElementById('aiBox'); const tt=document.getElementById('aiText'); tt.textContent = text||''; box.style.display = 'block'; }
  async function aiSummarize(){
    try{
      const r=await fetch('/api/ai/summarize_thread',{
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken':CSRF,
          'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
        },
        body:JSON.stringify({thread_id:TID})
      });
      const j=await r.json();
      if(j.ok && j.job_id){ pollJob(j.job_id, (res)=> showAI(res.output_text||'Готово')); toast('Запрос отправлен'); }
      else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  }
  async function aiDraft(){
    try{
      const r=await fetch('/api/ai/draft_reply',{
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken':CSRF,
          'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
        },
        body:JSON.stringify({thread_id:TID})
      });
      const j=await r.json();
      if(j.ok && j.variants){ showAI(j.variants[0]||''); }
      else if(j.ok && j.job_id){ pollJob(j.job_id, (res)=> showAI(res.output_text||'')); toast('Запрос отправлен'); }
      else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  }
  async function aiAutotag(){
    try{
      const r=await fetch('/api/ai/autotag',{
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'X-CSRFToken':CSRF,
          'Idempotency-Key': (window.IDK && window.IDK()) || (Date.now()+'-'+Math.random())
        },
        body:JSON.stringify({thread_id:TID})
      });
      const j=await r.json();
      if(j.ok && j.job_id){ pollJob(j.job_id, ()=>{ toast('Теги будут обновлены'); setTimeout(saveThread, 1000); }); }
      else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  }
  async function pollJob(id, cb){
    let tries=0;
    const tick = async ()=>{
      try{
        const r=await fetch('/api/ai/job_status?id='+id);
        const j=await r.json();
        if(j.ok){
          if((j.status||'')==='completed'){ cb && cb(j); return; }
          if((j.status||'')==='failed'){ toast('AI: ошибка'); return; }
        }
      }catch(_){}
      tries++; if(tries<60) setTimeout(tick, 2000);
    };
    tick();
  }

  document.getElementById('btnMore')?.addEventListener('click', loadMore);
  document.getElementById('btnRefresh')?.addEventListener('click', refreshTop);
  document.getElementById('btnAttach')?.addEventListener('click', uploadFile);
  document.getElementById('btnSend')?.addEventListener('click', sendMsg);
  document.getElementById('btnSaveThread')?.addEventListener('click', saveThread);
  document.getElementById('btnAssignMe')?.addEventListener('click', assignMe);
  document.getElementById('btnSummarize')?.addEventListener('click', aiSummarize);
  document.getElementById('btnDraft')?.addEventListener('click', aiDraft);
  document.getElementById('btnAutotag')?.addEventListener('click', aiAutotag);

  refreshTop();
})();
</script>
{% endblock %}
""")

# ===== BLOCK: PAGE ROUTES — INBOX LIST & THREAD VIEW =====
@app.route("/inbox")
@_login_required
def inbox_page():
    return render_template_string(
        INBOX_LIST_TMPL,
        user=g.user,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

@app.route("/thread/<int:thread_id>")
@_login_required
def thread_page(thread_id: int):
    user = g.user
    thr = query_db("SELECT * FROM inbox_threads WHERE id=? AND org_id=?", (thread_id, user["org_id"]), one=True)
    if not thr:
        return Response("Тема не найдена", 404)
    ch = query_db("SELECT name FROM channels WHERE id=?", (thr.get("channel_id"),), one=True) if thr.get("channel_id") else None
    ass = query_db("SELECT username FROM users WHERE id=?", (thr.get("assignee_id"),), one=True) if thr.get("assignee_id") else None
    comp = query_db("SELECT name FROM companies WHERE id=?", (thr.get("company_id"),), one=True) if thr.get("company_id") else None
    cont = query_db("SELECT name FROM contacts WHERE id=?", (thr.get("contact_id"),), one=True) if thr.get("contact_id") else None
    return render_template_string(
        THREAD_VIEW_TMPL,
        user=user,
        thread=thr,
        channel_name=(ch or {}).get("name"),
        assignee_name=(ass or {}).get("username"),
        company_name=(comp or {}).get("name"),
        contact_name=(cont or {}).get("name"),
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

# ===== BLOCK: UI ENDPOINT — THREAD MESSAGES FEED (PAGINATED) =====
@app.route("/ui/thread/<int:thread_id>/messages", methods=["GET"])
@_login_required
def ui_thread_messages(thread_id: int):
    user = g.user
    thr = query_db("SELECT id FROM inbox_threads WHERE id=? AND org_id=?", (thread_id, user["org_id"]), one=True)
    if not thr:
        return jsonify(ok=False, error="not_found"), 404
    try:
        offset = max(0, int(request.args.get("offset", 0)))
        limit = max(1, min(int(request.args.get("limit", 30)), 200))
    except Exception:
        offset, limit = 0, 30
    rows = query_db(
        "SELECT m.id, m.sender_type, m.user_id, u.username AS user_name, m.external_user_id, m.body, m.internal_note, m.created_at "
        "FROM inbox_messages m LEFT JOIN users u ON u.id=m.user_id "
        "WHERE m.thread_id=? ORDER BY m.created_at DESC, m.id DESC LIMIT ? OFFSET ?",
        (thread_id, limit, offset)
    ) or []
    mids = [int(r["id"]) for r in rows]
    atts_map = {}
    if mids:
        ph = ",".join(["?"]*len(mids))
        # ORG-SAFE: attachments ограничены организацией треда (join на m->t и фильтр t.org_id=?)
        att = query_db(
            f"""
            SELECT a.message_id, f.id AS file_id, f.name, f.content_type, f.size_bytes
            FROM message_attachments a
            JOIN files f ON f.id=a.file_id
            JOIN inbox_messages m ON m.id=a.message_id
            JOIN inbox_threads t ON t.id=m.thread_id
            WHERE a.message_id IN ({ph}) AND t.org_id=?
            """,
            tuple(mids + [user["org_id"]])
        ) or []
        for a in att:
            atts_map.setdefault(int(a["message_id"]), []).append({
                "file_id": a["file_id"],
                "name": a["name"],
                "content_type": a.get("content_type"),
                "size_bytes": a.get("size_bytes"),
                "url": f"/api/files/{a['file_id']}/download"
            })
    items = []
    for r in rows:
        obj = dict(r)
        obj["attachments"] = atts_map.get(int(r["id"]), [])
        items.append(obj)
    return jsonify(ok=True, items=items)

# ===== END OF STYLES PART 4/10 =====
# ===== START OF STYLES PART 5/10 =====
# coding: utf-8

# ==================== STYLES PART 5/10 ====================
# ===== BLOCK: TEMPLATES — CALLS (LIST + DIAL) =====

CALLS_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Звонки</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:grid;grid-template-columns:1.6fr 1fr;gap:12px;align-items:stretch;">
    <!-- Фильтры -->
    <div class="smart">
      <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
        <div>
          <label class="muted">Только мои</label>
          <select id="mine" class="select" style="min-width:120px;">
            <option value="0" {{ 'selected' if (request.args.get('mine') or '0')=='0' else '' }}>Нет</option>
            <option value="1" {{ 'selected' if request.args.get('mine')=='1' else '' }}>Да</option>
          </select>
        </div>
        <div>
          <label class="muted">С даты</label>
          <input id="date_from" class="input" type="datetime-local" style="min-width:210px;" value="{{ request.args.get('date_from','')[:16].replace(' ','T') }}">
        </div>
        <div>
          <label class="muted">По дату</label>
          <input id="date_to" class="input" type="datetime-local" style="min-width:210px;" value="{{ request.args.get('date_to','')[:16].replace(' ','T') }}">
        </div>
        <div>
          <label class="muted">Компания (ID)</label>
          <input id="company_id" class="input" placeholder="например, 1" style="min-width:120px;">
        </div>
        <div>
          <label class="muted">Контакт (ID)</label>
          <input id="contact_id" class="input" placeholder="например, 2" style="min-width:120px;">
        </div>
        <div>
          <button id="btnSearch" class="button">Показать</button>
          <a class="button ghost" href="/api/export/calls/csv">Экспорт CSV</a>
        </div>
      </div>
    </div>
    <!-- Набор номера / CTI -->
    <div class="smart">
      <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
        <div style="flex:1;min-width:220px;">
          <label class="muted">Набрать номер (E.164 или РФ)</label>
          <input id="dial_to" class="input" placeholder="+7XXXXXXXXXX или 8XXXXXXXXXX">
        </div>
        <div>
          <button id="btnDial" class="button secondary">Позвонить</button>
        </div>
      </div>
      <div id="lookupBox" class="muted" style="margin-top:8px;"></div>
    </div>
  </div>
</div>

<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div class="muted">Последние звонки</div>
    <div>
      <button id="btnPrev" class="button ghost small">Назад</button>
      <button id="btnNext" class="button ghost small">Вперёд</button>
    </div>
  </div>

  <table class="table" id="tblCalls">
    <thead>
      <tr>
        <th>ID</th>
        <th>Направление</th>
        <th>От</th>
        <th>Кому</th>
        <th>Агент</th>
        <th>Статус</th>
        <th>Длит., с</th>
        <th>Начат</th>
        <th>Компания</th>
        <th>Контакт</th>
        <th></th>
      </tr>
    </thead>
    <tbody id="callsBody">
      <tr><td colspan="11" class="muted">Загрузка…</td></tr>
    </tbody>
  </table>
  <div id="pagerInfo" class="muted" style="margin-top:8px;">Стр. 1</div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const Q = (id)=>document.getElementById(id);
  const CSRF = '{{ session.get("csrf_token","") }}';
  let page=1, perPage=100, total=0;

  function toServerDT(val){ if(!val) return ''; return (val.replace('T',' ')+":00"); }

  function renderCalls(items){
    Q('callsBody').innerHTML = (items||[]).map(r=>{
      const recBtn = r.recording_url ? `<a class="button ghost small" target="_blank" href="/cti/recording/${ESC(r.id)}">Слушать</a>` : '';
      return `<tr>
        <td>${ESC(r.id)}</td>
        <td><span class="badge">${ESC(r.direction||'')}</span></td>
        <td>${ESC(r.from_e164||'')}</td>
        <td>${ESC(r.to_e164||'')}</td>
        <td>${ESC(r.agent_name||'')}</td>
        <td>${ESC(r.status||'')}</td>
        <td>${ESC(r.duration_sec||0)}</td>
        <td>${ESC(r.started_at||'')}</td>
        <td>${ESC(r.company_name||'')}</td>
        <td>${ESC(r.contact_name||'')}</td>
        <td>${recBtn}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="11" class="muted">Нет данных</td></tr>';
  }

  function fetchCalls(){
    const mine = Q('mine').value==='1';
    const df = toServerDT(Q('date_from').value)||'';
    const dt = toServerDT(Q('date_to').value)||'';
    const cid = Q('company_id').value||'';
    const pid = Q('contact_id').value||'';
    const params = new URLSearchParams({page:String(page), per_page:String(perPage)});
    if(mine) params.set('mine','1');
    if(df) params.set('date_from', df);
    if(dt) params.set('date_to', dt);
    if(cid) params.set('company_id', cid);
    if(pid) params.set('contact_id', pid);
    fetch('/api/calls/list?'+params.toString())
      .then(r=>r.json()).then(j=>{
        if(!j.ok){ Q('callsBody').innerHTML = '<tr><td colspan="11">Ошибка загрузки</td></tr>'; return; }
        total = j.total||0;
        renderCalls(j.items||[]);
        const pages = Math.ceil((j.total||0)/perPage)||1;
        Q('pagerInfo').textContent = 'Стр. '+page+' / '+pages+' (всего: '+(j.total||0)+')';
      }).catch(()=>{ Q('callsBody').innerHTML = '<tr><td colspan="11">Сеть недоступна</td></tr>'; });
  }

  async function clickToCall(){
    const to = (Q('dial_to').value||'').trim();
    if(!to){ toast('Укажите номер'); return; }
    try{
      const r=await fetch('/api/cti/click_to_call',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({to})});
      const j=await r.json();
      if(j.ok){ toast(j.message||'Звонок инициирован'); tryLookup(to); }
      else toast(j.error||'Не удалось позвонить');
    }catch(_){ toast('Ошибка сети'); }
  }

  async function tryLookup(phone){
    try{
      const r=await fetch('/api/lookup?phone='+encodeURIComponent(phone));
      const j=await r.json();
      if(j.ok){
        const cs = (j.companies||[]).map(c=>`<a class="badge info" href="/clients?company_id=${ESC(c.id)}">${ESC(c.name||('Компания #'+c.id))}</a>`).join(' ');
        const ps = (j.contacts||[]).map(c=>`<span class="badge">${ESC(c.name||('Контакт #'+c.id))}</span>`).join(' ');
        Q('lookupBox').innerHTML = (cs||ps) ? (`Найдено: ${cs} ${ps}`) : 'Клиент не найден';
      }
    }catch(_){ /* ignore */ }
  }

  Q('btnSearch')?.addEventListener('click', ()=>{ page=1; fetchCalls(); });
  Q('btnPrev')?.addEventListener('click', ()=>{ if(page>1){ page--; fetchCalls(); } });
  Q('btnNext')?.addEventListener('click', ()=>{ page++; fetchCalls(); });
  Q('btnDial')?.addEventListener('click', clickToCall);

  fetchCalls();
})();
</script>
{% endblock %}
""")

# ===== BLOCK: PAGE ROUTE — CALLS LIST =====
@app.route("/calls")
@_login_required
def calls_page():
    return render_template_string(
        CALLS_TMPL,
        user=g.user,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

# ===== END OF STYLES PART 5/10 =====
# ===== START OF STYLES PART 6/10 =====
# coding: utf-8

# ==================== STYLES PART 6/10 ====================
# ===== BLOCK: TEMPLATES — CALENDAR (MONTH/WEEK/LIST + EVENT MODAL) =====

CALENDAR_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Календарь</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;">
    <div>
      <label class="muted">Вид</label>
      <select id="viewType" class="select" style="min-width:160px;">
        <option value="month">Месяц</option>
        <option value="week">Неделя</option>
        <option value="list">Список</option>
      </select>
    </div>
    <div>
      <label class="muted">Период</label>
      <div style="display:flex;gap:6px;">
        <button id="btnPrev" class="button ghost">←</button>
        <button id="btnToday" class="button ghost">Сегодня</button>
        <button id="btnNext" class="button ghost">→</button>
      </div>
    </div>
    <div>
      <label class="muted">Типы событий</label>
      <input id="eventTypes" class="input" style="min-width:240px;" value="meeting,call,task">
    </div>
    <div style="flex:1;"></div>
    <div style="display:flex;gap:8px;">
      <button id="btnNewEvent" class="button secondary">Новое событие</button>
      <button id="btnSaveView" class="button ghost">Сохранить вид</button>
    </div>
  </div>
</div>

<div class="card" id="calendarContainer" style="overflow:hidden;">
  <div id="calendarHeader" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div id="periodTitle" style="font-weight:700;"></div>
    <div class="muted" id="eventsCount"></div>
  </div>
  <div id="calendarGrid"></div>
</div>

<!-- Modal создания/редактирования события -->
<div class="modal-backdrop" id="eventModal">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3 id="em_title" style="margin:0;">Событие</h3>
      <div style="display:flex;gap:6px;">
        <a id="em_ics" class="button ghost small" target="_blank" style="display:none;">ICS</a>
        <button class="button ghost small" onclick="closeEventModal()">Закрыть</button>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;">
      <input type="hidden" id="em_id">
      <div style="grid-column:1/3;">
        <label class="muted">Название</label>
        <input id="em_name" class="input" placeholder="Например: Встреча с клиентом">
      </div>
      <div>
        <label class="muted">Тип</label>
        <select id="em_type" class="select">
          <option value="meeting">meeting</option>
          <option value="call">call</option>
          <option value="task">task</option>
          <option value="other">other</option>
        </select>
      </div>
      <div>
        <label class="muted">Место</label>
        <input id="em_location" class="input" placeholder="Переговорка / Zoom / ...">
      </div>
      <div>
        <label class="muted">Начало</label>
        <input id="em_start" type="datetime-local" class="input">
      </div>
      <div>
        <label class="muted">Окончание</label>
        <input id="em_end" type="datetime-local" class="input">
      </div>
      <div>
        <label class="muted">Весь день</label>
        <select id="em_all_day" class="select">
          <option value="0" selected>Нет</option>
          <option value="1">Да</option>
        </select>
      </div>
      <div>
        <label class="muted">Зона</label>
        <input id="em_tz" class="input" value="UTC">
      </div>
      <div>
        <label class="muted">Организатор (ID)</label>
        <input id="em_org" class="input" placeholder="по умолчанию я">
      </div>
      <div>
        <label class="muted">Цвет</label>
        <input id="em_color" class="input" value="#3B82F6">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Участники (ID через запятую)</label>
        <input id="em_participants" class="input" placeholder="1,2,3">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Напоминания (минуты через запятую)</label>
        <input id="em_reminders" class="input" placeholder="60,15,5">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Описание</label>
        <textarea id="em_desc" class="input" rows="3" placeholder="Краткое описание"></textarea>
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Ссылка на встречу</label>
        <input id="em_link" class="input" placeholder="https://...">
      </div>
      <div>
        <label class="muted">Статус</label>
        <select id="em_status" class="select">
          <option value="confirmed">confirmed</option>
          <option value="tentative">tentative</option>
          <option value="cancelled">cancelled</option>
        </select>
      </div>
      <div>
        <label class="muted">Видимость</label>
        <select id="em_visibility" class="select">
          <option value="default">default</option>
          <option value="private">private</option>
          <option value="public">public</option>
        </select>
      </div>
    </div>

    <!-- Конфликты и слоты -->
    <div class="smart" style="margin-top:12px;">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <button class="button ghost small" id="btnCheckConflicts">Проверить конфликты</button>
        <button class="button ghost small" id="btnSuggestSlots">Предложить слоты</button>
        <div id="conflictsBox" class="muted" style="flex:1;"></div>
      </div>
      <div id="slotsBox" style="margin-top:8px;"></div>
    </div>

    <div style="margin-top:12px;display:flex;gap:8px;justify-content:space-between;">
      <div style="display:flex;gap:8px;">
        <button id="btnRSVPyes" class="button ghost small">RSVP: принимаю</button>
        <button id="btnRSVPmaybe" class="button ghost small">RSVP: возможно</button>
        <button id="btnRSVPno" class="button ghost small">RSVP: отклоняю</button>
      </div>
      <div style="display:flex;gap:8px;">
        <button id="btnDeleteEvent" class="button ghost">Удалить</button>
        <button id="btnSaveEvent" class="button">Сохранить</button>
      </div>
    </div>
  </div>
</div>

<style>
  /* Month view */
  .cal-month{display:grid;grid-template-columns:repeat(7,1fr);gap:6px;padding-bottom:8px;}
  .cal-month .cell{border:1px solid var(--border);border-radius:10px;min-height:110px;background:#fff;display:flex;flex-direction:column;}
  .cal-month .head{padding:6px 8px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;border-top-left-radius:10px;border-top-right-radius:10px;}
  .cal-month .body{padding:6px;flex:1;overflow:auto}
  .cal-daynum{font-weight:700}
  .cal-out{color:#9ca3af}
  .cal-evt{display:block;border-radius:8px;padding:2px 6px;margin:2px 0;color:#111;border:1px solid var(--border);background:var(--panel);cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .cal-evt[data-color]{border-color:transparent}
  /* Week view */
  .cal-week{display:grid;grid-template-columns:120px repeat(7,1fr);border:1px solid var(--border);border-radius:10px;overflow:hidden;background:#fff}
  .cal-week .hours{border-right:1px solid var(--border);background:var(--surface)}
  .cal-week .hours div{height:40px;border-bottom:1px dashed var(--border);padding:4px 6px;color:#6b7280}
  .cal-week .daycol{border-left:1px solid var(--border);}
  .cal-week .daycol .slot{height:40px;border-bottom:1px dashed var(--border);position:relative}
  .cal-week .daycol .ev{position:absolute;left:4px;right:4px;border-radius:8px;padding:4px 6px;background:var(--panel);border:1px solid var(--border);cursor:pointer;font-size:12px}
  /* List */
  .cal-list .row{border:1px solid var(--border);border-radius:10px;background:#fff;padding:8px;margin:6px 0;display:flex;justify-content:space-between;align-items:center}
</style>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const USER_ID = Number((document.body||{}).getAttribute('data-userid')||0);
  const Q = (s)=>document.querySelector(s);
  const QA = (s)=>Array.from(document.querySelectorAll(s));
  let current = new Date();
  let events = [];
  let view = 'month';

  // Helpers
  function pad2(n){ return String(n).padStart(2,'0'); }
  function toLocalInput(dt){ // 'YYYY-MM-DDTHH:MM'
    if(!dt) return '';
    const d = new Date(dt);
    return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate())+'T'+pad2(d.getHours())+':'+pad2(d.getMinutes());
  }
  function toServerDT(val){ if(!val) return null; return val.replace('T',' ')+':00'; }
  function fmtDate(d){ return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate()); }
  function startOfWeek(d){ const x=new Date(d); const wd=(x.getDay()+6)%7; x.setDate(x.getDate()-wd); x.setHours(0,0,0,0); return x; }
  function endOfWeek(d){ const x=startOfWeek(d); x.setDate(x.getDate()+6); x.setHours(23,59,59,999); return x; }
  function startOfMonth(d){ const x=new Date(d.getFullYear(), d.getMonth(), 1, 0,0,0,0); return x; }
  function endOfMonth(d){ const x=new Date(d.getFullYear(), d.getMonth()+1, 0, 23,59,59,999); return x; }
  function iso(dt){ // 'YYYY-MM-DD HH:MM:SS'
    return dt.getFullYear()+'-'+pad2(dt.getMonth()+1)+'-'+pad2(dt.getDate())+' '+pad2(dt.getHours())+':'+pad2(dt.getMinutes())+':'+pad2(dt.getSeconds());
  }
  function parseDate(s){ if(!s) return null; return new Date(s.replace(' ','T')+'Z'); } // server returns UTC-like
  function clamp(n,a,b){ return Math.max(a, Math.min(b, n)); }

  function rangeForView(){
    if(view==='month'){
      return {start: startOfMonth(current), end: endOfMonth(current)};
    } else if(view==='week'){
      return {start: startOfWeek(current), end: endOfWeek(current)};
    } else {
      // list: +/- 14 дней
      const s=new Date(current); s.setDate(s.getDate()-7); s.setHours(0,0,0,0);
      const e=new Date(current); e.setDate(e.getDate()+7); e.setHours(23,59,59,999);
      return {start:s, end:e};
    }
  }

  function periodTitle(){
    if(view==='month'){
      return current.toLocaleString('ru-RU',{month:'long', year:'numeric'});
    } else if(view==='week'){
      const r=rangeForView();
      return fmtDate(r.start)+' — '+fmtDate(r.end);
    } else {
      return 'Список вокруг '+fmtDate(current);
    }
  }

  async function fetchViewPrefs(){
    try{
      const r=await fetch('/api/calendar/views');
      const j=await r.json();
      if(j.ok && j.view){
        if(j.view.view_type){ view = j.view.view_type; Q('#viewType').value=view; }
      }
    }catch(_){}
  }

  async function saveViewPrefs(){
    const payload = {
      view_type: Q('#viewType').value || view,
      updated_at: null
    };
    try{
      const r=await fetch('/api/calendar/views',{method:'PUT',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(payload)});
      const j=await r.json();
      toast(j.ok? 'Вид сохранён' : (j.error||'Ошибка'));
    }catch(_){ toast('Ошибка сети'); }
  }

  async function loadEvents(){
    const rge = rangeForView();
    const start = iso(rge.start);
    const end = iso(rge.end);
    const et = (Q('#eventTypes').value||'').trim();
    const params = new URLSearchParams({start, end, view});
    if(et) params.set('event_types', et);
    try{
      const r=await fetch('/api/calendar/events?'+params.toString());
      const j=await r.json();
      if(j.ok){
        events = (j.events||[]).map(e=>({
          ...e,
          _start: parseDate(e.start_time),
          _end: parseDate(e.end_time)
        }));
        render();
      }else{
        Q('#calendarGrid').innerHTML = '<div class="muted" style="padding:8px;">Ошибка загрузки</div>';
      }
    }catch(_){
      Q('#calendarGrid').innerHTML = '<div class="muted" style="padding:8px;">Сеть недоступна</div>';
    }
  }

  function render(){
    Q('#periodTitle').textContent = periodTitle();
    Q('#eventsCount').textContent = 'Событий: '+(events.length||0);
    if(view==='month') renderMonth(); else if(view==='week') renderWeek(); else renderList();
  }

  function sameDay(a,b){ return a.getFullYear()===b.getFullYear() && a.getMonth()===b.getMonth() && a.getDate()===b.getDate(); }

  function renderMonth(){
    const grid = Q('#calendarGrid');
    const s = startOfMonth(current);
    const e = endOfMonth(current);
    // find first Monday to render
    const first = startOfWeek(s);
    const cells = [];
    let d = new Date(first);
    for(let i=0;i<42;i++){
      const dayEvents = events.filter(ev => ev._start && sameDay(ev._start, d));
      const outMonth = d.getMonth() !== current.getMonth();
      const daynum = d.getDate();
      const lis = dayEvents.slice(0, 6).map(ev=>{
        const color = ev.color || '#e5e7eb';
        const t = ev.all_day? 'Весь день' : (pad2(ev._start.getHours())+':'+pad2(ev._start.getMinutes()));
        return `<span class="cal-evt" data-id="${ev.id}" data-color style="background:${color};">${t} · ${ESC(ev.title||'')}</span>`;
      }).join('');
      cells.push(`
        <div class="cell" data-date="${fmtDate(d)}">
          <div class="head">
            <span class="cal-daynum ${outMonth?'cal-out':''}">${daynum}</span>
            <button class="button ghost small btnNewDay" data-date="${fmtDate(d)}">+</button>
          </div>
          <div class="body">${lis || '<span class="muted">—</span>'}</div>
        </div>
      `);
      d.setDate(d.getDate()+1);
    }
    grid.className = 'cal-month';
    grid.innerHTML = cells.join('');
    // bindings
    QA('.btnNewDay').forEach(b=> b.addEventListener('click', ()=> openEventModal({start:b.getAttribute('data-date')+' 09:00:00', end:b.getAttribute('data-date')+' 10:00:00'})));
    QA('.cal-evt').forEach(e=>{
      e.addEventListener('click', ()=>{
        const id = Number(e.getAttribute('data-id')||0);
        const ev = events.find(x=>x.id===id);
        openEventModal(ev);
      });
    });
  }

  function renderWeek(){
    const grid = Q('#calendarGrid');
    const r = rangeForView();
    const days = [];
    let d = new Date(r.start);
    for(let i=0;i<7;i++){ days.push(new Date(d)); d.setDate(d.getDate()+1); }
    const hours = Array.from({length: 24}, (_,i)=> i);
    let html = '<div class="cal-week">';
    // hours column
    html += '<div class="hours">'+hours.map(h=>`<div>${pad2(h)}:00</div>`).join('')+'</div>';
    // day columns
    days.forEach(day=>{
      html += `<div class="daycol" data-date="${fmtDate(day)}">`;
      hours.forEach(()=> html += '<div class="slot"></div>');
      // events for the day
      const evs = events.filter(ev => ev._start && sameDay(ev._start, day));
      evs.forEach(ev=>{
        const start = ev._start; const end = ev._end || new Date(start.getTime()+60*60000);
        const top = clamp((start.getHours()*60 + start.getMinutes())/ (24*60) * (24*40), 0, 24*40-20);
        const height = Math.max(20, ((end - start) / (60*1000)) / (24*60) * (24*40));
        const color = ev.color || '#e5e7eb';
        html += `<div class="ev" data-id="${ev.id}" style="top:${top}px;height:${height}px;background:${color};">${ESC(ev.title||'')}</div>`;
      });
      html += `</div>`;
    });
    html += '</div>';
    grid.className = '';
    grid.innerHTML = html;
    // bindings
    QA('.cal-week .ev').forEach(e=>{
      e.addEventListener('click', ()=>{
        const id = Number(e.getAttribute('data-id')||0);
        const ev = events.find(x=>x.id===id);
        openEventModal(ev);
      });
    });
  }

  function renderList(){
    const grid = Q('#calendarGrid');
    let rows = (events||[]).slice().sort((a,b)=> (a.start_time||'').localeCompare(b.start_time||''));
    const html = rows.map(ev=>{
      const color = ev.color||'#e5e7eb';
      return `<div class="row" data-id="${ev.id}">
        <div style="display:flex;gap:8px;align-items:center;">
          <span class="badge" style="background:${color};">${ESC(ev.event_type||'event')}</span>
          <div style="font-weight:700;max-width:420px;">${ESC(ev.title||'')}</div>
          <div class="muted">${ESC(ev.start_time||'')} — ${ESC(ev.end_time||'')}</div>
        </div>
        <div><button class="button ghost small btnOpen" data-id="${ev.id}">Открыть</button></div>
      </div>`;
    }).join('') || '<div class="muted" style="padding:8px;">Нет событий</div>';
    grid.className = 'cal-list';
    grid.innerHTML = html;
    QA('.btnOpen').forEach(b=>{
      b.addEventListener('click', ()=>{
        const id = Number(b.getAttribute('data-id')||0);
        const ev = events.find(x=>x.id===id);
        openEventModal(ev);
      });
    });
  }

  // Modal controls
  window.closeEventModal = ()=> Q('#eventModal')?.classList.remove('show');

  function fillModal(ev){
    const isNew = !ev || !ev.id;
    Q('#em_title').textContent = isNew? 'Новое событие' : ('Событие #'+ev.id);
    Q('#em_id').value = ev?.id || '';
    Q('#em_name').value = ev?.title || '';
    Q('#em_type').value = ev?.event_type || 'meeting';
    Q('#em_location').value = ev?.location || '';
    Q('#em_start').value = toLocalInput(ev? ev.start_time : null) || toLocalInput(rangeForView().start);
    Q('#em_end').value = toLocalInput(ev? ev.end_time : null) || toLocalInput(rangeForView().end);
    Q('#em_all_day').value = String(ev?.all_day? 1:0);
    Q('#em_tz').value = ev?.timezone || 'UTC';
    Q('#em_org').value = ev?.organizer_id || '';
    Q('#em_color').value = ev?.color || '#3B82F6';
    const parts = []; if(ev?.participants_json){ try{ const arr=JSON.parse(ev.participants_json||'[]'); arr.forEach(x=>{ if(x.user_id) parts.push(x.user_id); }); }catch(e){} }
    Q('#em_participants').value = parts.join(',');
    const rems = []; if(ev?.reminder_minutes){ try{ const arr=JSON.parse(ev.reminder_minutes||'[]'); arr.forEach(x=>rems.push(x)); }catch(e){} }
    Q('#em_reminders').value = rems.join(',');
    Q('#em_desc').value = ev?.description || '';
    Q('#em_link').value = ev?.meeting_url || '';
    Q('#em_status').value = ev?.status || 'confirmed';
    Q('#em_visibility').value = ev?.visibility || 'default';
    // ICS link
    const ics = Q('#em_ics');
    if(ev?.id){ ics.href = `/api/calendar/events/${ev.id}/ics`; ics.style.display='inline-flex'; } else { ics.style.display='none'; }
  }

  function openEventModal(ev){
    fillModal(ev||{});
    Q('#eventModal').classList.add('show');
  }

  // Actions
  async function saveEvent(){
    const id = Q('#em_id').value;
    const data = {
      title: Q('#em_name').value || '',
      event_type: Q('#em_type').value || 'meeting',
      location: Q('#em_location').value || '',
      start_time: toServerDT(Q('#em_start').value),
      end_time: toServerDT(Q('#em_end').value),
      all_day: Q('#em_all_day').value==='1',
      timezone: Q('#em_tz').value || 'UTC',
      organizer_id: Q('#em_org').value? Number(Q('#em_org').value) : USER_ID,
      participants: (Q('#em_participants').value||'').split(',').map(s=>Number(s.trim())).filter(Boolean),
      reminder_minutes: (Q('#em_reminders').value||'').split(',').map(s=>Number(s.trim())).filter(n=>!isNaN(n)),
      description: Q('#em_desc').value || '',
      meeting_url: Q('#em_link').value || '',
      status: Q('#em_status').value || 'confirmed',
      visibility: Q('#em_visibility').value || 'default'
    };
    try{
      if(id){
        const r=await fetch(`/api/calendar/events/${id}?update_mode=single`, {method:'PUT', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify(data)});
        const j=await r.json();
        if(j.ok){ toast('Сохранено'); closeEventModal(); loadEvents(); } else toast(j.error||'Ошибка');
      }else{
        data.organizer_id = data.organizer_id || USER_ID;
        const r=await fetch('/api/calendar/events', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify(data)});
        const j=await r.json();
        if(j.ok){ toast('Создано'); closeEventModal(); loadEvents(); } else toast(j.error||'Ошибка');
      }
    }catch(_){ toast('Ошибка сети'); }
  }

  async function deleteEvent(){
    const id = Q('#em_id').value;
    if(!id) return closeEventModal();
    if(!confirm('Удалить событие?')) return;
    try{
      const r=await fetch(`/api/calendar/events/${id}`, {method:'DELETE', headers:{'X-CSRFToken':CSRF}});
      const j=await r.json();
      if(j.ok){ toast('Удалено'); closeEventModal(); loadEvents(); } else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  }

  async function rsvp(response){
    const id = Q('#em_id').value;
    if(!id) return;
    try{
      const r=await fetch(`/api/calendar/events/${id}/respond`, {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({response})});
      const j=await r.json();
      toast(j.ok? 'Ответ отправлен' : (j.error||'Ошибка'));
    }catch(_){ toast('Ошибка сети'); }
  }

  async function checkConflicts(){
    const parts = (Q('#em_participants').value||'').split(',').map(s=>Number(s.trim())).filter(Boolean);
    const start_time = toServerDT(Q('#em_start').value); const end_time = toServerDT(Q('#em_end').value);
    if(parts.length===0 || !start_time || !end_time){ Q('#conflictsBox').textContent = 'Укажите участников и время'; return; }
    try{
      const r=await fetch('/api/calendar/conflicts', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({participants: parts, start_time, end_time})});
      const j=await r.json();
      if(j.ok){
        const conf = j.conflicts||[];
        Q('#conflictsBox').textContent = conf.length? ('Конфликты: '+conf.length) : 'Конфликтов не найдено';
      }else Q('#conflictsBox').textContent = j.error||'Ошибка';
    }catch(_){ Q('#conflictsBox').textContent = 'Ошибка сети'; }
  }

  async function suggestSlots(){
    const parts = (Q('#em_participants').value||'').split(',').map(s=>Number(s.trim())).filter(Boolean);
    const start_date = toServerDT(Q('#em_start').value); const end_date = toServerDT(Q('#em_end').value);
    if(parts.length===0 || !start_date || !end_date){ Q('#slotsBox').innerHTML = '<div class="muted">Укажите участников и период</div>'; return; }
    try{
      const r=await fetch('/api/calendar/suggest-slots', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':CSRF}, body: JSON.stringify({participants: parts, duration_minutes: 60, start_date, end_date})});
      const j=await r.json();
      if(j.ok){
        const ss = (j.suggestions||[]).slice(0,20);
        Q('#slotsBox').innerHTML = ss.length? ss.map(s=>`<a class="badge info slotPick" data-start="${ESC(s.start)}" data-end="${ESC(s.end)}" style="margin:4px 6px 0 0;cursor:pointer;">${ESC(s.start)} — ${ESC(s.end)} (${Math.round((s.score||0)*100)}%)</a>`).join('') : '<div class="muted">Нет подходящих слотов</div>';
        QA('.slotPick').forEach(a=> a.addEventListener('click', ()=>{
          Q('#em_start').value = a.getAttribute('data-start').replace(' ','T').slice(0,16);
          Q('#em_end').value = a.getAttribute('data-end').replace(' ','T').slice(0,16);
          toast('Слот выбран');
        }));
      }else{
        Q('#slotsBox').innerHTML = '<div class="muted">'+(j.error||'Ошибка')+'</div>';
      }
    }catch(_){
      Q('#slotsBox').innerHTML = '<div class="muted">Ошибка сети</div>';
    }
  }

  // Nav
  function goToday(){ current = new Date(); loadEvents(); }
  function goPrev(){
    if(view==='month'){ current.setMonth(current.getMonth()-1); }
    else if(view==='week'){ current.setDate(current.getDate()-7); }
    else { current.setDate(current.getDate()-14); }
    loadEvents();
  }
  function goNext(){
    if(view==='month'){ current.setMonth(current.getMonth()+1); }
    else if(view==='week'){ current.setDate(current.getDate()+7); }
    else { current.setDate(current.getDate()+14); }
    loadEvents();
  }

  // Bindings
  Q('#btnToday')?.addEventListener('click', goToday);
  Q('#btnPrev')?.addEventListener('click', goPrev);
  Q('#btnNext')?.addEventListener('click', goNext);
  Q('#viewType')?.addEventListener('change', ()=>{ view = Q('#viewType').value; loadEvents(); });
  Q('#eventTypes')?.addEventListener('keydown', (e)=>{ if(e.key==='Enter') loadEvents(); });
  Q('#btnNewEvent')?.addEventListener('click', ()=> openEventModal({}));
  Q('#btnSaveView')?.addEventListener('click', saveViewPrefs);

  Q('#btnSaveEvent')?.addEventListener('click', saveEvent);
  Q('#btnDeleteEvent')?.addEventListener('click', deleteEvent);
  Q('#btnRSVPyes')?.addEventListener('click', ()=> rsvp('accepted'));
  Q('#btnRSVPmaybe')?.addEventListener('click', ()=> rsvp('tentative'));
  Q('#btnRSVPno')?.addEventListener('click', ()=> rsvp('declined'));
  Q('#btnCheckConflicts')?.addEventListener('click', checkConflicts);
  Q('#btnSuggestSlots')?.addEventListener('click', suggestSlots);

  // Init
  (async function init(){
    await fetchViewPrefs();
    Q('#viewType').value = view;
    loadEvents();
  })();
})();
</script>
{% endblock %}
""")

# ===== BLOCK: PAGE ROUTE — CALENDAR =====
@app.route("/calendar")
@_login_required
def calendar_page():
    return render_template_string(
        CALENDAR_TMPL,
        user=g.user,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

# ===== END OF STYLES PART 6/10 =====
# ===== START OF STYLES PART 7/10 =====
# coding: utf-8

# ==================== STYLES PART 7/10 ====================
# ===== BLOCK: TEMPLATES — CLIENTS (COMPANIES/CONTACTS LIST + COMPANY VIEW) =====

CLIENTS_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Клиенты</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
    <div style="flex:1;min-width:240px;">
      <label class="muted">Поиск</label>
      <input id="q" class="input" placeholder="Компания/ИНН/Email/Контакт/Телефон" value="{{ request.args.get('q','') }}">
    </div>
    <div>
      <button id="btnSearch" class="button">Показать</button>
      <button id="btnNewCompany" class="button secondary">Новая компания</button>
    </div>
  </div>
</div>

<div class="card">
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
    <div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-weight:700;">Компании</div>
        <div class="muted">Найдено: {{ companies|length }}</div>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Название</th>
            <th>ИНН</th>
            <th>Телефон</th>
            <th>Email</th>
            <th>Отрасль</th>
            <th>Счёт</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {% for c in companies %}
          <tr>
            <td>{{ c.id }}</td>
            <td>{{ c.name }}</td>
            <td>{{ c.inn or '' }}</td>
            <td>{{ c.phone_norm or c.phone or '' }}</td>
            <td>{{ c.email or '' }}</td>
            <td>{{ c.industry or '' }}</td>
            <td>{{ c.score or 0 }}</td>
            <td><a class="button ghost small" href="/client/{{ c.id }}">Открыть</a></td>
          </tr>
          {% else %}
          <tr><td colspan="8" class="muted">Нет компаний</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-weight:700;">Контакты</div>
        <div class="muted">Найдено: {{ contacts|length }}</div>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Имя</th>
            <th>Должность</th>
            <th>Компания</th>
            <th>Телефон</th>
            <th>Email</th>
          </tr>
        </thead>
        <tbody>
          {% for p in contacts %}
          <tr>
            <td>{{ p.id }}</td>
            <td>{{ p.name }}</td>
            <td>{{ p.position or '' }}</td>
            <td>{% if p.company_id %}<a href="/client/{{ p.company_id }}">#{{ p.company_id }}</a>{% else %}—{% endif %}</td>
            <td>{{ p.phone_norm or p.phone or '' }}</td>
            <td>{{ p.email or '' }}</td>
          </tr>
          {% else %}
          <tr><td colspan="6" class="muted">Нет контактов</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Modal создания компании -->
<div class="modal-backdrop" id="modalCompany">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3 style="margin:0;">Новая компания</h3>
      <button class="button ghost small" onclick="closeCompanyModal()">Закрыть</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;">
      <div style="grid-column:1/3;">
        <label class="muted">Название</label>
        <input id="nc_name" class="input" placeholder="ООО Ромашка">
      </div>
      <div>
        <label class="muted">ИНН</label>
        <input id="nc_inn" class="input">
      </div>
      <div>
        <label class="muted">Отрасль</label>
        <input id="nc_industry" class="input">
      </div>
      <div>
        <label class="muted">Телефон</label>
        <input id="nc_phone" class="input" placeholder="+7...">
      </div>
      <div>
        <label class="muted">Email</label>
        <input id="nc_email" class="input">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Адрес</label>
        <input id="nc_address" class="input">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Заметки</label>
        <textarea id="nc_notes" class="input" rows="3"></textarea>
      </div>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">
      <button class="button ghost" onclick="closeCompanyModal()">Отмена</button>
      <button class="button" onclick="createCompany()">Создать</button>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const Q = (id)=>document.getElementById(id);
  const CSRF = '{{ session.get("csrf_token","") }}';

  // Search
  Q('btnSearch')?.addEventListener('click', ()=>{
    const q = Q('q').value||'';
    const url = new URL(location.href);
    if(q) url.searchParams.set('q', q); else url.searchParams.delete('q');
    location.href = url.toString();
  });
  Q('q')?.addEventListener('keydown', (e)=>{ if(e.key==='Enter'){ Q('btnSearch').click(); } });

  // Modal
  window.closeCompanyModal = ()=> Q('modalCompany')?.classList.remove('show');
  Q('btnNewCompany')?.addEventListener('click', ()=> Q('modalCompany')?.classList.add('show'));

  // Create company
  window.createCompany = async ()=>{
    const payload = {
      name: Q('nc_name').value||'',
      inn: Q('nc_inn').value||'',
      industry: Q('nc_industry').value||'',
      phone: Q('nc_phone').value||'',
      email: Q('nc_email').value||'',
      address: Q('nc_address').value||'',
      notes: Q('nc_notes').value||''
    };
    if(!payload.name){ toast('Укажите название'); return; }
    try{
      const r=await fetch('/ui/company/create',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(payload)});
      const j=await r.json();
      if(j.ok){ toast('Компания создана'); closeCompanyModal(); location.href = '/client/'+j.id; }
      else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  };
})();
</script>
{% endblock %}
""")

COMPANY_VIEW_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Компания #{{ company.id }} — {{ company.name }}</h2>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;">
  <!-- LEFT: Company form + contacts -->
  <div class="card">
    <h3 style="margin:0 0 8px 0;">Карточка компании</h3>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div>
        <label class="muted">Название</label>
        <input id="c_name" class="input" value="{{ company.name|e }}">
      </div>
      <div>
        <label class="muted">ИНН</label>
        <input id="c_inn" class="input" value="{{ company.inn or '' }}">
      </div>
      <div>
        <label class="muted">Отрасль</label>
        <input id="c_industry" class="input" value="{{ company.industry or '' }}">
      </div>
      <div>
        <label class="muted">Телефон</label>
        <input id="c_phone" class="input" value="{{ company.phone or '' }}">
      </div>
      <div>
        <label class="muted">Email</label>
        <input id="c_email" class="input" value="{{ company.email or '' }}">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Адрес</label>
        <input id="c_address" class="input" value="{{ company.address or '' }}">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Заметки</label>
        <textarea id="c_notes" class="input" rows="3">{{ company.notes or '' }}</textarea>
      </div>
    </div>
    <div style="margin-top:10px;display:flex;gap:8px;">
      <button id="btnSaveCompany" class="button">Сохранить</button>
      <a class="button ghost" href="/deals?q={{ company.name|e }}">Сделки</a>
    </div>

    <h3 style="margin:16px 0 8px 0;">Контакты</h3>
    <div style="margin-bottom:8px;"><button id="btnNewContact" class="button secondary small">Новый контакт</button></div>
    <table class="table" id="tblContacts">
      <thead>
        <tr>
          <th>ID</th>
          <th>Имя</th>
          <th>Должность</th>
          <th>Телефон</th>
          <th>Email</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {% for p in contacts %}
        <tr data-id="{{ p.id }}">
          <td>{{ p.id }}</td>
          <td><input class="input c_name" value="{{ p.name|e }}"></td>
          <td><input class="input c_pos" value="{{ p.position or '' }}"></td>
          <td><input class="input c_phone" value="{{ p.phone or '' }}"></td>
          <td><input class="input c_email" value="{{ p.email or '' }}"></td>
          <td><button class="button ghost small btnSaveContact">Сохранить</button></td>
        </tr>
        {% else %}
        <tr><td colspan="6" class="muted">Контактов нет</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- RIGHT: Deals/Tasks -->
  <div class="card">
    <h3 style="margin:0 0 8px 0;">Сделки</h3>
    <div style="margin-bottom:8px;">
      <button id="btnCreateDeal" class="button ghost small">Создать сделку</button>
    </div>
    <div id="dealsBox">
      {% for d in deals %}
      <div class="smart" style="margin:6px 0;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div style="font-weight:700;"><a href="/deal/{{ d.id }}">{{ d.title }}</a></div>
          <div class="badge ok">{{ d.amount or 0 }} {{ d.currency or 'RUB' }}</div>
        </div>
        <div class="muted">{{ d.status }}/{{ d.stage }} · {{ d.created_at }}</div>
      </div>
      {% else %}
      <div class="muted">Нет сделок</div>
      {% endfor %}
    </div>

    <h3 style="margin:16px 0 8px 0;">Задачи</h3>
    <div id="tasksBox">
      {% for t in tasks %}
      <div class="smart" style="margin:6px 0;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div style="font-weight:700;"><a href="/task/{{ t.id }}">{{ t.title }}</a></div>
          <div class="badge">{{ t.status }}</div>
        </div>
        <div class="muted">Срок: {{ t.due_at or '—' }}</div>
      </div>
      {% else %}
      <div class="muted">Нет задач</div>
      {% endfor %}
    </div>
  </div>
</div>

<!-- Modal нового контакта -->
<div class="modal-backdrop" id="modalContact">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3 style="margin:0;">Новый контакт</h3>
      <button class="button ghost small" onclick="closeContactModal()">Закрыть</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;">
      <div style="grid-column:1/3;">
        <label class="muted">Имя</label>
        <input id="np_name" class="input" placeholder="Иван Иванов">
      </div>
      <div>
        <label class="muted">Должность</label>
        <input id="np_pos" class="input" placeholder="Руководитель отдела">
      </div>
      <div>
        <label class="muted">Телефон</label>
        <input id="np_phone" class="input" placeholder="+7...">
      </div>
      <div>
        <label class="muted">Email</label>
        <input id="np_email" class="input" placeholder="email@example.com">
      </div>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">
      <button class="button ghost" onclick="closeContactModal()">Отмена</button>
      <button class="button" onclick="createContact()">Создать</button>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const COMPANY_ID = {{ company.id }};

  // Save company
  async function saveCompany(){
    const payload = {
      id: COMPANY_ID,
      name: document.getElementById('c_name').value||'',
      inn: document.getElementById('c_inn').value||'',
      industry: document.getElementById('c_industry').value||'',
      phone: document.getElementById('c_phone').value||'',
      email: document.getElementById('c_email').value||'',
      address: document.getElementById('c_address').value||'',
      notes: document.getElementById('c_notes').value||''
    };
    if(!payload.name){ toast('Название обязательно'); return; }
    try{
      const r=await fetch('/ui/company/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(payload)});
      const j=await r.json(); toast(j.ok? 'Сохранено' : (j.error||'Ошибка'));
    }catch(_){ toast('Ошибка сети'); }
  }
  document.getElementById('btnSaveCompany')?.addEventListener('click', saveCompany);

  // Contacts inline save
  document.querySelectorAll('#tblContacts .btnSaveContact').forEach(btn=>{
    btn.addEventListener('click', async ()=>{
      const tr = btn.closest('tr');
      const id = Number(tr.getAttribute('data-id')||0);
      const payload = {
        id,
        name: tr.querySelector('.c_name').value||'',
        position: tr.querySelector('.c_pos').value||'',
        phone: tr.querySelector('.c_phone').value||'',
        email: tr.querySelector('.c_email').value||''
      };
      if(!payload.name){ toast('Имя обязательно'); return; }
      try{
        const r=await fetch('/ui/contact/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(payload)});
        const j=await r.json(); toast(j.ok? 'Сохранено' : (j.error||'Ошибка'));
      }catch(_){ toast('Ошибка сети'); }
    });
  });

  // New contact modal
  window.closeContactModal = ()=> document.getElementById('modalContact')?.classList.remove('show');
  document.getElementById('btnNewContact')?.addEventListener('click', ()=> document.getElementById('modalContact')?.classList.add('show'));

  window.createContact = async ()=>{
    const payload = {
      company_id: COMPANY_ID,
      name: document.getElementById('np_name').value||'',
      position: document.getElementById('np_pos').value||'',
      phone: document.getElementById('np_phone').value||'',
      email: document.getElementById('np_email').value||''
    };
    if(!payload.name){ toast('Имя обязательно'); return; }
    try{
      const r=await fetch('/ui/contact/create',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(payload)});
      const j=await r.json();
      if(j.ok){ toast('Контакт создан'); location.reload(); } else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  };

  // Create deal for company
  document.getElementById('btnCreateDeal')?.addEventListener('click', async ()=>{
    try{
      const r=await fetch('/ui/deal/create',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({
        title: 'Новая сделка — '+('{{ company.name|e }}'),
        amount: 0, currency:'RUB', company_id: COMPANY_ID, stage: 'new', pipeline_key: 'default'
      })});
      const j=await r.json();
      if(j.ok){ location.href = '/deal/'+j.id; } else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  });
})();
</script>
{% endblock %}
""")

# ===== BLOCK: PAGE ROUTES — CLIENTS LIST & COMPANY VIEW =====
@app.route("/clients")
@_login_required
def clients_page():
    user = g.user
    q = (request.args.get("q") or "").strip()
    company_id = request.args.get("company_id")
    companies: List[dict] = []
    contacts: List[dict] = []
    try:
        if company_id:
            c = query_db("SELECT id, name, inn, phone, phone_norm, email, address, notes, industry, score FROM companies WHERE org_id=? AND id=?", (user["org_id"], int(company_id)), one=True)
            companies = [c] if c else []
            contacts = query_db(
                "SELECT id, name, position, company_id, phone, phone_norm, email FROM contacts "
                "WHERE org_id=? AND company_id=? "
                "ORDER BY (updated_at IS NULL), updated_at DESC, id DESC LIMIT 200",
                (user["org_id"], int(company_id))
            ) or []
        else:
            if q:
                like = f"%{q}%"
                companies = query_db(
                    "SELECT id, name, inn, phone, phone_norm, email, address, notes, industry, score FROM companies "
                    "WHERE org_id=? AND (name LIKE ? OR inn LIKE ? OR email LIKE ?) "
                    "ORDER BY (updated_at IS NULL), updated_at DESC, id DESC LIMIT 200",
                    (user["org_id"], like, like, like)
                ) or []
                contacts = query_db(
                    "SELECT id, name, position, company_id, phone, phone_norm, email FROM contacts "
                    "WHERE org_id=? AND (name LIKE ? OR email LIKE ? OR phone LIKE ?) "
                    "ORDER BY id DESC LIMIT 200",
                    (user["org_id"], like, like, like)
                ) or []
            else:
                companies = query_db(
                    "SELECT id, name, inn, phone, phone_norm, email, address, notes, industry, score FROM companies "
                    "WHERE org_id=? "
                    "ORDER BY (updated_at IS NULL), updated_at DESC, id DESC LIMIT 200",
                    (user["org_id"],)
                ) or []
                contacts = query_db(
                    "SELECT id, name, position, company_id, phone, phone_norm, email FROM contacts "
                    "WHERE org_id=? ORDER BY id DESC LIMIT 200",
                    (user["org_id"],)
                ) or []
    except Exception:
        companies, contacts = [], []

    return render_template_string(
        CLIENTS_TMPL,
        user=user,
        companies=companies,
        contacts=contacts,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

@app.route("/client/<int:company_id>")
@_login_required
def company_view_page(company_id: int):
    user = g.user
    c = query_db("SELECT * FROM companies WHERE id=? AND org_id=?", (company_id, user["org_id"]), one=True)
    if not c:
        return Response("Компания не найдена", 404)
    contacts = query_db("SELECT id, name, position, phone, email FROM contacts WHERE org_id=? AND company_id=? ORDER BY id DESC LIMIT 200", (user["org_id"], company_id)) or []
    deals = query_db("SELECT id, title, amount, currency, status, stage, created_at FROM deals WHERE org_id=? AND company_id=? ORDER BY created_at DESC LIMIT 50", (user["org_id"], company_id)) or []
    tasks = query_db("SELECT id, title, status, due_at FROM tasks WHERE org_id=? AND company_id=? ORDER BY created_at DESC LIMIT 50", (user["org_id"], company_id)) or []
    return render_template_string(
        COMPANY_VIEW_TMPL,
        user=g.user,
        company=c,
        contacts=contacts,
        deals=deals,
        tasks=tasks,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

# ===== BLOCK: UI ENDPOINTS — COMPANIES & CONTACTS CRUD (SERVER-SIDE, SAFE) =====
@app.route("/ui/company/create", methods=["POST"])
@_login_required
@_csrf_protect
def ui_company_create():
    user = g.user
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify(ok=False, error="name required"), 400
    inn = (data.get("inn") or "").strip()
    phone = (data.get("phone") or "").strip()
    phone_norm = normalize_phone(phone) if phone else ""
    email = (data.get("email") or "").strip()
    if email and not validate_email(email):
        return jsonify(ok=False, error="invalid email"), 400
    industry = (data.get("industry") or "").strip()
    address = (data.get("address") or "").strip()
    notes = (data.get("notes") or "").strip()
    try:
        cid = exec_db(
            "INSERT INTO companies (org_id, name, inn, phone, phone_norm, email, address, notes, industry, score, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (user["org_id"], name, inn, phone, phone_norm, email, address, notes, industry, utc_now(), utc_now())
        )
        _timeline_add(user["org_id"], user["id"], "company", int(cid or 0), "created", {"name": name})
        try:
            add_audit(user["org_id"], user["id"], "company.created", "company", int(cid or 0), {"name": name})  # type: ignore
        except Exception:
            pass
        return jsonify(ok=True, id=int(cid or 0))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route("/ui/company/update", methods=["POST"])
@_login_required
@_csrf_protect
def ui_company_update():
    user = g.user
    data = request.get_json() or {}
    cid = int(data.get("id") or 0)
    if not cid:
        return jsonify(ok=False, error="id required"), 400
    exists = query_db("SELECT id FROM companies WHERE id=? AND org_id=?", (cid, user["org_id"]), one=True)
    if not exists:
        return jsonify(ok=False, error="not_found"), 404
    allowed = {"name","inn","phone","email","address","notes","industry"}
    updates = {k: (data.get(k) or "").strip() for k in allowed if k in data}
    if "email" in updates and updates["email"] and not validate_email(updates["email"]):
        return jsonify(ok=False, error="invalid email"), 400
    if "phone" in updates:
        pn = normalize_phone(updates["phone"]) if updates["phone"] else ""
        updates["phone_norm"] = pn
    set_clause, params = _safe_update_clause(set(list(updates.keys())+["phone_norm"]), updates)
    if set_clause:
        set_clause = f"{set_clause}, updated_at=?"
        params.append(utc_now())
        params.extend([cid, user["org_id"]])
        try:
            exec_db_affect(f"UPDATE companies SET {set_clause} WHERE id=? AND org_id=?", tuple(params))
            _timeline_add(user["org_id"], user["id"], "company", cid, "updated", updates)
            try:
                add_audit(user["org_id"], user["id"], "company.updated", "company", cid, updates)  # type: ignore
            except Exception:
                pass
            return jsonify(ok=True)
        except Exception as e:
            return jsonify(ok=False, error=str(e)), 400
    return jsonify(ok=False, error="no updates"), 400

@app.route("/ui/contact/create", methods=["POST"])
@_login_required
@_csrf_protect
def ui_contact_create():
    user = g.user
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify(ok=False, error="name required"), 400
    company_id = int(data.get("company_id") or 0) or None
    if company_id:
        chk = query_db("SELECT id FROM companies WHERE id=? AND org_id=?", (company_id, user["org_id"]), one=True)
        if not chk:
            return jsonify(ok=False, error="company_not_found"), 404
    position = (data.get("position") or "").strip()
    phone = (data.get("phone") or "").strip()
    phone_norm = normalize_phone(phone) if phone else ""
    email = (data.get("email") or "").strip()
    if email and not validate_email(email):
        return jsonify(ok=False, error="invalid email"), 400
    try:
        pid = exec_db(
            "INSERT INTO contacts (org_id, company_id, name, position, phone, phone_norm, email, notes, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (user["org_id"], company_id, name, position, phone, phone_norm, email, "", utc_now(), utc_now())
        )
        _timeline_add(user["org_id"], user["id"], "contact", int(pid or 0), "created", {"name": name, "company_id": company_id})
        try:
            add_audit(user["org_id"], user["id"], "contact.created", "contact", int(pid or 0), {"company_id": company_id})  # type: ignore
        except Exception:
            pass
        return jsonify(ok=True, id=int(pid or 0))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route("/ui/contact/update", methods=["POST"])
@_login_required
@_csrf_protect
def ui_contact_update():
    user = g.user
    data = request.get_json() or {}
    pid = int(data.get("id") or 0)
    if not pid:
        return jsonify(ok=False, error="id required"), 400
    chk = query_db("SELECT id FROM contacts WHERE id=? AND org_id=?", (pid, user["org_id"]), one=True)
    if not chk:
        return jsonify(ok=False, error="not_found"), 404
    allowed = {"name","position","phone","email"}
    updates = {k: (data.get(k) or "").strip() for k in allowed if k in data}
    if "email" in updates and updates["email"] and not validate_email(updates["email"]):
        return jsonify(ok=False, error="invalid email"), 400
    if "phone" in updates:
        updates["phone_norm"] = normalize_phone(updates["phone"]) if updates["phone"] else ""
    set_clause, params = _safe_update_clause(set(list(updates.keys())+["phone_norm"]), updates)
    if set_clause:
        set_clause = f"{set_clause}, updated_at=?"
        params.append(utc_now())
        params.extend([pid, user["org_id"]])
        try:
            exec_db_affect(f"UPDATE contacts SET {set_clause} WHERE id=? AND org_id=?", tuple(params))
            _timeline_add(user["org_id"], user["id"], "contact", pid, "updated", updates)
            try:
                add_audit(user["org_id"], user["id"], "contact.updated", "contact", pid, updates)  # type: ignore
            except Exception:
                pass
            return jsonify(ok=True)
        except Exception as e:
            return jsonify(ok=False, error=str(e)), 400
    return jsonify(ok=False, error="no updates"), 400

# ===== END OF STYLES PART 7/10 =====
# ===== START OF STYLES PART 8/10 =====
# coding: utf-8

# ==================== STYLES PART 8/10 ====================
# ===== BLOCK: TEMPLATES — DOCUMENTS (LIST + VIEW/EDIT + TEMPLATES) =====

DOCUMENTS_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Документы</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
    <div style="flex:1;min-width:260px;">
      <label class="muted">Поиск</label>
      <input id="q" class="input" placeholder="Название / тип / компания" value="{{ request.args.get('q','') }}">
    </div>
    <div>
      <button id="btnSearch" class="button">Показать</button>
      <button id="btnNewDoc" class="button secondary">Новый документ</button>
      <button id="btnNewTpl" class="button ghost">Новый шаблон</button>
    </div>
  </div>
</div>

<div class="card">
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
    <!-- Templates -->
    <div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-weight:700;">Шаблоны</div>
        <div class="muted">Всего: {{ templates|length }}</div>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Тип</th>
            <th>Ключ</th>
            <th>Название</th>
            <th>Создан</th>
          </tr>
        </thead>
        <tbody>
          {% for t in templates %}
          <tr>
            <td>{{ t.id }}</td>
            <td><span class="badge">{{ t.type }}</span></td>
            <td>{{ t.tkey or '—' }}</td>
            <td>{{ t.name }}</td>
            <td>{{ t.created_at }}</td>
          </tr>
          {% else %}
          <tr><td colspan="5" class="muted">Нет шаблонов</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <!-- Documents -->
    <div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-weight:700;">Документы</div>
        <div class="muted">Всего: {{ documents|length }}</div>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Тип</th>
            <th>Название</th>
            <th>Компания</th>
            <th>Автор</th>
            <th>Создан</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {% for d in documents %}
          <tr>
            <td>{{ d.id }}</td>
            <td><span class="badge">{{ d.doc_type or '—' }}</span></td>
            <td>{{ d.title }}</td>
            <td>{% if d.company_id %}<a href="/client/{{ d.company_id }}">#{{ d.company_id }}</a>{% else %}—{% endif %}</td>
            <td>{% if d.user_id %}user#{{ d.user_id }}{% else %}—{% endif %}</td>
            <td>{{ d.created_at }}</td>
            <td><a class="button ghost small" href="/document/{{ d.id }}">Открыть</a></td>
          </tr>
          {% else %}
          <tr><td colspan="7" class="muted">Нет документов</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Modal: Новый документ -->
<div class="modal-backdrop" id="modalDoc">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3 style="margin:0;">Новый документ</h3>
      <button class="button ghost small" onclick="closeDocModal()">Закрыть</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;">
      <div style="grid-column:1/3;">
        <label class="muted">Название</label>
        <input id="nd_title" class="input" placeholder="Коммерческое предложение">
      </div>
      <div>
        <label class="muted">Тип</label>
        <input id="nd_type" class="input" value="quote">
      </div>
      <div>
        <label class="muted">Компания (ID)</label>
        <input id="nd_company" class="input" placeholder="например, 1">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Шаблон (опционально)</label>
        <select id="nd_tpl" class="select">
          <option value="">— Без шаблона —</option>
          {% for t in templates %}
            <option value="{{ t.id }}">{{ t.type }} — {{ t.name }}</option>
          {% endfor %}
        </select>
      </div>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">
      <button class="button ghost" onclick="closeDocModal()">Отмена</button>
      <button class="button" onclick="createDoc()">Создать</button>
    </div>
  </div>
</div>

<!-- Modal: Новый шаблон -->
<div class="modal-backdrop" id="modalTpl">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3 style="margin:0;">Новый шаблон</h3>
      <button class="button ghost small" onclick="closeTplModal()">Закрыть</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;">
      <div style="grid-column:1/3;">
        <label class="muted">Название</label>
        <input id="nt_name" class="input" placeholder="КП — SaaS">
      </div>
      <div>
        <label class="muted">Тип</label>
        <input id="nt_type" class="input" value="quote">
      </div>
      <div>
        <label class="muted">Ключ</label>
        <input id="nt_tkey" class="input" placeholder="kp_default">
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Тело (HTML)</label>
        <textarea id="nt_body" class="input" rows="10" placeholder="<h1>КП</h1>"></textarea>
      </div>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">
      <button class="button ghost" onclick="closeTplModal()">Отмена</button>
      <button class="button" onclick="createTpl()">Создать</button>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const Q = (id)=>document.getElementById(id);
  const CSRF = '{{ session.get("csrf_token","") }}';

  // Search
  Q('btnSearch')?.addEventListener('click', ()=>{
    const q = Q('q').value||'';
    const url = new URL(location.href);
    if(q) url.searchParams.set('q', q); else url.searchParams.delete('q');
    location.href = url.toString();
  });
  Q('q')?.addEventListener('keydown', (e)=>{ if(e.key==='Enter'){ Q('btnSearch').click(); } });

  // Modals
  window.closeDocModal = ()=> Q('modalDoc')?.classList.remove('show');
  window.closeTplModal = ()=> Q('modalTpl')?.classList.remove('show');
  Q('btnNewDoc')?.addEventListener('click', ()=> Q('modalDoc')?.classList.add('show'));
  Q('btnNewTpl')?.addEventListener('click', ()=> Q('modalTpl')?.classList.add('show'));

  // Create document
  window.createDoc = async ()=>{
    const title = (Q('nd_title').value||'').trim();
    if(!title){ toast('Укажите название'); return; }
    const payload = {
      title,
      doc_type: Q('nd_type').value||'quote',
      company_id: Q('nd_company').value? Number(Q('nd_company').value): null,
      template_id: Q('nd_tpl').value? Number(Q('nd_tpl').value): null
    };
    try{
      const r=await fetch('/ui/document/create',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(payload)});
      const j=await r.json();
      if(j.ok){ toast('Документ создан'); closeDocModal(); location.href = '/document/'+j.id; }
      else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  };

  // Create template
  window.createTpl = async ()=>{
    const name = (Q('nt_name').value||'').trim();
    const ttype = (Q('nt_type').value||'').trim();
    const tkey = (Q('nt_tkey').value||'').trim();
    const body = Q('nt_body').value||'';
    if(!name || !ttype || !body){ toast('Заполните все обязательные поля'); return; }
    try{
      const r=await fetch('/ui/template/create',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({name, type: ttype, tkey, body_template: body})});
      const j=await r.json();
      if(j.ok){ toast('Шаблон создан'); closeTplModal(); location.reload(); }
      else toast(j.error||'Ошибка');
    }catch(_){ toast('Ошибка сети'); }
  };
})();
</script>
{% endblock %}
""")

DOCUMENT_VIEW_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Документ #{{ doc.id }}</h2>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;">
  <!-- LEFT: Editor -->
  <div class="card">
    <h3 style="margin:0 0 8px 0;">Редактирование</h3>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div>
        <label class="muted">Название</label>
        <input id="d_title" class="input" value="{{ doc.title|e }}">
      </div>
      <div>
        <label class="muted">Тип</label>
        <input id="d_type" class="input" value="{{ doc.doc_type or '' }}">
      </div>
      <div>
        <label class="muted">Компания (ID)</label>
        <input id="d_company" class="input" value="{{ doc.company_id or '' }}">
      </div>
      <div>
        <label class="muted">Шаблон</label>
        <div class="muted">{{ tpl_name or '—' }}</div>
      </div>
      <div style="grid-column:1/3;">
        <label class="muted">Содержимое (HTML)</label>
        <textarea id="d_body" class="input" rows="18">{{ doc.content_html or '' }}</textarea>
      </div>
    </div>
    <div style="margin-top:10px;display:flex;gap:8px;">
      <button id="btnSaveDoc" class="button">Сохранить</button>
      <a class="button ghost" href="/documents">К списку</a>
    </div>
  </div>

  <!-- RIGHT: Preview + Sign -->
  <div class="card">
    <h3 style="margin:0 0 8px 0;">Превью</h3>
    <div id="preview" class="smart" style="max-height:420px;overflow:auto;border:1px dashed var(--border);padding:10px;background:#fff;">
      {{ sanitized_html|safe }}
    </div>
    <div style="margin-top:12px;">
      <h3 style="margin:0 0 8px 0;">ЭДО Подписание</h3>
      <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
        <div>
          <label class="muted">Провайдер</label>
          <select id="edo_provider" class="select">
            <option value="diadoc">diadoc</option>
            <option value="sbis">sbis</option>
            <option value="astral">astral</option>
          </select>
        </div>
        <div>
          <button id="btnSign" class="button">Подписать</button>
        </div>
      </div>
      <div id="edoResult" class="muted" style="margin-top:8px;"></div>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const DID = {{ doc.id }};

  function payload(){
    return {
      id: DID,
      title: document.getElementById('d_title').value || '',
      doc_type: document.getElementById('d_type').value || '',
      company_id: document.getElementById('d_company').value? Number(document.getElementById('d_company').value): null,
      content_html: document.getElementById('d_body').value || ''
    };
  }

  async function saveDoc(){
    try{
      const r=await fetch('/ui/document/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(payload())});
      const j=await r.json();
      toast(j.ok? 'Сохранено' : (j.error||'Ошибка'));
      if(j.ok){
        // update preview optimistically (client-side render; server sanitizes on next load)
        document.getElementById('preview').innerHTML = payload().content_html;
      }
    }catch(_){ toast('Ошибка сети'); }
  }

  async function signDoc(){
    const provider = document.getElementById('edo_provider').value || '';
    if(!provider){ toast('Выберите провайдера'); return; }
    try{
      const r=await fetch('/api/edo/sign',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({provider, document_id: DID, payload:{title: payload().title}})});
      const j=await r.json();
      const box=document.getElementById('edoResult');
      if(j.ok){ box.textContent = 'Запрос отправлен: '+JSON.stringify(j.data||{}); toast('Отправлено на подпись'); }
      else{ box.textContent = 'Ошибка: '+(j.error||''); toast(j.error||'Ошибка ЭДО'); }
    }catch(_){ toast('Ошибка сети'); }
  }

  document.getElementById('btnSaveDoc')?.addEventListener('click', saveDoc);
  document.getElementById('btnSign')?.addEventListener('click', signDoc);
})();
</script>
{% endblock %}
""")

# ===== BLOCK: PAGE ROUTES — DOCUMENTS LIST & DOCUMENT VIEW =====
@app.route("/documents")
@_login_required
def documents_page():
    user = g.user
    q = (request.args.get("q") or "").strip()
    params: List[Any] = [user["org_id"]]
    where_docs = ["org_id=?"]
    if q:
        like = f"%{q}%"
        where_docs.append("(title LIKE ? OR doc_type LIKE ?)")
        params.extend([like, like])
    docs = query_db(f"SELECT * FROM documents WHERE {' AND '.join(where_docs)} ORDER BY created_at DESC LIMIT 500", tuple(params)) or []
    tpls = query_db("SELECT id, type, tkey, name, created_at FROM document_templates WHERE org_id=? ORDER BY created_at DESC LIMIT 500", (user["org_id"],)) or []
    return render_template_string(
        DOCUMENTS_TMPL,
        user=user,
        documents=docs,
        templates=tpls,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

@app.route("/document/<int:doc_id>")
@_login_required
def document_view_page(doc_id: int):
    user = g.user
    doc = query_db("SELECT * FROM documents WHERE id=? AND org_id=?", (doc_id, user["org_id"]), one=True)
    if not doc:
        return Response("Документ не найден", 404)
    tpl_name = None
    if doc.get("template_id"):
        t = query_db("SELECT name FROM document_templates WHERE id=? AND org_id=?", (doc["template_id"], user["org_id"]), one=True)
        tpl_name = (t or {}).get("name")
    sanitized = sanitize_document_html(doc.get("content_html") or "")
    return render_template_string(
        DOCUMENT_VIEW_TMPL,
        user=user,
        doc=doc,
        tpl_name=tpl_name,
        sanitized_html=sanitized,
        css=DESIGN_SYSTEM_CSS,
        js=BASE_JS,
        csp_nonce=g.get("csp_nonce","")
    )

# ===== BLOCK: UI ENDPOINTS — DOCUMENTS & TEMPLATES CRUD =====
@app.route("/ui/document/create", methods=["POST"])
@_login_required
@_csrf_protect
def ui_document_create():
    user = g.user
    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify(ok=False, error="title required"), 400
    doc_type = (data.get("doc_type") or "").strip() or None
    company_id = int(data.get("company_id") or 0) or None
    template_id = int(data.get("template_id") or 0) or None
    content_html = ""
    if template_id:
        tpl = query_db("SELECT body_template FROM document_templates WHERE id=? AND org_id=?", (template_id, user["org_id"]), one=True)
        if tpl and tpl.get("body_template"):
            content_html = tpl["body_template"]
    if not content_html:
        content_html = f"<h1>{title}</h1><p>Документ создан {utc_now()}</p>"
    try:
        doc_id = exec_db(
            "INSERT INTO documents (org_id, template_id, doc_type, title, content_html, company_id, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user["org_id"], template_id, doc_type, title, sanitize_document_html(content_html), company_id, user["id"], utc_now())
        )
        _timeline_add(user["org_id"], user["id"], "document", int(doc_id or 0), "created", {"title": title})
        try:
            add_audit(user["org_id"], user["id"], "document.created", "document", int(doc_id or 0), {"title": title})  # type: ignore
        except Exception:
            pass
        return jsonify(ok=True, id=int(doc_id or 0))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route("/ui/document/update", methods=["POST"])
@_login_required
@_csrf_protect
def ui_document_update():
    user = g.user
    data = request.get_json() or {}
    doc_id = int(data.get("id") or 0)
    if not doc_id:
        return jsonify(ok=False, error="id required"), 400
    doc = query_db("SELECT id FROM documents WHERE id=? AND org_id=?", (doc_id, user["org_id"]), one=True)
    if not doc:
        return jsonify(ok=False, error="not_found"), 404
    allowed = {"title","doc_type","company_id","content_html"}
    updates = {k: data.get(k) for k in allowed if k in data}
    if "content_html" in updates and updates["content_html"] is not None:
        try:
            updates["content_html"] = sanitize_document_html(str(updates["content_html"] or ""))
        except Exception:
            updates["content_html"] = ""
    set_clause, params = _safe_update_clause(set(updates.keys()), updates)
    if not set_clause:
        return jsonify(ok=False, error="no updates"), 400
    set_clause = f"{set_clause}"
    params.extend([doc_id, user["org_id"]])
    try:
        exec_db_affect(f"UPDATE documents SET {set_clause} WHERE id=? AND org_id=?", tuple(params))
        _timeline_add(user["org_id"], user["id"], "document", doc_id, "updated", {k: ("<html>" if k=="content_html" else updates[k]) for k in updates})
        try:
            add_audit(user["org_id"], user["id"], "document.updated", "document", doc_id, {k: ("<html>" if k=="content_html" else updates[k]) for k in updates})  # type: ignore
        except Exception:
            pass
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

@app.route("/ui/template/create", methods=["POST"])
@_login_required
@_csrf_protect
def ui_template_create():
    user = g.user
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    ttype = (data.get("type") or "").strip()
    body = data.get("body_template") or ""
    if not name or not ttype or not body:
        return jsonify(ok=False, error="name, type, body_template are required"), 400
    tkey = (data.get("tkey") or "").strip() or None
    try:
      tid = exec_db(
          "INSERT INTO document_templates (org_id, type, tkey, name, body_template, created_at) VALUES (?, ?, ?, ?, ?, ?)",
          (user["org_id"], ttype, tkey, name, str(body), utc_now())
      )
      try:
          add_audit(user["org_id"], user["id"], "doc_template.created", "document_template", int(tid or 0), {"name": name})  # type: ignore
      except Exception:
          pass
      return jsonify(ok=True, id=int(tid or 0))
    except Exception as e:
      return jsonify(ok=False, error=str(e)), 400

# ===== END OF STYLES PART 8/10 =====
# ===== START OF STYLES PART 9/10 =====
# coding: utf-8

# ==================== STYLES PART 9/10 ====================
# ===== BLOCK: TEMPLATES — DIGITAL TWIN (HEALTH + FORECAST + NBA + SIMULATIONS + INSIGHTS) =====

DIGITAL_TWIN_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Digital Twin</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;">
    <!-- HEALTH & STATE -->
    <div class="smart">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-weight:800;">Состояние и здоровье</div>
        <div>
          <button id="btnRefreshHealth" class="button ghost small">Обновить</button>
        </div>
      </div>
      <div id="healthBox">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
          <div class="badge {{ 'ok' if health.status=='healthy' else ('warn' if health.status=='warning' else 'err') }}">Итоговое здоровье: {{ health.overall }}%</div>
          <div class="muted">Статус: {{ health.status }}</div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <div>
            <label class="muted">Продукты/Продажи</label>
            <div class="smart" style="padding:8px;">
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;">
                <div style="width:140px;" class="muted">Индекс</div>
                <div style="flex:1;background:#e5e7eb;height:10px;border-radius:6px;overflow:hidden;"><div style="width: {{ health.breakdown.sales }}%;height:100%;background:#10b981;"></div></div>
                <div style="width:50px;text-align:right;">{{ health.breakdown.sales }}%</div>
              </div>
              <div class="muted">Pipeline: {{ state.sales.pipeline_value|round(2) }} | Сделок открыто: {{ state.sales.open_deals }} | Конверсия 30д: {{ (state.sales.conversion_rate_30d*100)|round(1) }}%</div>
            </div>
          </div>
          <div>
            <label class="muted">Операции</label>
            <div class="smart" style="padding:8px;">
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;">
                <div style="width:140px;" class="muted">Индекс</div>
                <div style="flex:1;background:#e5e7eb;height:10px;border-radius:6px;overflow:hidden;"><div style="width: {{ health.breakdown.operations }}%;height:100%;background:#0ea5e9;"></div></div>
                <div style="width:50px;text-align:right;">{{ health.breakdown.operations }}%</div>
              </div>
              <div class="muted">Открытые задачи: {{ state.operations.open_tasks }} | Просрочено: {{ state.operations.overdue_tasks }} | Утилизация: {{ (state.operations.team_utilization*100)|round(0) }}%</div>
            </div>
          </div>
          <div>
            <label class="muted">Клиентский успех</label>
            <div class="smart" style="padding:8px;">
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;">
                <div style="width:140px;" class="muted">Индекс</div>
                <div style="flex:1;background:#e5e7eb;height:10px;border-radius:6px;overflow:hidden;"><div style="width: {{ health.breakdown.customer_success }}%;height:100%;background:#f59e0b;"></div></div>
                <div style="width:50px;text-align:right;">{{ health.breakdown.customer_success }}%</div>
              </div>
              <div class="muted">Активных клиентов: {{ state.customer_success.active_customers }} | Отток 30д: {{ (state.customer_success.churn_rate_30d*100)|round(1) }}% | NPS: {{ state.customer_success.nps_score }}</div>
            </div>
          </div>
          <div>
            <label class="muted">Финансы</label>
            <div class="smart" style="padding:8px;">
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;">
                <div style="width:140px;" class="muted">Индекс</div>
                <div style="flex:1;background:#e5e7eb;height:10px;border-radius:6px;overflow:hidden;"><div style="width: {{ health.breakdown.finance }}%;height:100%;background:#2563eb;"></div></div>
                <div style="width:50px;text-align:right;">{{ health.breakdown.finance }}%</div>
              </div>
              <div class="muted">MRR: {{ state.finance.mrr|round(2) }} | ARR: {{ state.finance.arr|round(2) }} | План: {{ state.finance.target_month|round(0) }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- NBA -->
    <div class="smart">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-weight:800;">Next Best Actions</div>
        <div>
          <button id="btnRefreshNBA" class="button ghost small">Обновить</button>
        </div>
      </div>
      <ul id="nbaList" style="padding-left:18px;margin:6px 0 0 0;">
        {% for a in nba %}<li>{{ a.text }}</li>{% else %}<li class="muted">Нет рекомендаций</li>{% endfor %}
      </ul>
    </div>
  </div>
</div>

<!-- FORECASTS -->
<div class="card" style="margin-bottom:12px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div style="font-weight:800;">Прогнозы на 30 дней</div>
    <div><button id="btnRefreshForecast" class="button ghost small">Обновить</button></div>
  </div>
  <div id="forecastBox" style="display:grid;grid-template-columns:2fr 1fr;gap:12px;">
    <div class="smart">
      <div style="font-weight:700;margin-bottom:6px;">Сделки к закрытию</div>
      <div id="dealsToClose">
        {% for d in forecast.deals_to_close %}
        <div class="smart" style="margin:6px 0;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div style="font-weight:700;">#{{ d.deal_id }} — {{ d.title }}</div>
            <div class="badge ok">{{ d.amount }} / {{ (d.close_probability*100)|round(0) }}%</div>
          </div>
          <div class="muted">Ожидаемая дата: {{ d.expected_close_date }}</div>
          <div class="muted">Рекоммендации: {{ d.recommended_actions|join(', ') }}</div>
        </div>
        {% else %}
        <div class="muted">Нет кандидатов</div>
        {% endfor %}
      </div>
    </div>
    <div class="smart">
      <div style="font-weight:700;margin-bottom:6px;">Итоги</div>
      <div class="badge">Ожидаемая выручка 30д: {{ forecast.revenue_forecast.expected_30d|round(2) }}</div>
      <div class="badge warn" style="margin-top:6px;">Отток 30д: {{ (forecast.churn_risk.churn_rate_30d*100)|round(1) }}% (~{{ forecast.churn_risk.at_risk_customers }})</div>
      <div class="badge info" style="margin-top:6px;">Вместимость команды/неделя: {{ forecast.team_capacity.capacity_per_week }}</div>
      <div class="badge" style="margin-top:6px;">Бэклог (дней): {{ forecast.team_capacity.estimated_backlog_days }}</div>
    </div>
  </div>
</div>

<!-- SIMULATIONS -->
<div class="card" style="margin-bottom:12px;">
  <div style="font-weight:800;margin-bottom:8px;">Симуляции</div>
  <div class="smart" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
    <div>
      <label class="muted">Сценарий</label>
      <select id="simType" class="select">
        <option value="hire_salesperson">Наём менеджера по продажам</option>
        <option value="increase_prices">Повышение цен</option>
        <option value="increase_marketing_budget">Увеличение маркетингового бюджета</option>
      </select>
    </div>
    <div>
      <label class="muted">Параметры</label>
      <div id="simParams" class="smart">
        <!-- динамически заполняется -->
      </div>
    </div>
    <div style="grid-column:1/3;display:flex;gap:8px;justify-content:flex-end;">
      <button id="btnRunSim" class="button">Запустить</button>
    </div>
    <div style="grid-column:1/3;">
      <div style="font-weight:700;margin-bottom:6px;">Результат</div>
      <div id="simResult" class="smart muted">—</div>
    </div>
  </div>
</div>

<!-- INSIGHTS FEED -->
<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div style="font-weight:800;">Инсайты (SSE)</div>
    <div><button id="btnRefreshInsights" class="button ghost small">Обновить</button></div>
  </div>
  <div id="insightsBox" class="smart"></div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const USER_ID = Number((document.body||{}).getAttribute('data-userid')||0);

  function setHTML(id, html){ const el=document.getElementById(id); if(el) el.innerHTML = html; }
  function esc(s){ if(s==null) return ''; const d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; }

  // Refresh Health
  async function refreshHealth(){
    try{
      const r=await fetch('/ui/twin/health');
      const j=await r.json();
      if(j.ok){
        // Simple client render (compact)
        const h=j.health||{}, st=j.state||{};
        const mkbar = (label,val,color)=>`
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;">
            <div style="width:140px;" class="muted">${label}</div>
            <div style="flex:1;background:#e5e7eb;height:10px;border-radius:6px;overflow:hidden;"><div style="width:${val||0}%;height:100%;background:${color};"></div></div>
            <div style="width:50px;text-align:right;">${(val||0)}%</div>
          </div>`;
        const html = `
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
            <div class="badge ${h.status==='healthy'?'ok':(h.status==='warning'?'warn':'err')}">Итоговое здоровье: ${h.overall||0}%</div>
            <div class="muted">Статус: ${esc(h.status||'')}</div>
          </div>
          ${mkbar('Продажи', (h.breakdown||{}).sales||0, '#10b981')}
          ${mkbar('Операции', (h.breakdown||{}).operations||0, '#0ea5e9')}
          ${mkbar('Клиентский успех', (h.breakdown||{}).customer_success||0, '#f59e0b')}
          ${mkbar('Финансы', (h.breakdown||{}).finance||0, '#2563eb')}
          <div class="muted">Pipeline: ${((st.sales||{}).pipeline_value||0)} | Откр. сделки: ${((st.sales||{}).open_deals||0)} | Конверсия 30д: ${Math.round((((st.sales||{}).conversion_rate_30d||0)*100)*10)/10}%</div>
        `;
        setHTML('healthBox', html);
      }
    }catch(_){}
  }

  // NBA
  async function refreshNBA(){
    try{
      const r=await fetch('/ui/twin/nba');
      const j=await r.json();
      if(j.ok){
        const items=(j.nba||[]).map(a=> `<li>${esc(a.text||'')}</li>`).join('') || '<li class="muted">Нет рекомендаций</li>';
        setHTML('nbaList', items);
      }
    }catch(_){}
  }

  // Forecast
  async function refreshForecast(){
    try{
      const r=await fetch('/ui/twin/forecast');
      const j=await r.json();
      if(j.ok){
        const d = j.forecast||{};
        const deals = (d.deals_to_close||[]).map(x=>`
          <div class="smart" style="margin:6px 0;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div style="font-weight:700;">#${esc(x.deal_id)} — ${esc(x.title||'')}</div>
              <div class="badge ok">${esc(x.amount)} / ${Math.round((x.close_probability||0)*100)}%</div>
            </div>
            <div class="muted">Ожид.: ${esc(x.expected_close_date||'')}</div>
            <div class="muted">${(x.recommended_actions||[]).join(', ')}</div>
          </div>
        `).join('') || '<div class="muted">Нет кандидатов</div>';
        const right = `
          <div style="font-weight:700;margin-bottom:6px;">Итоги</div>
          <div class="badge">Ожидаемая выручка 30д: ${(d.revenue_forecast||{}).expected_30d||0}</div>
          <div class="badge warn" style="margin-top:6px;">Отток 30д: ${Math.round((((d.churn_risk||{}).churn_rate_30d||0)*100)*10)/10}% (~${((d.churn_risk||{}).at_risk_customers||0)})</div>
          <div class="badge info" style="margin-top:6px;">Вместимость/неделя: ${((d.team_capacity||{}).capacity_per_week||0)}</div>
          <div class="badge" style="margin-top:6px;">Бэклог (дней): ${((d.team_capacity||{}).estimated_backlog_days||0)}</div>`;
        setHTML('dealsToClose', deals);
        document.querySelector('#forecastBox .smart:nth-child(2)').innerHTML = right;
      }
    }catch(_){}
  }

  // Simulations
  function renderSimParams(){
    const type = document.getElementById('simType').value;
    let html = '';
    if(type==='hire_salesperson'){
      html = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
          <div><label class="muted">Сделок/мес</label><input id="sim_deals_per_month" class="input" type="number" value="10"></div>
          <div><label class="muted">Оклад/мес</label><input id="sim_monthly_salary" class="input" type="number" value="100000"></div>
        </div>`;
    }else if(type==='increase_prices'){
      html = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
          <div><label class="muted">Рост цен, %</label><input id="sim_increase_percent" class="input" type="number" value="10"></div>
          <div><label class="muted">Рост оттока, %</label><input id="sim_expected_churn_increase" class="input" type="number" value="5"></div>
        </div>`;
    }else{
      html = `
        <div style="display:grid;grid-template-columns:1fr;gap:8px;">
          <div><label class="muted">Рост бюджета, %</label><input id="sim_budget_increase_percent" class="input" type="number" value="20"></div>
        </div>`;
    }
    document.getElementById('simParams').innerHTML = html;
  }

  async function runSim(){
    const type = document.getElementById('simType').value;
    const payload = { type };
    if(type==='hire_salesperson'){
      payload.deals_per_month = Number(document.getElementById('sim_deals_per_month').value||10);
      payload.monthly_salary = Number(document.getElementById('sim_monthly_salary').value||100000);
    }else if(type==='increase_prices'){
      payload.increase_percent = Number(document.getElementById('sim_increase_percent').value||10);
      payload.expected_churn_increase = Number(document.getElementById('sim_expected_churn_increase').value||5);
    }else{
      payload.budget_increase_percent = Number(document.getElementById('sim_budget_increase_percent').value||20);
    }
    try{
      const r=await fetch('/ui/twin/simulate',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({scenario: payload})});
      const j=await r.json();
      document.getElementById('simResult').textContent = j.ok? JSON.stringify(j.simulation||j.result||{}, null, 2) : (j.error||'Ошибка');
      if(!j.ok) document.getElementById('simResult').classList.add('err');
    }catch(_){ document.getElementById('simResult').textContent='Ошибка сети'; }
  }

  // Insights
  function refreshInsights(){
    try{
      const key = 'notif_'+(USER_ID||0);
      const arr = JSON.parse(localStorage.getItem(key)||'[]').filter(x=> (x.kind==='insight'));
      const html = arr.length? arr.slice(0,50).map(x=>`
        <div class="smart" style="margin:6px 0;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div style="font-weight:700;">${esc(x.title||'Insight')}</div>
            <div class="muted">${esc(x.ts||'')}</div>
          </div>
          <div class="muted" style="margin-top:4px;">${esc(x.body||'')}</div>
        </div>
      `).join('') : '<div class="muted">Пока нет инсайтов</div>';
      setHTML('insightsBox', html);
    }catch(_){ setHTML('insightsBox','<div class="muted">—</div>'); }
  }

  // Bindings
  document.getElementById('btnRefreshHealth')?.addEventListener('click', refreshHealth);
  document.getElementById('btnRefreshNBA')?.addEventListener('click', refreshNBA);
  document.getElementById('btnRefreshForecast')?.addEventListener('click', refreshForecast);
  document.getElementById('btnRefreshInsights')?.addEventListener('click', refreshInsights);
  document.getElementById('simType')?.addEventListener('change', renderSimParams);
  document.getElementById('btnRunSim')?.addEventListener('click', runSim);

  // Init
  renderSimParams();
  refreshInsights();
})();
</script>
{% endblock %}
""")

# ===== BLOCK: PAGE ROUTE — DIGITAL TWIN =====
@app.route("/digital_twin")
@_login_required
def digital_twin_page():
    user = g.user
    try:
        twin = BusinessTwin(user["org_id"])
        health = twin.get_health_score()
        forecast = twin.predict_next_30_days()
        nba = twin.next_best_actions(limit=5)  # type: ignore
        return render_template_string(
            DIGITAL_TWIN_TMPL,
            user=user,
            health=health,
            forecast=forecast,
            nba=nba,
            state=twin.state,
            css=DESIGN_SYSTEM_CSS,
            js=BASE_JS,
            csp_nonce=g.get("csp_nonce","")
        )
    except Exception as e:
        return Response(f"Digital Twin error: {e}", 500)

# ===== BLOCK: UI ENDPOINTS — TWIN HEALTH / FORECAST / NBA / SIMULATE / DECISION-CENTER BRIDGE =====
@app.route("/ui/twin/health", methods=["GET"])
@_login_required
def ui_twin_health():
    user = g.user
    try:
        twin = BusinessTwin(user["org_id"])
        return jsonify(ok=True, health=twin.get_health_score(), state=twin.state)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/ui/twin/forecast", methods=["GET"])
@_login_required
def ui_twin_forecast():
    user = g.user
    try:
        twin = BusinessTwin(user["org_id"])
        return jsonify(ok=True, forecast=twin.predict_next_30_days())
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/ui/twin/nba", methods=["GET"])
@_login_required
def ui_twin_nba():
    user = g.user
    lim = 5
    try:
        lim = int(request.args.get("limit") or "5")
    except Exception:
        lim = 5
    try:
        twin = BusinessTwin(user["org_id"])
        return jsonify(ok=True, nba=twin.next_best_actions(limit=lim))  # type: ignore
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/ui/twin/simulate", methods=["POST"])
@_login_required
@_csrf_protect
def ui_twin_simulate():
    user = g.user
    data = request.get_json() or {}
    scenario = data.get("scenario") or {}
    try:
        twin = BusinessTwin(user["org_id"])
        return jsonify(ok=True, simulation=twin.simulate_scenario(scenario))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/ui/twin/consult", methods=["POST"])
@_login_required
@_csrf_protect
def ui_twin_consult():
    """
    Универсальный мост к DecisionCenter.consult.
    Пример payload: {"kind":"forecast"} | {"kind":"nba"} | {"kind":"simulate","scenario":{...}} | {"kind":"rag_answer","q":"...","entity_type":"kb_doc"}
    """
    data = request.get_json() or {}
    kind = (data.get("kind") or "").strip() or "nba"
    query = {"org_id": g.user["org_id"], **data}
    try:
        res = DECISION_CENTER.consult(query)  # type: ignore
        return jsonify(res if isinstance(res, dict) else {"ok": False, "error": "invalid_result"})
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

# ===== END OF STYLES PART 9/10 =====
# ===== START OF STYLES PART 10/10 =====
# coding: utf-8

# ==================== STYLES PART 10/10 ====================
# ===== BLOCK: TEMPLATES — AGENTS (LIST/EDITOR/TEST/ОРКЕСТРАТОР) + SETTINGS (SYSTEM/NOTIFY/THEME) =====

AGENTS_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Агенты</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:grid;grid-template-columns:1fr 2fr;gap:12px;">
    <!-- Left: list -->
    <div class="smart">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <div style="font-weight:800;">Сохранённые агенты</div>
        <button id="btnReload" class="button ghost small" type="button">Обновить</button>
      </div>
      <div id="agentsList" class="smart" style="max-height:420px;overflow:auto;">
        <div class="muted">Загрузка…</div>
      </div>
    </div>

    <!-- Right: editor/test -->
    <div class="smart">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:6px;">
        <input id="a_name" class="input" placeholder="Имя агента (уникально)" style="flex:1;min-width:180px;">
        <input id="a_desc" class="input" placeholder="Описание" style="flex:1;min-width:180px;">
        <label style="display:flex;gap:6px;align-items:center;"><input id="a_active" type="checkbox" checked>Активен</label>
        <button id="btnSaveDef" class="button" type="button">Сохранить</button>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div>
          <label class="muted">Граф дефиниции (JSON)</label>
          <textarea id="a_graph" class="input" rows="18" placeholder='{"start_node":"...","nodes":{...}}'></textarea>
        </div>
        <div>
          <label class="muted">Контекст (JSON)</label>
          <textarea id="a_ctx" class="input" rows="18" placeholder='{"org_id":{{ user.org_id }},"user_id":{{ user.id }}}'></textarea>
        </div>
      </div>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
        <button id="btnTestDef" class="button ghost" type="button">Тест дефиниции</button>
        <button id="btnRunByName" class="button ghost" type="button">Запустить по имени</button>
      </div>
      <div id="a_result" class="smart muted" style="margin-top:8px;white-space:pre-wrap;max-height:260px;overflow:auto;">—</div>
    </div>
  </div>
</div>

<!-- Orchestrator -->
<div class="card">
  <div style="font-weight:800;margin-bottom:6px;">Оркестратор</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
    <div>
      <label class="muted">План (JSON-массив шагов, пример: [{"agent":"sales","context":{"company_id":1}}, ...])</label>
      <textarea id="o_plan" class="input" rows="10" placeholder='[{"agent":"sales","context":{"company_id":1}},{"agent":"inbox","context":{"thread_id":123}}]'></textarea>
    </div>
    <div>
      <label class="muted">Глобальный контекст (JSON, опционально)</label>
      <textarea id="o_ctx" class="input" rows="10" placeholder='{}'></textarea>
    </div>
  </div>
  <div style="margin-top:8px;display:flex;gap:8px;justify-content:flex-end;">
    <button id="btnRunOrch" class="button" type="button">Запустить оркестрацию</button>
  </div>
  <div id="o_result" class="smart muted" style="margin-top:8px;white-space:pre-wrap;">—</div>
</div>

<!-- Lightweight Command Palette for this page (Ctrl+K) -->
<div id="kpBackdrop" class="modal-backdrop" style="backdrop-filter:blur(2px);">
  <div class="modal" style="max-width:760px;">
    <div style="display:flex;gap:8px;align-items:center;">
      <input id="kpInput" class="input" placeholder="Команда… (например, 'создать задачу позвонить клиенту завтра')" autofocus>
      <button id="kpClose" class="button ghost small" type="button">Закрыть</button>
    </div>
    <div id="kpHint" class="muted" style="margin-top:8px;">Поддержка: go | create_task | create_deal | search | summarize_thread | run_agent | orchestrate | bi_query | rag_answer</div>
    <div id="kpOut" class="smart muted" style="margin-top:8px;white-space:pre-wrap;max-height:240px;overflow:auto;">—</div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const Q = (s)=>document.querySelector(s);
  const ESC = (s)=>{ if(s==null) return ''; const d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; };

  // Agents list
  async function loadAgents(){
    const box = Q('#agentsList'); box.innerHTML = '<div class="muted">Загрузка…</div>';
    try{
      const r=await fetch('/api/agents/list'); const j=await r.json();
      if(j.ok){
        const items = (j.items||[]).map(a=>`
          <div class="smart" style="margin:6px 0;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div>
                <div style="font-weight:700;">${ESC(a.name)}</div>
                <div class="muted">${ESC(a.description||'')}</div>
              </div>
              <div style="display:flex;gap:6px;align-items:center;">
                <span class="badge ${a.active?'ok':'warn'}">${a.active?'active':'inactive'}</span>
                <button class="button ghost small" type="button" data-name="${ESC(a.name)}" data-json="${ESC(a.graph_json||'')}">Открыть</button>
              </div>
            </div>
          </div>`).join('') || '<div class="muted">Нет агентов</div>';
        box.innerHTML = items;
        box.querySelectorAll('button[data-name]').forEach(b=>{
          b.addEventListener('click', ()=>{
            Q('#a_name').value = b.getAttribute('data-name')||'';
            Q('#a_graph').value = b.getAttribute('data-json')||'{}';
            Q('#a_desc').value = '';
            Q('#a_active').checked = true;
          });
        });
      }else box.innerHTML = '<div class="muted">Ошибка</div>';
    }catch(_){ box.innerHTML = '<div class="muted">Сеть недоступна</div>'; }
  }

  async function saveDef(){
    const name = (Q('#a_name').value||'').trim(); if(!name){ toast('Укажите имя'); return; }
    let graph = {}; try{ graph = JSON.parse(Q('#a_graph').value||'{}'); }catch(e){ toast('Некорректный JSON графа'); return; }
    const payload = {name, description: Q('#a_desc').value||'', graph, active: Q('#a_active').checked};
    try{
      const r=await fetch('/api/agent/definition/save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify(payload)});
      const j=await r.json(); toast(j.ok? 'Сохранено' : (j.error||'Ошибка')); if(j.ok) loadAgents();
    }catch(_){ toast('Ошибка сети'); }
  }

  async function testDef(){
    let graph = {}; let ctx={};
    try{ graph = JSON.parse(Q('#a_graph').value||'{}'); }catch(e){ toast('Некорректный JSON графа'); return; }
    try{ ctx = JSON.parse(Q('#a_ctx').value||'{}'); }catch(e){ ctx={}; }
    try{
      const r=await fetch('/api/agent/test',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({definition: graph, context: ctx})});
      const j=await r.json(); Q('#a_result').textContent = JSON.stringify(j, null, 2);
    }catch(_){ Q('#a_result').textContent='Ошибка сети'; }
  }

  async function runByName(){
    const agent = (Q('#a_name').value||'').trim(); if(!agent){ toast('Укажите имя'); return; }
    let ctx={}; try{ ctx = JSON.parse(Q('#a_ctx').value||'{}'); }catch(e){ ctx={}; }
    try{
      const r=await fetch('/api/agent/run',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({agent, context: ctx})});
      const j=await r.json(); Q('#a_result').textContent = JSON.stringify(j, null, 2);
    }catch(_){ Q('#a_result').textContent='Ошибка сети'; }
  }

  async function runOrchestrator(){
    let plan=[]; let ctx={};
    try{ plan = JSON.parse(Q('#o_plan').value||'[]'); }catch(e){ toast('Некорректный JSON плана'); return; }
    try{ ctx = JSON.parse(Q('#o_ctx').value||'{}'); }catch(e){ ctx={}; }
    try{
      const r=await fetch('/api/agents/orchestrate',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({plan, context: ctx})});
      const j=await r.json(); Q('#o_result').textContent = JSON.stringify(j, null, 2);
    }catch(_){ Q('#o_result').textContent='Ошибка сети'; }
  }

  // Command palette (local for this page)
  const bp = Q('#kpBackdrop'); const inp = Q('#kpInput'); const out = Q('#kpOut');
  function openPalette(){ bp.classList.add('show'); setTimeout(()=> inp&&inp.focus(), 0); out.textContent='—'; }
  function closePalette(){ bp.classList.remove('show'); }
  async function execPalette(){
    const cmd = (inp.value||'').trim(); if(!cmd) return;
    try{
      const ctx = {}; // could be extended
      const r=await fetch('/api/ai/command',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({command: cmd, context: ctx})});
      const j=await r.json(); out.textContent = JSON.stringify(j, null, 2);
      if(j.ok && j.action==='navigate' && j.url){ location.href = j.url; }
    }catch(_){ out.textContent='Ошибка сети'; }
  }

  document.addEventListener('keydown', (e)=>{
    if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='k'){ e.preventDefault(); openPalette(); }
    if(e.key==='Escape'){ closePalette(); }
  });
  Q('#kpClose')?.addEventListener('click', closePalette);
  Q('#kpInput')?.addEventListener('keydown',(e)=>{ if(e.key==='Enter'){ execPalette(); } });

  // Bindings
  Q('#btnReload')?.addEventListener('click', loadAgents);
  Q('#btnSaveDef')?.addEventListener('click', saveDef);
  Q('#btnTestDef')?.addEventListener('click', testDef);
  Q('#btnRunByName')?.addEventListener('click', runByName);
  Q('#btnRunOrch')?.addEventListener('click', runOrchestrator);

  // Init
  loadAgents();
  Q('#a_ctx').value = JSON.stringify({org_id: {{ user.org_id }}, user_id: {{ user.id }}}, null, 2);
})();
</script>
{% endblock %}
""")

SETTINGS_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Настройки</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
    <div class="smart">
      <div style="font-weight:800;margin-bottom:6px;">Система</div>
      <div id="sysInfo" class="smart muted">Загрузка…</div>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
        <button id="btnReloadInfo" class="button ghost" type="button">Обновить</button>
        <button id="btnHealth" class="button ghost" type="button">Проверка /health</button>
        <button id="btnReady" class="button ghost" type="button">Проверка /readyz</button>
      </div>
      <div id="healthBox" class="smart muted" style="margin-top:8px;">—</div>
      <div id="readyBox" class="smart muted" style="margin-top:8px;">—</div>
    </div>

    <div class="smart">
      <div style="font-weight:800;margin-bottom:6px;">Уведомления и тема</div>
      <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
        <div>
          <label class="muted">Тест уведомления</label><br>
          <button id="btnNotify" class="button" type="button">Отправить</button>
        </div>
        <div>
          <label class="muted">Очистить локальные уведомления</label><br>
          <button id="btnClearNotif" class="button ghost" type="button">Очистить</button>
        </div>
        <div style="min-width:220px;">
          <label class="muted">Тема</label>
          <select id="themeSel" class="select">
            <option value="light" {% if user.theme=='light' %}selected{% endif %}>Светлая</option>
            <option value="dark" {% if user.theme=='dark' %}selected{% endif %}>Тёмная</option>
          </select>
        </div>
        <div>
          <button id="btnApplyTheme" class="button ghost" type="button">Применить</button>
        </div>
      </div>
      <div class="muted" style="margin-top:8px;">Текущая тема: {{ user.theme or 'light' }}</div>
    </div>
  </div>
</div>

<!-- Lightweight Command Palette for this page -->
<div id="kpBackdrop" class="modal-backdrop" style="backdrop-filter:blur(2px);">
  <div class="modal" style="max-width:760px;">
    <div style="display:flex;gap:8px;align-items:center;">
      <input id="kpInput" class="input" placeholder="Команда… (Ctrl+K)" autofocus>
      <button id="kpClose" class="button ghost small" type="button">Закрыть</button>
    </div>
    <div id="kpOut" class="smart muted" style="margin-top:8px;white-space:pre-wrap;max-height:240px;overflow:auto;">—</div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const CSRF = '{{ session.get("csrf_token","") }}';
  const USER_ID = Number((document.body||{}).getAttribute('data-userid')||0);

  // System info
  async function loadInfo(){
    try{
      const r=await fetch('/api/system/info'); const j=await r.json();
      if(j.ok){
        const keys=['version','env','dialect','storage_backend','ai_provider','redis_available','sse_enabled','rate_limit_enabled','cache_enabled','debug'];
        const html = keys.map(k=> `<div><span class="muted">${k}:</span> <b>${(j[k]!==undefined)? j[k] : '-'}</b></div>`).join('');
        document.getElementById('sysInfo').innerHTML = html;
      }else document.getElementById('sysInfo').textContent = j.error||'Ошибка';
    }catch(_){ document.getElementById('sysInfo').textContent='Сеть недоступна'; }
  }

  async function probeHealth(){
    try{
      const r=await fetch('/health'); const j=await r.json();
      document.getElementById('healthBox').textContent = JSON.stringify(j, null, 2);
    }catch(_){ document.getElementById('healthBox').textContent='Сеть недоступна'; }
  }
  async function probeReady(){
    try{
      const r=await fetch('/readyz'); const j=await r.json();
      document.getElementById('readyBox').textContent = JSON.stringify(j, null, 2);
    }catch(_){ document.getElementById('readyBox').textContent='Сеть недоступна'; }
  }

  // Notify test
  async function sendNotify(){
    try{
      const r=await fetch('/ui/notify/test',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({title:'Тест уведомления',body:'Проверка центра уведомлений',kind:'info'})});
      const j=await r.json(); toast(j.ok? 'Отправлено' : (j.error||'Ошибка'));
    }catch(_){ toast('Ошибка сети'); }
  }

  // Theme
  function injectTheme(theme){
    const dark = `
    :root{
      --bg:#0b1020;--fg:#e5e7eb;--surface:#0f1629;--panel:#101827;--panel-strong:#1f2937;--border:#1f2937;
      --muted:#9ca3af;--primary:#60a5fa;--accent:#34d399;--ok:#10b981;--info:#38bdf8;--warn:#f59e0b;--err:#ef4444;
      --shadow-sm:0 1px 2px rgba(0,0,0,.5);--shadow-md:0 4px 12px rgba(0,0,0,.5);
    }`;
    let style = document.getElementById('themeStyle');
    if(!style){ style = document.createElement('style'); style.id='themeStyle'; document.head.appendChild(style); }
    style.textContent = (theme==='dark')? dark : '';
  }
  async function applyTheme(){
    const theme = document.getElementById('themeSel').value||'light';
    injectTheme(theme);
    try{
      await fetch('/api/profile',{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({theme})});
      toast('Тема применена');
    }catch(_){ /* ignore */ }
  }

  // Palette (local)
  const bp = document.getElementById('kpBackdrop'); const inp = document.getElementById('kpInput'); const out = document.getElementById('kpOut');
  function openPalette(){ bp.classList.add('show'); setTimeout(()=> inp&&inp.focus(), 0); out.textContent='—'; }
  function closePalette(){ bp.classList.remove('show'); }
  async function execPalette(){
    const cmd = (inp.value||'').trim(); if(!cmd) return;
    try{
      const r=await fetch('/api/ai/command',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':CSRF},body:JSON.stringify({command: cmd, context: {}})});
      const j=await r.json(); out.textContent = JSON.stringify(j, null, 2);
      if(j.ok && j.action==='navigate' && j.url){ location.href = j.url; }
    }catch(_){ out.textContent='Ошибка сети'; }
  }
  document.addEventListener('keydown', (e)=>{
    if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='k'){ e.preventDefault(); openPalette(); }
    if(e.key==='Escape'){ closePalette(); }
  });
  document.getElementById('kpClose')?.addEventListener('click', closePalette);
  document.getElementById('kpInput')?.addEventListener('keydown',(e)=>{ if(e.key==='Enter'){ execPalette(); } });

  // Bindings
  document.getElementById('btnReloadInfo')?.addEventListener('click', loadInfo);
  document.getElementById('btnHealth')?.addEventListener('click', probeHealth);
  document.getElementById('btnReady')?.addEventListener('click', probeReady);
  document.getElementById('btnNotify')?.addEventListener('click', sendNotify);
  document.getElementById('btnClearNotif')?.addEventListener('click', ()=>{ try{ localStorage.removeItem('notif_'+(USER_ID||0)); toast('Очищено'); }catch(_){} });
  document.getElementById('btnApplyTheme')?.addEventListener('click', applyTheme);

  // Init
  loadInfo();
  injectTheme('{{ user.theme or "light" }}');
})();
</script>
{% endblock %}
""")

# ===== BLOCK: ANALYTICS PAGE =====
ANALYTICS_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Аналитика</h2>

<div class="card" style="margin-bottom:12px;">
  <div class="smart">
    <div style="font-weight:800;margin-bottom:6px;">Сводные метрики (быстрый обзор)</div>
    <div id="dashBox" class="smart muted">Загрузка…</div>
    <div style="margin-top:8px;">
      <button id="btnReloadDash" class="button ghost small" type="button">Обновить</button>
    </div>
  </div>
</div>

<div class="card">
  <div class="smart">
    <div style="font-weight:800;margin-bottom:6px;">Conversational BI (NL→ответ)</div>
    <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
      <input id="bi_q" class="input" placeholder="Например: Сколько закрыли сделок за месяц?" style="flex:1;min-width:280px;">
      <button id="btnBI" class="button" type="button">Спросить</button>
    </div>
    <div id="bi_out" class="smart muted" style="margin-top:8px;white-space:pre-wrap;">—</div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  async function loadDash(){
    try{
      const res = await fetch('/ui/twin/health');
      const j = await res.json();
      if(j.ok){
        const s = j.state||{};
        const html = `
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;">
            <div class="smart"><div class="muted">Открытые задачи</div><div style="font-weight:800;font-size:20px;">${(s.operations||{}).open_tasks||0}</div></div>
            <div class="smart"><div class="muted">Откр. сделки</div><div style="font-weight:800;font-size:20px;">${(s.sales||{}).open_deals||0}</div></div>
            <div class="smart"><div class="muted">Pipeline</div><div style="font-weight:800;font-size:20px;">${Math.round(((s.sales||{}).pipeline_value||0))}</div></div>
            <div class="smart"><div class="muted">MRR</div><div style="font-weight:800;font-size:20px;">${(s.finance||{}).mrr||0}</div></div>
          </div>`;
        document.getElementById('dashBox').innerHTML = html;
      } else {
        document.getElementById('dashBox').textContent = j.error||'Ошибка';
      }
    }catch(_){ document.getElementById('dashBox').textContent='Сеть недоступна'; }
  }
  async function askBI(){
    const q = (document.getElementById('bi_q').value||'').trim();
    if(!q){ return; }
    document.getElementById('bi_out').textContent = 'Выполняю запрос...';
    try{
      const r = await fetch('/api/bi/query',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:JSON.stringify({q})});
      const j = await r.json();
      document.getElementById('bi_out').textContent = JSON.stringify(j.result||j, null, 2);
    }catch(_){ document.getElementById('bi_out').textContent='Ошибка сети'; }
  }
  document.getElementById('btnReloadDash')?.addEventListener('click', loadDash);
  document.getElementById('btnBI')?.addEventListener('click', askBI);
  loadDash();
})();
</script>
{% endblock %}
""")

@app.route("/analytics")
@_login_required
def analytics_page():
    return render_template_string(
        ANALYTICS_TMPL,
        user=g.user, css=DESIGN_SYSTEM_CSS, js=BASE_JS, csp_nonce=g.get("csp_nonce","")
    )

# ===== BLOCK: PAYROLL PAGE =====
PAYROLL_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Зарплата</h2>

<div class="card" style="margin-bottom:12px;">
  <div class="smart">
    <div style="font-weight:800;margin-bottom:6px;">Планы</div>
    <div id="plansBox" class="smart muted">Загрузка…</div>
    <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-top:8px;">
      <input id="pl_name" class="input" placeholder="Название плана">
      <textarea id="pl_cfg" class="input" rows="3" placeholder='{"base_salary":50000,"percent_of_sales":0.03}'></textarea>
      <button id="btnPlanUpsert" class="button" type="button">Сохранить план</button>
    </div>
  </div>
</div>

<div class="card" style="margin-bottom:12px;">
  <div class="smart">
    <div style="font-weight:800;margin-bottom:6px;">Период</div>
    <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
      <input id="per_key" class="input" placeholder="2025-10">
      <input id="per_from" class="input" type="datetime-local">
      <input id="per_to" class="input" type="datetime-local">
      <button id="btnPerEnsure" class="button ghost" type="button">Создать/обновить период</button>
      <button id="btnPerRecalc" class="button" type="button">Пересчитать</button>
      <button id="btnPerLock" class="button warn" type="button">Заблокировать</button>
    </div>
    <div id="per_out" class="smart muted" style="margin-top:8px;">—</div>
  </div>
</div>

<div class="card">
  <div class="smart">
    <div style="font-weight:800;margin-bottom:6px;">Итог по пользователю</div>
    <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
      <input id="sum_user" class="input" placeholder="User ID">
      <input id="sum_period" class="input" placeholder="Период (2025-10)">
      <button id="btnSummary" class="button" type="button">Показать</button>
    </div>
    <div id="sum_out" class="smart muted" style="margin-top:8px;white-space:pre-wrap;">—</div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  async function loadPlans(){
    try{
      const r=await fetch('/api/payroll/plan/list'); const j=await r.json();
      if(j.ok){
        const items = (j.items||[]).map(p=> `<div class="smart" style="margin:6px 0;"><div style="font-weight:700;">${p.name}</div><div class="muted">${p.description||''}</div></div>`).join('') || '<div class="muted">Нет планов</div>';
        document.getElementById('plansBox').innerHTML = items;
      }else{ document.getElementById('plansBox').textContent = j.error||'Ошибка'; }
    }catch(_){ document.getElementById('plansBox').textContent='Сеть недоступна'; }
  }
  async function planUpsert(){
    const name=(document.getElementById('pl_name').value||'').trim();
    if(!name){ return; }
    let cfg={}; try{ cfg=JSON.parse(document.getElementById('pl_cfg').value||'{}'); }catch(_){}
    const r=await fetch('/api/payroll/plan/upsert',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:JSON.stringify({name,config:cfg,active:true})});
    const j=await r.json(); if(j.ok){ loadPlans(); toast('План сохранен'); }
  }
  async function perEnsure(){
    const key=(document.getElementById('per_key').value||'').trim();
    const ds=document.getElementById('per_from').value; const de=document.getElementById('per_to').value;
    const r=await fetch('/api/payroll/period/ensure',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:JSON.stringify({period_key:key,date_start:ds?ds.replace('T',' ')+':00':null,date_end:de?de.replace('T',' ')+':00':null})});
    const j=await r.json(); document.getElementById('per_out').textContent = JSON.stringify(j, null, 2);
  }
  async function perRecalc(){
    const key=(document.getElementById('per_key').value||'').trim();
    const r=await fetch('/api/payroll/period/recalc',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:JSON.stringify({period_key:key})});
    const j=await r.json(); document.getElementById('per_out').textContent = JSON.stringify(j, null, 2);
  }
  async function perLock(){
    const key=(document.getElementById('per_key').value||'').trim();
    const r=await fetch('/api/payroll/period/lock',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:JSON.stringify({period_key:key, lock:true})});
    const j=await r.json(); document.getElementById('per_out').textContent = JSON.stringify(j, null, 2);
  }
  async function summary(){
    const uid=Number(document.getElementById('sum_user').value||0)||0;
    const key=(document.getElementById('sum_period').value||'').trim();
    const r=await fetch(`/api/payroll/user/summary?user_id=${uid}&period_key=${encodeURIComponent(key)}`);
    const j=await r.json(); document.getElementById('sum_out').textContent = JSON.stringify(j, null, 2);
  }

  document.getElementById('btnPlanUpsert')?.addEventListener('click', planUpsert);
  document.getElementById('btnPerEnsure')?.addEventListener('click', perEnsure);
  document.getElementById('btnPerRecalc')?.addEventListener('click', perRecalc);
  document.getElementById('btnPerLock')?.addEventListener('click', perLock);
  document.getElementById('btnSummary')?.addEventListener('click', summary);

  loadPlans();
})();
</script>
{% endblock %}
""")

@app.route("/payroll")
@_login_required
def payroll_page():
    return render_template_string(
        PAYROLL_TMPL,
        user=g.user, css=DESIGN_SYSTEM_CSS, js=BASE_JS, csp_nonce=g.get("csp_nonce","")
    )

# ===== BLOCK: CHAT PAGE + UI HELPERS =====
CHAT_TMPL = LAYOUT_TMPL.replace("{% block content %}{% endblock %}", r"""
{% block content %}
<h2 style="margin:0 0 12px 0;">Чат</h2>

<div class="card" style="margin-bottom:12px;">
  <div style="display:grid;grid-template-columns:260px 1fr;gap:12px;">
    <div class="smart">
      <div style="font-weight:800;margin-bottom:6px;">Каналы</div>
      <div id="channels" class="smart muted">Загрузка…</div>
      <div style="margin-top:8px;">
        <input id="ch_title" class="input" placeholder="Название канала">
        <button id="btnCreateCh" class="button small" type="button" style="margin-top:6px;">Создать канал</button>
      </div>
    </div>
    <div class="smart">
      <div style="display:flex;gap:8px;align-items:flex-end;">
        <div class="muted">Канал:</div>
        <div id="curCh" class="badge">—</div>
      </div>
      <div id="history" class="smart" style="margin-top:8px;max-height:50vh;overflow:auto;">Выберите канал</div>
      <div style="display:flex;gap:8px;align-items:center;margin-top:8px;">
        <input id="msg" class="input" placeholder="Сообщение" style="flex:1;">
        <button id="btnSendMsg" class="button" type="button">Отправить</button>
      </div>
    </div>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  let currentChannel = null;

  async function loadChannels(){
    try{
      const r=await fetch('/ui/chat/channels');
      const j=await r.json();
      if(j.ok){
        const list=(j.items||[]).map(c=>`<div class="smart" style="margin:6px 0;cursor:pointer;" data-id="${c.id}">${c.title||('channel#'+c.id)} <span class="muted">(${c.type})</span></div>`).join('') || '<div class="muted">Нет каналов</div>';
        const box=document.getElementById('channels'); box.innerHTML = list;
        Array.from(box.querySelectorAll('[data-id]')).forEach(el=>{
          el.addEventListener('click', ()=>{ openChannel(Number(el.getAttribute('data-id'))); });
        });
      }else{ document.getElementById('channels').textContent=j.error||'Ошибка'; }
    }catch(_){ document.getElementById('channels').textContent='Сеть недоступна'; }
  }

  async function openChannel(id){
    currentChannel = id;
    document.getElementById('curCh').textContent = '#'+id;
    await loadHistory();
  }

  async function loadHistory(){
    if(!currentChannel){ return; }
    try{
      const r=await fetch('/ui/chat/history?channel_id='+currentChannel);
      const j=await r.json();
      if(j.ok){
        const msgs=(j.items||[]).map(m=>`
          <div class="smart" style="margin:6px 0;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div><span class="badge">${m.user_name||'user#'+(m.user_id||'')}</span></div>
              <div class="muted">${m.created_at||''}</div>
            </div>
            <div style="margin-top:4px;white-space:pre-wrap;">${(m.body||'')}</div>
          </div>`).join('') || '<div class="muted">Нет сообщений</div>';
        document.getElementById('history').innerHTML = msgs;
        document.getElementById('history').scrollTop = 1e9;
      }else{ document.getElementById('history').textContent=j.error||'Ошибка'; }
    }catch(_){ document.getElementById('history').textContent='Сеть недоступна'; }
  }

  async function sendMsg(){
    if(!currentChannel){ return; }
    const body=(document.getElementById('msg').value||'').trim(); if(!body) return;
    try{
      const r=await fetch('/api/chat/send',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:JSON.stringify({channel_id:currentChannel, body})});
      const j=await r.json();
      if(j.ok){ document.getElementById('msg').value=''; loadHistory(); }
    }catch(_){ /* ignore */ }
  }
  async function createChannel(){
    const title=(document.getElementById('ch_title').value||'').trim();
    if(!title) return;
    try{
      const r=await fetch('/api/chat/create',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':'{{ session.get("csrf_token","") }}'},body:JSON.stringify({type:'public', title, members:[]})});
      const j=await r.json(); if(j.ok){ document.getElementById('ch_title').value=''; loadChannels(); }
    }catch(_){ /* ignore */ }
  }

  document.getElementById('btnSendMsg')?.addEventListener('click', sendMsg);
  document.getElementById('btnCreateCh')?.addEventListener('click', createChannel);

  loadChannels();
})();
</script>
{% endblock %}
""")

@app.route("/chat")
@_login_required
def chat_page():
    return render_template_string(
        CHAT_TMPL,
        user=g.user, css=DESIGN_SYSTEM_CSS, js=BASE_JS, csp_nonce=g.get("csp_nonce","")
    )

@app.route("/ui/chat/channels")
@_login_required
def ui_chat_channels():
    rows = query_db("SELECT id, type, title FROM chat_channels WHERE org_id=? ORDER BY id DESC LIMIT 200", (g.user["org_id"],)) or []
    return jsonify(ok=True, items=rows)

@app.route("/ui/chat/history")
@_login_required
def ui_chat_history():
    ch_id = int(request.args.get("channel_id") or 0)
    if not ch_id:
        return jsonify(ok=False, error="channel_id required"), 400
    # ORG-SAFE: ограничиваем историю каналом в рамках организации
    rows = query_db(
        "SELECT m.id, m.user_id, u.username AS user_name, m.body, m.created_at "
        "FROM chat_messages m "
        "JOIN chat_channels ch ON ch.id=m.channel_id "
        "LEFT JOIN users u ON u.id=m.user_id "
        "WHERE m.channel_id=? AND ch.org_id=? "
        "ORDER BY m.id ASC LIMIT 500",
        (ch_id, g.user["org_id"])
    ) or []
    return jsonify(ok=True, items=rows)

# ===== BLOCK: UX PATCH (COLLAB/NOTIF/MODALS) =====
# 1) Добавим pointer на колокольчик (на случай переопределений тем)
DESIGN_SYSTEM_CSS += "\n#notifBell{cursor:pointer}\n"

# 2) Бэкап-инициализация кнопок и колокольчика (если основной JS не выполнился)
BASE_JS += r"""
;(()=>{ try{
  document.addEventListener('DOMContentLoaded', ()=>{
    // всем кнопкам по умолчанию выставим type='button', чтобы исключить нежелательный submit
    document.querySelectorAll('button').forEach(b=>{
      if(!b.hasAttribute('type')) b.setAttribute('type','button');
    });
    // резервный обработчик для колокольчика
    const bell=document.getElementById('notifBell');
    const drawer=document.getElementById('notifDrawer');
    if(bell && drawer && !bell.__backupBound){
      bell.__backupBound = true;
      bell.addEventListener('click', ()=>{ drawer.classList.toggle('show'); try{ NOTIF && NOTIF.render(); }catch(e){} });
    }
  });
} catch(e){} })();
"""

# ===== BLOCK: ENTRYPOINT =====
def _start_server():
    """
    Точка запуска Flask-приложения.
    Выполняем ранний bootstrap до первого запроса, затем запускаем сервер.
    """
    log("INFO", "Starting CRM/ERP server", host=HOST, port=PORT, env=ENV, debug=DEBUG)
    try:
        with app.app_context():
            ensure_schema()
            _ensure_mv_tables()  # гарантируем наличие вспомогательных таблиц для дашборда
            sse_backplane_start()
            start_workers_once()
            log("INFO", "Early bootstrap done")
    except Exception as e:
        log("ERROR", "Early bootstrap failed", error=str(e))
    app.run(host=HOST, port=PORT, debug=DEBUG)

if __name__ == "__main__":
    _start_server()

# ===== END OF STYLES PART 10/10 =====
