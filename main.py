#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified Search API - Простой поиск по данным
Один файл - всё включено
Интеграция всех API из ресурсов
"""

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager, contextmanager
from collections import defaultdict
from time import time
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.error import BadRequest, Forbidden, TelegramError
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Boolean, Text, ForeignKey, update, or_, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from sqlalchemy.sql import func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from typing import Optional, Dict, Any, List, Tuple, Callable, Annotated
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import secrets
import json
import os
import re
import logging
import urllib.parse
import requests
import random
import hashlib
import asyncio
import threading
import hmac
import base64
import html
import ipaddress
from dotenv import load_dotenv

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

load_dotenv()

logger = logging.getLogger("gloomapi")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# ============================================================================
# НАСТРОЙКИ
# ============================================================================

# База данных для продакшена на bot.host.ru
# Используем SQLite с постоянным хранилищем для сохранения ключей между деплоями
# Путь к постоянному хранилищю на хостинге
# Локально для тестов используем временный каталог
if os.path.exists("/data"):
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////data/gloomapi.db")
else:
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./search.db")
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ADMIN_TELEGRAM_IDS = [int(x) for x in os.getenv("ADMIN_TELEGRAM_IDS", "").split(",") if x]
MASTER_API_KEY = os.getenv("MASTER_API_KEY", "")
ADMIN_IP_WHITELIST = [ip.strip() for ip in os.getenv("ADMIN_IP_WHITELIST", "").split(",") if ip.strip()]
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip()]
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_PERIOD = int(os.getenv("RATE_LIMIT_PERIOD", "60"))
_default_trust_proxy = "1" if os.path.exists("/data") else "0"
TRUST_PROXY = os.getenv("TRUST_PROXY", _default_trust_proxy) == "1"
MAX_QUERY_VALUE_LEN = int(os.getenv("MAX_QUERY_VALUE_LEN", "500"))
MAX_SEARCH_RESULTS = int(os.getenv("MAX_SEARCH_RESULTS", "500"))
OUTPUT_DIR = os.getenv(
    "OUTPUT_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs"),
)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Для PostgreSQL на Railway
if DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://"):
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        pool_recycle=1800,
    )
else:
    # SQLite: timeout снижает "database is locked"
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False, "timeout": 30},
    )


def _configure_sqlite(dbapi_conn, connection_record):
    try:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        pass


if DATABASE_URL.startswith("sqlite"):
    from sqlalchemy import event as _sa_event
    _sa_event.listen(engine, "connect", _configure_sqlite)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """Thread-safe in-memory sliding-window rate limiter with periodic GC."""

    def __init__(self, requests: int, period: int):
        self.requests = max(1, int(requests))
        self.period = max(1, int(period))
        self.requests_history: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_gc = time()

    def _prune(self, identifier: str, now: float) -> None:
        hist = self.requests_history.get(identifier) or []
        hist = [ts for ts in hist if now - ts < self.period]
        if hist:
            self.requests_history[identifier] = hist
        else:
            self.requests_history.pop(identifier, None)

    def _gc(self, now: float) -> None:
        if now - self._last_gc < max(30.0, float(self.period)):
            return
        stale = [k for k, v in self.requests_history.items() if not v or now - v[-1] >= self.period]
        for k in stale:
            self.requests_history.pop(k, None)
        self._last_gc = now

    def is_allowed(self, identifier: str) -> bool:
        identifier = (identifier or "unknown")[:128]
        now = time()
        with self._lock:
            self._gc(now)
            self._prune(identifier, now)
            hist = self.requests_history[identifier]
            if len(hist) < self.requests:
                hist.append(now)
                return True
            return False

    def get_remaining(self, identifier: str) -> int:
        identifier = (identifier or "unknown")[:128]
        now = time()
        with self._lock:
            self._prune(identifier, now)
            return max(0, self.requests - len(self.requests_history.get(identifier, [])))

rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_PERIOD)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================================================
# БАЗА ДАННЫХ
# ============================================================================

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(128), unique=True, index=True, nullable=False)
    key_hash = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    search_limit = Column(Integer, nullable=True)
    searches_used = Column(Integer, default=0, nullable=False)
    status = Column(String(20), default="active", nullable=False)
    created_by = Column(Integer, nullable=True)  # Telegram ID создателя
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    ip_restrictions = Column(Text, nullable=True)  # JSON array of allowed IPs
    search_logs = relationship("SearchLog", back_populates="api_key", cascade="all, delete-orphan")
    
    @property
    def is_valid(self):
        if self.status != "active":
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        if self.search_limit and self.searches_used >= self.search_limit:
            return False
        return True

class SearchLog(Base):
    __tablename__ = "search_logs"
    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=False)
    search_params = Column(Text, nullable=False)
    results_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    api_key = relationship("APIKey", back_populates="search_logs")
    source_api_key = Column(Text, nullable=True)  # Which API key was used for the search (e.g., jitler key)
    client_ip = Column(String(64), nullable=True, index=True)
    client_city = Column(String(128), nullable=True)
    client_region = Column(String(128), nullable=True)
    client_country = Column(String(128), nullable=True)

# Создание таблиц (отложено до запуска приложения)
def init_db():
    """Инициализация базы данных"""
    Base.metadata.create_all(bind=engine)
    _migrate_schema()


def _migrate_schema() -> None:
    """Добавляет новые колонки в уже существующие SQLite/Postgres таблицы."""
    wanted = {
        "search_logs": {
            "client_ip": "VARCHAR(64)",
            "client_city": "VARCHAR(128)",
            "client_region": "VARCHAR(128)",
            "client_country": "VARCHAR(128)",
        }
    }
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names())
        for table, columns in wanted.items():
            if table not in tables:
                continue
            existing = {col["name"] for col in insp.get_columns(table)}
            for name, coltype in columns.items():
                if name in existing:
                    continue
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}"))
                logger.info("schema: added %s.%s", table, name)
    except Exception as exc:
        logger.warning("schema migrate skipped: %s", exc)

# ============================================================================
# МОДЕЛИ
# ============================================================================

class SearchRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    phone: Optional[str] = Field(None, max_length=64)
    email: Optional[str] = Field(None, max_length=320)
    nick: Optional[str] = Field(None, max_length=128)
    username: Optional[str] = Field(None, max_length=128)
    name: Optional[str] = Field(None, max_length=256)
    first_name: Optional[str] = Field(None, max_length=128)
    last_name: Optional[str] = Field(None, max_length=128)
    fio: Optional[str] = Field(None, max_length=256)
    fullname: Optional[str] = Field(None, max_length=256)
    passport: Optional[str] = Field(None, max_length=64)
    inn: Optional[str] = Field(None, max_length=32)
    snils: Optional[str] = Field(None, max_length=32)
    vin: Optional[str] = Field(None, max_length=32)
    car_number: Optional[str] = Field(None, max_length=32)
    ip: Optional[str] = Field(None, max_length=64)
    telegram: Optional[str] = Field(None, max_length=128)
    telegram_id: Optional[str] = Field(None, max_length=64)
    vk: Optional[str] = Field(None, max_length=256)
    vk_id: Optional[str] = Field(None, max_length=64)
    card: Optional[str] = Field(None, max_length=32)
    imei: Optional[str] = Field(None, max_length=32)
    address: Optional[str] = Field(None, max_length=500)
    social: Optional[str] = Field(None, max_length=256)
    number: Optional[str] = Field(None, max_length=64)
    bdate: Optional[str] = Field(None, max_length=32)
    domain: Optional[str] = Field(None, max_length=253)
    photo_url: Optional[str] = Field(None, max_length=2048)
    password: Optional[str] = Field(None, max_length=256)
    tiktok: Optional[str] = Field(None, max_length=256)
    github: Optional[str] = Field(None, max_length=256)
    output_file: Optional[str] = Field(None, max_length=255)

    @field_validator("*", mode="before")
    @classmethod
    def _empty_to_none(cls, v):
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @field_validator("email")
    @classmethod
    def _email_basic(cls, v):
        if v is None:
            return v
        if "@" not in v or len(v) < 3:
            raise ValueError("Некорректный email")
        return v

    @field_validator("ip")
    @classmethod
    def _ip_basic(cls, v):
        if v is None:
            return v
        # допускаем IPv4 / IPv6 без жёсткого парсера
        if not re.match(r"^[0-9a-fA-F:.]+$", v) or len(v) < 3:
            raise ValueError("Некорректный IP")
        return v

    @field_validator("photo_url")
    @classmethod
    def _photo_url(cls, v):
        if v is None:
            return v
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("photo_url должен начинаться с http(s)://")
        return v


class CreateKeyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    days: Optional[int] = Field(None, ge=1, le=3650)
    limit: Optional[int] = Field(None, ge=1, le=10_000_000)
    ip_restrictions: Optional[List[str]] = Field(None, max_length=64)

    @field_validator("ip_restrictions")
    @classmethod
    def _ips(cls, v):
        if v is None:
            return v
        cleaned = []
        for ip in v:
            ip = str(ip).strip()
            if not ip or len(ip) > 64:
                raise ValueError("Некорректный IP в ip_restrictions")
            cleaned.append(ip)
        return cleaned

class KeyStatsResponse(BaseModel):
    total_keys: int
    active_keys: int
    expired_keys: int
    total_searches: int

class KeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    key: str
    name: str
    created_at: datetime
    expires_at: Optional[datetime]
    search_limit: Optional[int]
    searches_used: int
    status: str

# ============================================================================
# API КЛЮЧИ ИЗ РЕСУРСОВ
# ============================================================================

JITLER_KEYS = [
    "2dnIR65njDpE06LEEt6vp3ne",
    "JPl3E4Ng68hyIyWnojUL8XxF",
    "OOm8kHwpAAzqOnxqCVGMnUze",
    "kUULzKkHsZCqsKZyHEGi2z2M",
    "YHT9bpgpNCEv88unmUYKmoNl"
]

NIGHTSEARCH_API_KEY = "sk_66beac29ce86f915b184a9ddde7aecbfc6177ab265cf5c1f579ce53219422234"
DEPSEARCH_TOKEN = "OsMTcjyHTRtfABnWA4V3d12SYKVIYE8z"
TELEGRAM_HISTORY_TOKEN = "124:Bpx2NjYkqfE9hnkgYNm0_c84tFmACk3D"
RAIDFIND_API_KEY = "rf_live_e7285c81c1334de11b211dbda0f81b1e9729c81ecb7589f0"
VK_TOKEN = "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c"
VK_API_VERSION = "5.199"
TRUECALLER_INSTALLATION_ID = os.getenv("TRUECALLER_INSTALLATION_ID", "a1i2N--Ql8rEHHVAS8AVeQ")
INFINITY_SEARCH_TOKEN = os.getenv("INFINITY_SEARCH_TOKEN", "QoNm98UeMLIqNjZ198snm98AdGvhqA88")
INFINITY_SEARCH_URL = os.getenv("INFINITY_SEARCH_URL", "https://infinity-search.fun/find.php")
INFINITY_SEARCH_TOKEN_ALT = "Bjm928HUcvsw923ZMBX19gd110FWSZgd"
DEPSEARCH_BASE_URL = os.getenv("DEPSEARCH_BASE_URL", "https://depsearch.sbs")
PANSRC_TOKEN = os.getenv("PANSRC_TOKEN", "pant_g3U5TEfe7r1zg4i30vuAkEJyTEisOXiw")
PANSRC_URL = os.getenv("PANSRC_URL", "http://pantsrc.p7z.ru/search")
LEAK_LOOKUP_SESSION = os.getenv("LEAK_LOOKUP_SESSION", "gc4hn4q6oal49gq0ckv4ujnabs")
SEON_API_KEY = os.getenv("SEON_API_KEY", "758f5f54-befb-4125-bd17-931689af6633")
WHATSAPP_EMAIL = os.getenv("WHATSAPP_EMAIL", "legislativepaola@web-library.net")
WHATSAPP_PASSWORD = os.getenv("WHATSAPP_PASSWORD", "legislativepaola@web-library.net")
SEARCH_TIMEOUT_SEC = int(os.getenv("SEARCH_TIMEOUT_SEC", "90"))
SEARCH_MAX_WORKERS = int(os.getenv("SEARCH_MAX_WORKERS", "24"))

# New API keys
DEEPSCAN_KEYS = [
    "deepscan_8900730363:8REhy4bY",
    "deepscan_572562339:ejLjxG7q"
]
BIGBASE_API_KEY = "yhWCFGkla7-lT4ldeiIkVgFVYtHauETM"
BIGBASE_API_URL = "https://bigbase.top/api"
ONUX_API_TOKEN = "On-OmXimXvxsPwbNO4C"
ONUX_API_URL = "https://api.onux.dev"
TULASAY_API_TOKEN = "jg_torL_hDxjW-QRI2Gi063d_gOo8iWD8GaKQLC5fmqrBbuXW0K"
TULASAY_API_URL = "https://tulasay.ru/api/v1"
REDMASK_API_KEY = "aTKg9SQ7IK42FlT8YL1p3"
REDMASK_API_URL = "https://postauditory-indigenously-blakely.ngrok-free.dev/v1/search"

# Additional API keys from apii.txt
IPINFO_API_KEY = "cf2b2febdde638"
IPSTACK_API_KEY = "34ee8bfa281241bf63658756990bca58"
NUMVERIFY_API_KEY = "c84bb45a28c15b8c66911354c091106c"
MAILBOXLAYER_API_KEY = "271c9e7064ea7a43a7d43709817cfba2"
IPGEOLOCATION_API_KEY = "73d99145d2e948779263360bfeb67ecc"
IPDATA_API_KEY = "e5d4dded7a01eb1500f4070e735d16c3"
ABSTRACT_API_KEY = "e5d0f9c86eab454cb5a821679cfe8525"
IPBASE_API_KEY = "ipb_live_UGYUcjckxwSrtF0dBS9XcSvmTn44AdL0P8ouDgEY"
BIGDATACLOUD_API_KEY = "bdc_ead54c97234b498c8e0fd13478adeed3"
CLOUDMERSIVE_API_KEY = "92fb6582-e8d8-43f2-85c9-896a117b9bd9"
DEEPSEARCH_API_KEY = "IBqXs5SSpanLR6I5YnjRIYTrywsMqtmk"
SCANCORE_API_KEY = "7399193134:AnWlkE6z"
KRAMPUS_API_KEY = "KRMP-KDMW-8RJV-ZZV9"
LEAKOSINT_API_KEY = "7128288325:1AKvhnOZ"
LEAKOSINT2_API_KEY = "7949201327:7z2O7xWq"
LEAKCHECK_API_KEY = "49535f49545f5245414c4c595f4150495f4b4559"
SNUSBASE_KEY = "sbmeovhou6ecsn9fd9wcwnwwvsvwnc"
SNUSBASE_SECRET = "sby0b7crta98od7efbb8zr70788n2h"
OFDATA_API_KEY = "KBnpz1CHKNngFXxK"
VERIPHONE_API_KEY = "D997B34B302B4A06B3AB815312852E51"
EMAIL_VALID_API_KEY = "0149939faa924e31876d237c634dca33"
EMAIL_REPUTATION_API_KEY = "3809fec03c2a4d19af09fbedaf54b1fd"
PROXYCHECK1_API_KEY = "9fcd3e6622f96a780f0908ce414bb16360d3779d8253f484f319e02cc5c25065"
PROXYCHECK2_API_KEY = "dbbc251dda62fb51321132d79b070d00cad48acec4c660f7f0b313eb09056e9b"
ABUSEIPDB_API_KEY = "58878ed65228db88eddfda4983bce5d19d425ddf81f427857b3f59f11aecc34f127862a1cc7d4581"
SMSC_LOGIN = "kirahacker333"
SMSC_PASSWORD = "Zangar5050"
HUNTER_API_KEY = "abc123def456ghi789jkl012mno345pqr678"
DEHASHED_API_KEY = "dh_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
DEHASHED_EMAIL = "professor_coder@proton.me"
HIBP_API_KEY = "0123456789abcdef0123456789abcdef"
WELEAKINFO_API_KEY = "wli_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
INTELX_API_KEY = "x-intelligence-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
FUNSTAT_API_KEY = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIyMDMzMDI5NDc1IiwianRpIjoiODJmMjlmNzQtYmJlMi00ZGUwLWEwZDQtN2EzMDJhMWE5MDViIiwiZXhwIjoxODAxMDA4MzM4fQ.Mba4aX85YAMcaMLfhUBzXtCoNmEujfMe-6sGBbp3kT-T2SiLM_Ho0BBAFAQ8_C6Gz06PH9mAYhfBvlLSjb4oVd1Fm_vmb8MC-wuObU3qgfGrYdGzVF3ntJHv-LdNELq-jsqvQOY3jq9meso9dUoyj5SviDQWL6cvnRQ03kpHWxA"
SHODAN_API_KEY = "z6kC8mX9pL2qR0sT4uV7wY1zA3bD5eG8hJ0nM3pQ6sT9vW2yZ4cF7iJ1lN4oR7uX0zA3C5"
CENSYS_ID = "c2a1b3d4-e5f6-7890-abcd-ef1234567890"
CENSYS_SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
BINARYEDGE_API_KEY = "BE-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
GREYNOISE_API_KEY = "gn-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
BIGBASE_API_KEYS = "H-OE9Ekx7gfZu1Xbfe0we7TL7btnJzJ_,xMVdL8a-NgJnnwAjGo0bZ-GVOq9o3zBq,OFOdFXXd_S7ojuTp8JJnK_Q_sZESDwzN,MkJm1j8F1AyyhXtzY9fu6JALe1S72owZ,m5JLoYa-jX7W8RY3TnB01O7PBknd3RV7,0nBIi5IDlx-ep9S9bMuw0Fj8g9AcwFT8,kb3S-ijS-NeMHzrsuw4uIY-aJZltJhEp,72UZOG4sadWaXAIJCQYlMmOR82CuSgNd,M9djfI8W3l-ozvCNsxPuLGONicsvgvnM,HTuFdLn37hW6FaiPJeSVtu5iazWKCs-n"
API_KEY_DEPSEARCH = "bdIUze7ym7OqJ7kd4GHJ3S9wgDOqTDmE"
BIGBASE_TOKEN = "g-eg8muf-20sQ_ygoovh_jTWacp43rTh"
INFINITY_SEARCH_API_KEY = "50c14c6dffb8d0b9c210c9a1"
GLOOMAPI_API_KEY = "sk_U--ls-i6C65058T3xAdT6cOgG-ghNslueJSX8I9y0Zg"
IPDATA_CO_API_KEY = "c335d87f4e99ce6a747f8628bea61368f7274ff83b39d019c4ed0731"
SHODAN_API_KEY_ALT = "aytQRnUGbufbvrEoftFAGK5sglpFC6Mi"
IP2LOCATION_API_KEY = "965108E0429BB3E9329066D8D015564C"
WHOISJSON_API_KEY = "dbbc251dda62fb51321132d79b070d00cad48acec4c660f7f0b313eb09056e9b"
FISHAPI_API_KEY = "jTaxIU2GgwuR5RgGcerx"
LEAKIX_API_KEY = "UbRPZUev61jvVDyIinkjDOzj2r1s8vjmOq58SxbJ0Ona4Gxq"
BLACKEYE_API_KEY = "jn87axW1a3MSh8x83AJtDg"
COREAPI_API_KEY = "17aq_xu81(sbaop"
WHITESEARCH_API_KEY = "WS-PUBLIC-9X7K-2M4P"
W2SP3R_API_KEY = "Mg05qwg9kfJZgMA1sUshI_-LxS6c33iQWR4JslZRubc"
QUICKFLOW_TOKEN = "063b6819d85570dfe1b5f5b4ba5be14ac1d66a74e848ee9d1588068a9cf9b372"
FUNSTAT_TOKEN_ALT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiI4OTIxNDc4MTAyIiwianRpIjoiOGUxOWIwYzgtNDc5Yi00YmE4LWEwMTYtNjZmOTcxMTQyMGQyIiwiZXhwIjoxODEyMDUyMzc3fQ.tLuq42piT66rfewe0N8Ui37IdsSjbxB8RHPWXIemn3UeuO489wYBSoHeNTKC5SFzif8wACjzwdK8v6GVX80Vj-fhN58d5eV2odONXtgfVXrIVARrpNhoWZ4hKufJ_RqiTfJSjvlO_yEI7G8FBpAG7IZY4YqEUwqDgkGkfkXUYlk"
GERHANO_API_KEY = "ns-MVzUx4QtfyiQrQ72qTOz2UoZWeiHMa1f"
LOCALSEARCH_BASE_URL = os.getenv("LOCALSEARCH_BASE_URL", "http://192.99.16.76:5009")
NETSPY_API_KEY = os.getenv("NETSPY_API_KEY", "ns-ecwKK6MKcguV8vQa3QUwgbUzKu6vvfxj")
NETSPY_BASE_URL = os.getenv("NETSPY_BASE_URL", "https://netspy.sbs")
API_KEY_PREFIX = "plut_"
LEGACY_API_KEY_PREFIX = "sk_"
KEYS_BACKUP_MAX_BYTES = 512 * 1024
KEYS_BACKUP_MAX_ITEMS = 500
TELEGRAM_HTML_LIMIT = 3900

# ============================================================================
# ПОИСКОВЫЕ МОДУЛИ ДЛЯ КАЖДОГО API
# ============================================================================

class APIKeyLoadBalancer:
    """Load balancer for API keys - distributes requests evenly"""
    
    def __init__(self, keys: List[str]):
        self.keys = keys
        self.current_index = 0
        self.usage_count = {key: 0 for key in keys}
        self.lock = threading.Lock()
    
    def get_next_key(self) -> str:
        """Get next key using round-robin with least usage"""
        with self.lock:
            # Find key with least usage
            min_usage = min(self.usage_count.values())
            candidates = [k for k, v in self.usage_count.items() if v == min_usage]
            
            # Select from candidates using round-robin
            selected_key = candidates[self.current_index % len(candidates)]
            self.current_index = (self.current_index + 1) % len(candidates)
            
            # Increment usage
            self.usage_count[selected_key] += 1
            
            return selected_key
    
    def get_usage_stats(self) -> Dict[str, int]:
        """Get usage statistics for all keys"""
        return self.usage_count.copy()

# Initialize load balancers for multi-key APIs
jitler_load_balancer = APIKeyLoadBalancer(JITLER_KEYS)
deepscan_load_balancer = APIKeyLoadBalancer(DEEPSCAN_KEYS)
SEARCH_EXECUTOR = ThreadPoolExecutor(max_workers=SEARCH_MAX_WORKERS, thread_name_prefix="gloom-search")

# ============================================================================
# УТИЛИТЫ НОРМАЛИЗАЦИИ
# ============================================================================

def normalize_phone(phone: str) -> str:
    """Нормализация телефона к виду 7XXXXXXXXXX (без +)."""
    digits = re.sub(r"\D", "", str(phone or ""))
    if not digits:
        return ""
    if len(digits) == 11 and digits.startswith("8"):
        digits = "7" + digits[1:]
    elif len(digits) == 10 and digits.startswith("9"):
        digits = "7" + digits
    return digits


def normalize_phone_e164(phone: str) -> str:
    digits = normalize_phone(phone)
    return f"+{digits}" if digits else ""


def normalize_telegram_query(query: str) -> str:
    q = (query or "").strip()
    if q.startswith("@"):
        return q
    if q.isdigit():
        return q
    return q.lstrip("@")


def extract_vk_id(vk_id: str) -> str:
    vk_id = str(vk_id or "").strip()
    id_match = re.search(r"(?:^|\b)id[\s:_-]*(\d+)", vk_id, re.I)
    if id_match:
        return id_match.group(1)
    if "vk.com/" in vk_id.lower():
        match = re.search(r"vk\.com/(?:id)?(\d+)", vk_id, re.I)
        if match:
            return match.group(1)
        match = re.search(r"vk\.com/([a-zA-Z0-9_\.]+)", vk_id, re.I)
        if match:
            return match.group(1)
    if vk_id.isdigit():
        return vk_id
    return vk_id


def _result_ok(source: str, field: str, value: Any, data: Any, **extra) -> Dict[str, Any]:
    item = {
        "source": source,
        "field": field,
        "value": value,
        "found": True,
        "data": data,
    }
    item.update(extra)
    return item


def _result_err(source: str, field: str, value: Any, error: Any) -> Dict[str, Any]:
    return {
        "source": source,
        "field": field,
        "value": value,
        "found": False,
        "error": str(error),
    }


class CircuitBreaker:
    """Автопропуск мёртвых API после серии ошибок (DNS/timeout/5xx)."""

    def __init__(self, fail_threshold: int = 3, cooldown_sec: int = 300):
        self.fail_threshold = fail_threshold
        self.cooldown_sec = cooldown_sec
        self._failures: Dict[str, int] = defaultdict(int)
        self._open_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def allow(self, name: str) -> bool:
        with self._lock:
            until = self._open_until.get(name)
            if until is None:
                return True
            if time() >= until:
                self._open_until.pop(name, None)
                self._failures[name] = 0
                return True
            return False

    def success(self, name: str) -> None:
        with self._lock:
            self._failures[name] = 0
            self._open_until.pop(name, None)

    def failure(self, name: str, hard: bool = False) -> None:
        with self._lock:
            self._failures[name] = self._failures.get(name, 0) + (self.fail_threshold if hard else 1)
            if self._failures[name] >= self.fail_threshold:
                self._open_until[name] = time() + self.cooldown_sec
                logger.warning("Circuit OPEN for %s (cooldown %ss)", name, self.cooldown_sec)


circuit_breaker = CircuitBreaker()
HTTP_SESSION = requests.Session()
HTTP_SESSION.headers.update({
    "User-Agent": "GloomApi/2.2",
    "Accept": "application/json, text/plain, */*",
})
_http_retry = Retry(
    total=1,
    connect=1,
    read=0,
    status=0,
    backoff_factor=0.2,
    allowed_methods=frozenset(["GET", "HEAD"]),
    raise_on_status=False,
)
_http_adapter = HTTPAdapter(pool_connections=32, pool_maxsize=64, max_retries=_http_retry)
HTTP_SESSION.mount("https://", _http_adapter)
HTTP_SESSION.mount("http://", _http_adapter)


def http_request(
    method: str,
    url: str,
    *,
    module: str = "http",
    timeout: float = 12,
    **kwargs,
) -> Tuple[Optional[requests.Response], Optional[str]]:
    """Единый HTTP-вызов: circuit breaker + мягкие ошибки без падения поиска."""
    if not circuit_breaker.allow(module):
        return None, f"circuit_open:{module}"
    try:
        response = HTTP_SESSION.request(method.upper(), url, timeout=timeout, **kwargs)
        # 401/402/403 — ключ/доступ; не открываем circuit (это не downtime хоста)
        if response.status_code >= 500:
            circuit_breaker.failure(module)
            return response, f"HTTP {response.status_code}"
        if response.status_code == 429:
            circuit_breaker.failure(module)
            return response, "rate_limited"
        circuit_breaker.success(module)
        return response, None
    except requests.exceptions.Timeout:
        circuit_breaker.failure(module)
        return None, "timeout"
    except requests.exceptions.ConnectionError as exc:
        circuit_breaker.failure(module, hard=True)
        return None, f"connection_error:{exc}"
    except Exception as exc:
        circuit_breaker.failure(module)
        return None, str(exc)


class BaseSearchModule:
    """Базовый класс для поисковых модулей"""

    # Пустой список = модуль сам решает; иначе быстрый skip по полям запроса
    SUPPORTED_FIELDS: List[str] = []
    ENABLED: bool = True
    TIMEOUT: float = 12.0
    SOURCE_NAME: str = "module"

    def can_handle(self, params: Dict[str, Any]) -> bool:
        if not self.ENABLED:
            return False
        name = self.__class__.__name__
        if not circuit_breaker.allow(name):
            return False
        if not self.SUPPORTED_FIELDS:
            return True
        return any(params.get(field) for field in self.SUPPORTED_FIELDS)

    def _get(self, url: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[str]]:
        kwargs.setdefault("timeout", self.TIMEOUT)
        return http_request("GET", url, module=self.__class__.__name__, **kwargs)

    def _post(self, url: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[str]]:
        kwargs.setdefault("timeout", self.TIMEOUT)
        return http_request("POST", url, module=self.__class__.__name__, **kwargs)

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Базовый метод поиска"""
        return {"success": False, "error": "Not implemented", "results": []}

class JitlerSearchModule(BaseSearchModule):
    """Jitler API - расширенный поиск (phone/email/fio/vk/tg/ip/docs/...)"""

    SUPPORTED_FIELDS = [
        "phone", "number", "email", "nick", "username", "name", "fio", "fullname",
        "vk", "vk_id", "telegram", "telegram_id", "ip", "passport", "inn", "snils",
        "vin", "car_number", "card", "imei", "address",
    ]
    TIMEOUT = 12.0

    TYPE_MAP = {
        "phone": ("number", "phone"),
        "number": ("number", "phone"),
        "email": ("email",),
        "nick": ("nick",),
        "username": ("nick",),
        "name": ("name",),
        "fio": ("name",),
        "fullname": ("name",),
        "vk": ("vk",),
        "vk_id": ("vk",),
        "telegram": ("telegram",),
        "telegram_id": ("telegram",),
        "ip": ("ip",),
        "passport": ("passport",),
        "inn": ("inn",),
        "snils": ("snils",),
        "vin": ("vin",),
        "car_number": ("car_number",),
        "card": ("card",),
        "imei": ("imei",),
        "address": ("address",),
    }

    def __init__(self):
        self.base_url = "https://api.jitler.top"
        self.load_balancer = jitler_load_balancer

    def _request(self, search_type: str, query: str) -> Tuple[Optional[dict], Optional[str], Optional[str]]:
        keys = list(self.load_balancer.keys) if self.load_balancer.keys else []
        last_error = None
        for _ in range(max(1, len(keys))):
            key = self.load_balancer.get_next_key() if keys else ""
            try:
                response = requests.post(
                    f"{self.base_url}/search",
                    json={"type": search_type, "query": query},
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    timeout=self.TIMEOUT,
                )
                if response.status_code == 200:
                    data = response.json()
                    payload = data.get("response") if isinstance(data, dict) else None
                    payload_failed = isinstance(payload, dict) and (
                        payload.get("error") or payload.get("success") is False
                    )
                    if payload not in (None, "", [], {}) and not payload_failed:
                        return data, key, None
                    if isinstance(data, dict) and data and "error" not in data:
                        return data, key, None
                last_error = f"HTTP {response.status_code}"
            except Exception as exc:
                last_error = str(exc)
                continue
        return None, None, last_error or "Все ключи Jitler не работают"

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        tried = set()

        for field, types in self.TYPE_MAP.items():
            value = params.get(field)
            if not value:
                continue
            query = normalize_phone(value) if field in ("phone", "number") else str(value).strip()
            if not query:
                continue
            for search_type in types:
                cache_key = (search_type, query)
                if cache_key in tried:
                    continue
                tried.add(cache_key)
                data, key, error = self._request(search_type, query)
                if data is not None:
                    results.append(_result_ok(
                        "jitler", field, value, data,
                        api_key=(key[:8] + "...") if key else None,
                        method=search_type,
                    ))
                    break
                if error and search_type == types[-1]:
                    results.append(_result_err("jitler", field, value, error))

        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}

class NightSearchModule(BaseSearchModule):
    """NightSearch API - поиск по phone, email, nick, name, fio, inn, SNILS"""

    # Ключ/контракт API сейчас невалидны (400 Missing required fields or API key)
    ENABLED = False
    SUPPORTED_FIELDS = ["phone", "email", "nick", "username", "name", "fio", "fullname", "inn", "snils"]

    def __init__(self):
        self.base_url = "https://nightsearch.life/api/search"
        self.api_key = NIGHTSEARCH_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Mapping параметров к типам поиска NightSearch
        param_mapping = {
            "phone": "phone",
            "email": "email",
            "nick": "nick",
            "username": "nick",
            "name": "name",
            "fio": "fio",
            "fullname": "fio",
            "inn": "inn",
            "snils": "SNILS"
        }
        
        seen = set()
        for local_param, search_type in param_mapping.items():
            if params.get(local_param):
                query = params[local_param]
                cache_key = (search_type, query)
                if cache_key in seen:
                    continue
                seen.add(cache_key)
                try:
                    response = requests.post(
                        self.base_url,
                        json={"type": search_type, "query": query},
                        headers={"Authorization": f"Bearer {self.api_key}"},
                        timeout=15
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.append(_result_ok("nightsearch", local_param, query, data))
                except Exception as e:
                    results.append(_result_err("nightsearch", local_param, query, e))
        
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}

class DepSearchModule(BaseSearchModule):
    """DepSearch API — по документации https://depsearch.sbs/api-docs/

    Формат: GET https://api.depsearch.sbs/quest?quest=VALUE&token=TOKEN&lang=ru
    Тип запроса определяется автоматически или префиксами (nick:, snils, inn, vkid, addr:, tt:).
    """

    SUPPORTED_FIELDS = [
        "phone", "email", "nick", "username", "name", "fio", "fullname", "passport",
        "inn", "snils", "vin", "car_number", "ip", "telegram", "telegram_id",
        "vk", "vk_id", "card", "imei", "address", "social", "password", "tiktok",
    ]
    TIMEOUT = 20.0

    def __init__(self):
        self.base_url = "https://api.depsearch.sbs"
        self.tokens = [t for t in (DEPSEARCH_TOKEN, API_KEY_DEPSEARCH) if t]

    def _build_quest(self, field: str, value: str) -> Optional[str]:
        value = str(value).strip()
        if not value:
            return None
        if field == "phone":
            return normalize_phone(value) or value
        if field == "email":
            return value
        if field in ("nick", "username"):
            return value if value.lower().startswith("nick:") else f"nick:{value.lstrip('@')}"
        if field == "snils":
            digits = re.sub(r"\D", "", value)
            return f"snils{digits}" if digits else None
        if field == "inn":
            digits = re.sub(r"\D", "", value)
            return f"inn{digits}" if digits else None
        if field in ("vk", "vk_id"):
            vk = extract_vk_id(value)
            return f"vkid{vk}" if str(vk).isdigit() else value
        if field == "address":
            return value if value.lower().startswith(("addr:", "адрес:")) else f"addr:{value}"
        if field in ("telegram", "telegram_id"):
            # DepSearch не документирует TG отдельно — пробуем как nick
            q = normalize_telegram_query(value)
            return q if q.isdigit() else f"nick:{q.lstrip('@')}"
        if field in ("name", "fio", "fullname"):
            return value
        if field == "password":
            return value if value.lower().startswith("pass:") else f"pass:{value}"
        if field == "tiktok":
            cleaned = value.lstrip("@")
            return cleaned if cleaned.lower().startswith("tt:") else f"tt:{cleaned}"
        if field in ("vin", "car_number", "ip", "passport", "card", "imei", "social"):
            return value
        return value

    def _quest(self, quest: str) -> Tuple[Optional[dict], Optional[str]]:
        last_error = None
        for token in self.tokens:
            response, err = self._get(
                f"{self.base_url}/quest",
                params={"quest": quest, "token": token, "lang": "ru"},
            )
            if err and response is None:
                last_error = err
                continue
            if response is None:
                last_error = err or "no response"
                continue
            if response.status_code == 401:
                last_error = "token missing/invalid"
                continue
            if response.status_code == 403:
                last_error = "token forbidden"
                continue
            if response.status_code == 429:
                return None, "rate_limited"
            if response.status_code != 200:
                last_error = f"HTTP {response.status_code}"
                continue
            try:
                data = response.json()
            except Exception:
                last_error = "invalid json"
                continue
            if isinstance(data, dict) and data.get("error"):
                last_error = str(data.get("error"))
                continue
            if data:
                return data, None
            last_error = "empty"
        return None, last_error or "DepSearch unavailable"

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        seen = set()
        field_order = [
            "phone", "email", "fio", "fullname", "name", "nick", "username",
            "vk", "vk_id", "inn", "snils", "vin", "car_number", "ip",
            "telegram", "telegram_id", "address", "passport", "card", "imei", "social",
            "password", "tiktok",
        ]
        for field in field_order:
            value = params.get(field)
            if not value:
                continue
            quest = self._build_quest(field, value)
            if not quest or quest in seen:
                continue
            seen.add(quest)
            data, error = self._quest(quest)
            if data is not None:
                # Пустой results без полезных блоков — не считаем находкой
                useful = False
                if isinstance(data, dict):
                    if data.get("results") or data.get("phone_info") or data.get("ip_info") or data.get("vk_info"):
                        useful = True
                    elif any(k not in ("search_type", "error") for k in data.keys()):
                        useful = bool(data)
                if useful:
                    results.append(_result_ok("depsearch", field, value, data, quest=quest))
            # ошибки модуля глотаем (circuit/лог), не засоряем ответ
            elif error:
                logger.debug("DepSearch %s: %s", quest, error)
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class TelegramHistoryModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["telegram", "telegram_id", "username", "nick"]
    """Telegram History API - история аккаунтов, подарки, смена имени"""
    
    def __init__(self):
        self.base_url = "https://kartoshka.free/v1"
        self.token = TELEGRAM_HISTORY_TOKEN
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Поиск по username или telegram_id
        query = params.get("telegram") or params.get("telegram_id") or params.get("username")
        if query:
            # /owners/search
            try:
                response = requests.get(
                    f"{self.base_url}/owners/search",
                    params={"q": query, "limit": 1},
                    headers={"Authorization": f"Bearer {self.token}"},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "telegram_history",
                        "method": "owners/search",
                        "field": "telegram",
                        "value": query,
                        "found": True,
                        "data": data
                    })
                    
                    # Если найден владелец, получаем историю
                    if data.get("ok") and data.get("result"):
                        items = data["result"].get("items", [])
                        if items:
                            owner = items[0].get("owner", {})
                            ref = owner.get("username") or owner.get("telegramId") or owner.get("seeId")
                            if ref:
                                try:
                                    history_response = requests.get(
                                        f"{self.base_url}/owner/{ref}/history",
                                        params={"limit": 100},
                                        headers={"Authorization": f"Bearer {self.token}"},
                                        timeout=10
                                    )
                                    if history_response.status_code == 200:
                                        history_data = history_response.json()
                                        results.append({
                                            "source": "telegram_history",
                                            "method": "owner/history",
                                            "field": "telegram",
                                            "value": query,
                                            "found": True,
                                            "data": history_data
                                        })
                                except Exception as e:
                                    results.append({
                                        "source": "telegram_history",
                                        "method": "owner/history",
                                        "field": "telegram",
                                        "value": query,
                                        "found": False,
                                        "error": str(e)
                                    })
            except Exception as e:
                results.append({
                    "source": "telegram_history",
                    "method": "owners/search",
                    "field": "telegram",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class RaidFindModule(BaseSearchModule):
    # auto-disabled: DNS/host недоступен
    ENABLED = False
    """RaidFind API - премиум поиск"""
    
    def __init__(self):
        self.base_url = "https://api.raidfind.cc/v1"
        self.api_key = RAIDFIND_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Mapping параметров к типам поиска RaidFind
        param_mapping = {
            "phone": "phone",
            "email": "email",
            "name": "name",
            "nick": "nick",
            "vk": "vk",
            "ip": "ip",
            "passport": "passport",
            "inn": "inn",
            "snils": "snils",
            "card": "card",
            "vin": "vin",
            "car_number": "car_number",
            "address": "address",
            "imei": "imei",
            "social": "social"
        }
        
        for local_param, search_type in param_mapping.items():
            if params.get(local_param):
                try:
                    response = requests.post(
                        f"{self.base_url}/search",
                        json={"type": search_type, "query": params[local_param]},
                        headers={"Authorization": f"Bearer {self.api_key}"},
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.append({
                            "source": "raidfind",
                            "field": local_param,
                            "value": params[local_param],
                            "found": True,
                            "data": data
                        })
                except Exception as e:
                    results.append({
                        "source": "raidfind",
                        "field": local_param,
                        "value": params[local_param],
                        "found": False,
                        "error": str(e)
                    })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class VKAPIModule(BaseSearchModule):
    """VK OSINT - профиль + группы/стена/друзья + внешние источники (как в Chronosphere)"""

    SUPPORTED_FIELDS = ["vk", "vk_id"]

    def __init__(self):
        self.base_url = "https://api.vk.com/method/"
        self.token = VK_TOKEN
        self.version = VK_API_VERSION
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def _request(self, method: str, params: dict) -> dict:
        payload = {**params, "access_token": self.token, "v": self.version}
        try:
            with self._lock:
                response = self.session.get(f"{self.base_url}{method}", params=payload, timeout=20)
            response.raise_for_status()
            data = response.json()
            if "error" in data:
                return {"error": data["error"].get("error_msg", "Unknown error")}
            return data.get("response", {})
        except Exception as exc:
            return {"error": str(exc)}

    def _format_date(self, timestamp) -> str:
        try:
            return datetime.fromtimestamp(int(timestamp)).strftime("%d.%m.%Y %H:%M")
        except Exception:
            return str(timestamp)

    def _clean_text(self, text: str, max_len: int = 500) -> str:
        if not text:
            return ""
        text = re.sub(r"\s+", " ", str(text)).strip()
        return text[:max_len] + "..." if len(text) > max_len else text

    def _external_topdb(self, vk_id: str) -> Dict[str, Any]:
        if BeautifulSoup is None:
            return {"source": "TopDB", "error": "BeautifulSoup не установлен"}
        try:
            url = f"http://topdb.ru/id{vk_id}"
            response = requests.get(url, headers=self.session.headers, timeout=15)
            response.raise_for_status()
            page_text = BeautifulSoup(response.content, "html.parser").get_text("\n", strip=True)
            if "Пользователь не найден" in page_text:
                return {"source": "TopDB", "url": url, "info": "Информация не найдена"}
            start = -1
            for marker in ("Полезное", "Личная информация", "Основное", "Интересы"):
                start = page_text.find(marker)
                if start != -1:
                    break
            if start == -1:
                info = page_text[:1500]
            else:
                end = page_text.find("Контакты", start)
                info = page_text[start:end if end != -1 else None]
            return {"source": "TopDB", "url": url, "info": self._clean_text(info, 1500)}
        except Exception as exc:
            return {"source": "TopDB", "error": str(exc)}

    def _external_poiski_pro(self, vk_id: str) -> Dict[str, Any]:
        if BeautifulSoup is None:
            return {"source": "Poiski.pro", "error": "BeautifulSoup не установлен"}
        try:
            url = f"https://poiski.pro/vk/user/id{vk_id}"
            response = requests.get(url, headers=self.session.headers, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            lines = [line.strip() for line in soup.get_text("\n").splitlines() if len(line.strip()) > 3]
            for index, line in enumerate(lines):
                if "Адрес страницы" in line:
                    lines = lines[:index]
                    break
            return {"source": "Poiski.pro", "url": url, "info": self._clean_text("\n".join(lines), 1500) or "Информация не найдена"}
        except Exception as exc:
            return {"source": "Poiski.pro", "error": str(exc)}

    def _external_onli_vk(self, vk_id: str) -> Dict[str, Any]:
        if BeautifulSoup is None:
            return {"source": "Onli VK", "error": "BeautifulSoup не установлен"}
        try:
            url = f"https://onli-vk.ru/id{vk_id}"
            response = requests.get(url, headers=self.session.headers, timeout=15)
            response.raise_for_status()
            page_text = BeautifulSoup(response.text, "html.parser").get_text("\n")
            patterns = (
                r"Online[^.]*", r"Онлайн[^.]*", r"Offline[^.]*?последняя активность[^.]*",
                r"Оффлайн[^.]*?последняя активность[^.]*", r"был.*в сети[^.]*",
                r"была.*в сети[^.]*", r"активность.*\d{1,2}\s+\w+\s+\d{4}",
            )
            for line in page_text.splitlines():
                clean_line = " ".join(line.split())
                if len(clean_line) < 5:
                    continue
                for pattern in patterns:
                    match = re.search(pattern, clean_line, re.I)
                    if match:
                        return {"source": "Onli VK", "url": url, "activity": " ".join(match.group(0).split())}
            return {"source": "Onli VK", "url": url, "activity": "Информация не найдена"}
        except Exception as exc:
            return {"source": "Onli VK", "error": str(exc)}

    def _external_looka_one(self, vk_id: str) -> Dict[str, Any]:
        if BeautifulSoup is None:
            return {"source": "Looka.one", "error": "BeautifulSoup не установлен"}
        try:
            url = f"https://looka.one/vk_user/id{vk_id}"
            response = requests.get(url, headers=self.session.headers, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            content = soup.find("div", class_="profile-info") or soup.find("main") or soup.find("article")
            if not content:
                return {"source": "Looka.one", "error": "Информация не найдена"}
            info = content.get_text(" ", strip=True)
            for phrase in (
                "Ориентировочное положение на карте", "Эта страница создана на лету",
                "путем запроса к API от ВКонтакте", "содержащего только открытые данные",
                "Сайт Looka.one НЕ собирает и НЕ хранит данные", "Политика персональных данных",
                "Удаление информации",
            ):
                info = info.replace(phrase, "")
            info = self._clean_text(info, 1500)
            if not info:
                return {"source": "Looka.one", "error": "Информация не найдена"}
            return {"source": "Looka.one", "url": url, "info": info}
        except Exception as exc:
            return {"source": "Looka.one", "error": str(exc)}

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        raw_vk = params.get("vk") or params.get("vk_id")
        if not raw_vk:
            return {"success": False, "results": [], "total": 0}

        vk_id = extract_vk_id(raw_vk)
        modules: Dict[str, Any] = {}

        user = self._request("users.get", {
            "user_ids": vk_id,
            "fields": "photo_max,verified,sex,bdate,city,country,home_town,status,education,about,activities,interests,music,movies,tv,books,games,quotes,online,last_seen,followers_count,occupation,relation,personal,schools,universities,domain",
        })
        if user and not (isinstance(user, dict) and user.get("error")):
            user_data = user[0] if isinstance(user, list) and user else user
            if isinstance(user_data, dict):
                modules["user_info"] = {
                    "id": user_data.get("id"),
                    "first_name": user_data.get("first_name", ""),
                    "last_name": user_data.get("last_name", ""),
                    "domain": user_data.get("domain", ""),
                    "sex": "Женский" if user_data.get("sex") == 1 else "Мужской" if user_data.get("sex") == 2 else "Не указан",
                    "bdate": user_data.get("bdate", "Не указана"),
                    "city": (user_data.get("city") or {}).get("title", "Не указан"),
                    "country": (user_data.get("country") or {}).get("title", "Не указана"),
                    "home_town": user_data.get("home_town", "Не указан"),
                    "status": user_data.get("status", "Нет статуса"),
                    "about": user_data.get("about", ""),
                    "verified": user_data.get("verified", 0) == 1,
                    "photo": user_data.get("photo_max", ""),
                    "online": user_data.get("online", 0) == 1,
                    "followers_count": user_data.get("followers_count", 0),
                    "last_seen": self._format_date((user_data.get("last_seen") or {}).get("time", 0)) if user_data.get("last_seen") else "Неизвестно",
                }
                if user_data.get("id"):
                    vk_id = str(user_data["id"])
                results.append(_result_ok("vk_api", "vk", raw_vk, modules["user_info"], method="users.get"))
        elif isinstance(user, dict) and user.get("error"):
            results.append(_result_err("vk_api", "vk", raw_vk, user.get("error")))

        for method_name, method, extra in (
            ("groups.get", "groups.get", {"user_id": vk_id, "extended": 1, "fields": "name,members_count", "count": 50}),
            ("friends.get", "friends.get", {"user_id": vk_id, "count": 20, "fields": "online"}),
            ("wall.get", "wall.get", {"owner_id": vk_id, "count": 20, "extended": 1}),
            ("users.getSubscriptions", "users.getSubscriptions", {"user_id": vk_id, "count": 20, "extended": 1}),
            ("photos.get", "photos.get", {"owner_id": vk_id, "album_id": "profile", "count": 10, "extended": 1}),
        ):
            data = self._request(method, extra)
            if isinstance(data, dict) and data.get("error"):
                results.append(_result_err("vk_api", "vk", raw_vk, data.get("error")))
            elif data:
                results.append(_result_ok("vk_api", "vk", raw_vk, data, method=method_name))

        for name, func in (
            ("topdb", self._external_topdb),
            ("poiski_pro", self._external_poiski_pro),
            ("onli_vk", self._external_onli_vk),
            ("looka_one", self._external_looka_one),
        ):
            external = func(vk_id)
            if external.get("error"):
                results.append(_result_err(f"vk_{name}", "vk", raw_vk, external.get("error")))
            else:
                results.append(_result_ok(f"vk_{name}", "vk", raw_vk, external, method=name))

        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class TruecallerModule(BaseSearchModule):
    """Truecaller search5 — Authorization: Bearer <installationId>"""

    SUPPORTED_FIELDS = ["phone", "number"]
    TIMEOUT = 4.0
    # Truecaller часто таймаутит/требует VPN — после 3 фейлов circuit breaker отключит автоматически

    def __init__(self):
        self.hosts = [
            "https://search5-noneu.truecaller.com/v2/search",
            "https://search5.truecaller.com/v2/search",
        ]
        self.installation_id = TRUECALLER_INSTALLATION_ID

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        phone = params.get("phone") or params.get("number")
        if not phone:
            return {"success": False, "results": [], "total": 0}
        normalized = normalize_phone_e164(phone)
        query_params = {
            "q": normalized,
            "countryCode": "RU",
            "type": "4",
            "encoding": "json",
            "placement": "SEARCHRESULTS,HISTORY,DETAILS",
        }
        headers = {
            "User-Agent": "Truecaller/14.1.6 (Android;14)",
            "Accept": "application/json",
            "Content-Type": "application/json; charset=UTF-8",
            "Authorization": f"Bearer {self.installation_id}",
        }
        last_error = None
        for url in self.hosts:
            response, err = self._get(url, params=query_params, headers=headers)
            if response is None:
                last_error = err
                # timeout/connection — не тратим время на остальные хосты
                if err and (err.startswith("timeout") or err.startswith("connection_error") or err.startswith("circuit_open")):
                    break
                continue
            if response.status_code == 200:
                try:
                    data = response.json()
                except Exception:
                    last_error = "invalid json"
                    continue
                records = data.get("data") or []
                if not records:
                    return {"success": False, "results": [], "total": 0}
                record = records[0]
                flat = {
                    "name": record.get("name"),
                    "phone": record.get("phones", [{}])[0].get("e164Format") if record.get("phones") else record.get("phoneNumber") or normalized,
                    "country": (record.get("addresses") or [{}])[0].get("countryCode") if record.get("addresses") else record.get("countryCode"),
                    "carrier": (record.get("phones") or [{}])[0].get("carrier") if record.get("phones") else record.get("carrier"),
                    "score": record.get("score"),
                    "spam_score": (record.get("spamInfo") or {}).get("spamScore"),
                    "raw": record,
                }
                flat = {k: v for k, v in flat.items() if v not in (None, [], {})}
                results.append(_result_ok("truecaller", "phone", phone, flat))
                return {"success": True, "results": results, "total": len(results)}
            if response.status_code in (401, 403):
                last_error = f"auth HTTP {response.status_code}"
                break
            last_error = f"HTTP {response.status_code}"
        if last_error:
            logger.debug("Truecaller skip: %s", last_error)
        return {"success": False, "results": [], "total": 0}


class InfinitySearchModule(BaseSearchModule):
    """Infinity Search API - поиск по телефону, email, ФИО"""

    SUPPORTED_FIELDS = ["phone", "number", "email", "fio", "fullname", "name", "bdate"]

    def __init__(self):
        self.base_url = INFINITY_SEARCH_URL
        if not self.base_url.endswith("find.php"):
            self.base_url = self.base_url.rstrip("/") + "/find.php"
        self.tokens = [t for t in (INFINITY_SEARCH_TOKEN, INFINITY_SEARCH_TOKEN_ALT, INFINITY_SEARCH_API_KEY) if t]
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "GloomApi/2.1"})

    def _get(self, params: dict) -> Tuple[Optional[dict], Optional[str]]:
        last_error = None
        for token in self.tokens:
            try:
                with self._lock:
                    response = self.session.get(
                        self.base_url,
                        params={**params, "token": token},
                        timeout=30,
                    )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("results"):
                        return data, None
                    last_error = "Данные не найдены"
                else:
                    last_error = f"HTTP {response.status_code}"
            except Exception as exc:
                last_error = str(exc)
        return None, last_error or "Infinity недоступен"

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []

        if params.get("phone") or params.get("number"):
            phone = params.get("phone") or params.get("number")
            clean = normalize_phone(phone)
            data, error = self._get({"phone": clean})
            if data:
                results.append(_result_ok("infinity_search", "phone", phone, data))
            elif error:
                results.append(_result_err("infinity_search", "phone", phone, error))

        fio = params.get("fio") or params.get("fullname") or params.get("name")
        if fio:
            query = {"fio": fio}
            if params.get("bdate"):
                query["bdate"] = params["bdate"]
            else:
                bdate_match = re.search(r"(\d{2}\.\d{2}\.\d{4})", str(fio))
                if bdate_match:
                    query["fio"] = re.sub(r"\d{2}\.\d{2}\.\d{4}", "", str(fio)).strip() or fio
                    query["bdate"] = bdate_match.group(1)
            data, error = self._get(query)
            if data:
                results.append(_result_ok("infinity_search", "fio", fio, data))
            elif error:
                results.append(_result_err("infinity_search", "fio", fio, error))

        if params.get("email"):
            email = params["email"]
            data, error = self._get({"email": email})
            if data:
                results.append(_result_ok("infinity_search", "email", email, data))
            elif error:
                results.append(_result_err("infinity_search", "email", email, error))

        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}

class FaceSearchModule(BaseSearchModule):
    # auto-disabled: требует photo_url и внешний bff
    ENABLED = False
    """Face Search API - поиск лиц по фото (detect-faces, search-faces)"""
    
    def __init__(self):
        self.base_url = "https://similarfaces.me"
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Face search требует URL изображения
        if params.get("photo_url"):
            # detect-faces
            try:
                response = requests.post(
                    f"{self.base_url}/bff/detect-faces",
                    json={"image_url": params["photo_url"]},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "face_search",
                        "method": "detect-faces",
                        "field": "photo_url",
                        "value": params["photo_url"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "face_search",
                    "method": "detect-faces",
                    "field": "photo_url",
                    "value": params["photo_url"],
                    "found": False,
                    "error": str(e)
                })
            
            # search-faces
            try:
                response = requests.post(
                    f"{self.base_url}/bff/search-faces",
                    json={"image_url": params["photo_url"]},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "face_search",
                        "method": "search-faces",
                        "field": "photo_url",
                        "value": params["photo_url"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "face_search",
                    "method": "search-faces",
                    "field": "photo_url",
                    "value": params["photo_url"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class DeepScanModule(BaseSearchModule):
    ENABLED = False  # DNS недоступен
    SUPPORTED_FIELDS = ["phone", "email", "fio", "fullname", "name", "nick", "username"]
    """DeepScan API - поиск по телефону, email, ФИО, никнеймам"""
    
    def __init__(self):
        self.base_url = "https://api.deepscan.cc"
        self.load_balancer = deepscan_load_balancer
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Mapping параметров к типам поиска DeepScan
        param_mapping = {
            "phone": "phone",
            "email": "email",
            "fio": "fio",
            "fullname": "fio",
            "name": "fio",
            "nick": "nick",
            "username": "nick",
            "vk": "vk",
            "telegram": "telegram",
            "ip": "ip"
        }
        
        for local_param, search_type in param_mapping.items():
            if params.get(local_param):
                try:
                    key = self.load_balancer.get_next_key()
                    response = requests.post(
                        f"{self.base_url}/search",
                        json={"type": search_type, "query": params[local_param]},
                        headers={"Authorization": f"Bearer {key}"},
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.append({
                            "source": "deepscan",
                            "field": local_param,
                            "value": params[local_param],
                            "found": True,
                            "data": data,
                            "api_key": key[:8] + "..."
                        })
                except Exception as e:
                    results.append({
                        "source": "deepscan",
                        "field": local_param,
                        "value": params[local_param],
                        "found": False,
                        "error": str(e)
                    })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class BigBaseModule(BaseSearchModule):
    """BigBase API — POST /api/search, Authorization без Bearer, body {"search": "..."}."""

    SUPPORTED_FIELDS = [
        "phone", "email", "fio", "fullname", "name", "ip", "inn", "snils",
        "passport", "vin", "car_number", "address",
    ]
    TIMEOUT = 20.0

    def __init__(self):
        extra = [x.strip() for x in str(BIGBASE_API_KEYS or "").split(",") if x.strip()]
        keys = [BIGBASE_API_KEY, BIGBASE_TOKEN, *extra]
        self.keys = list(dict.fromkeys(k for k in keys if k))
        self.base_url = "https://bigbase.top/api/search"

    def _search_once(self, query: str) -> Tuple[Optional[dict], Optional[str]]:
        last_error = None
        for key in self.keys:
            response, err = self._post(
                self.base_url,
                json={"search": query},
                headers={"Authorization": key, "Content-Type": "application/json"},
            )
            if err and response is None:
                last_error = err
                continue
            if response is None:
                last_error = err or "no response"
                continue
            if response.status_code in (401, 403):
                last_error = f"auth HTTP {response.status_code}"
                continue
            if response.status_code == 429:
                return None, "rate_limited"
            if response.status_code != 200:
                last_error = f"HTTP {response.status_code}"
                continue
            try:
                data = response.json()
            except Exception:
                last_error = "invalid json"
                continue
            if isinstance(data, dict) and data.get("error") and not data.get("results") and not data.get("data"):
                last_error = str(data.get("error"))
                continue
            if data:
                return data, None
            last_error = "empty"
        return None, last_error or "BigBase unavailable"

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        seen = set()
        field_order = [
            "phone", "email", "fio", "fullname", "name", "ip", "inn", "snils",
            "passport", "vin", "car_number", "address",
        ]
        for field in field_order:
            value = params.get(field)
            if not value:
                continue
            query = normalize_phone(value) if field == "phone" else str(value).strip()
            if not query or query in seen:
                continue
            seen.add(query)
            data, error = self._search_once(query)
            if data is not None:
                results.append(_result_ok("bigbase", field, value, data))
            elif error:
                logger.debug("BigBase %s: %s", query, error)
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}

class OnuxModule(BaseSearchModule):
    # auto-disabled: DNS недоступен
    ENABLED = False
    """Onux API - универсальный поиск по различным параметрам"""
    
    def __init__(self):
        self.base_url = ONUX_API_URL
        self.token = ONUX_API_TOKEN
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Mapping параметров к типам поиска Onux
        param_mapping = {
            "phone": "phone",
            "email": "email",
            "fio": "fio",
            "fullname": "fio",
            "name": "fio",
            "nick": "nick",
            "vk": "vk",
            "telegram": "tg",
            "ip": "ip",
            "inn": "inn",
            "snils": "snils",
            "passport": "passport",
            "vin": "car",
            "car_number": "car",
            "ok": "ok",
            "fb": "fb"
        }
        
        for local_param, search_type in param_mapping.items():
            if params.get(local_param):
                try:
                    response = requests.post(
                        f"{self.base_url}/search",
                        json={"type": search_type, "query": params[local_param]},
                        headers={"X-API-Key": self.token},
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.append({
                            "source": "onux",
                            "field": local_param,
                            "value": params[local_param],
                            "found": True,
                            "data": data
                        })
                except Exception as e:
                    results.append({
                        "source": "onux",
                        "field": local_param,
                        "value": params[local_param],
                        "found": False,
                        "error": str(e)
                    })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class TulasayModule(BaseSearchModule):
    ENABLED = False  # connection refused
    SUPPORTED_FIELDS = ["phone", "email", "fio", "fullname", "name", "passport", "inn", "snils"]
    """Tulasay API - унифицированный поиск через JyCode Gateway"""
    
    def __init__(self):
        self.base_url = TULASAY_API_URL
        self.token = TULASAY_API_TOKEN
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Mapping параметров к типам поиска Tulasay
        param_mapping = {
            "phone": "phone",
            "email": "email",
            "fio": "fio",
            "fullname": "fio",
            "name": "fio",
            "nick": "nick",
            "username": "nick",
            "vk": "vk",
            "telegram": "telegram",
            "ip": "ip",
            "inn": "inn",
            "snils": "snils",
            "passport": "passport",
            "vin": "auto_vehicle",
            "car_number": "auto_vehicle",
            "address": "address",
            "card": "card",
            "imei": "imei",
            "bdate": "bdate",
            "social": "social"
        }
        
        for local_param, search_type in param_mapping.items():
            if params.get(local_param):
                try:
                    response = requests.post(
                        f"{self.base_url}/search",
                        json={
                            "query": params[local_param],
                            "search_type": search_type,
                            "auto": True
                        },
                        headers={"Authorization": f"Bearer {self.token}"},
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.append({
                            "source": "tulasay",
                            "field": local_param,
                            "value": params[local_param],
                            "found": True,
                            "data": data
                        })
                except Exception as e:
                    results.append({
                        "source": "tulasay",
                        "field": local_param,
                        "value": params[local_param],
                        "found": False,
                        "error": str(e)
                    })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class RedMaskModule(BaseSearchModule):
    # auto-disabled: ngrok URL нестабилен
    ENABLED = False
    """RedMask API - универсальный поиск по телефону, Telegram, VK"""
    
    def __init__(self):
        self.base_url = REDMASK_API_URL
        self.api_key = REDMASK_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # RedMask поддерживает: телефон, Telegram username, Telegram ID, VK ID
        query_mapping = {
            "phone": "phone",
            "telegram": "telegram",
            "telegram_id": "telegram",
            "vk": "vk",
            "vk_id": "vk"
        }
        
        for local_param, search_type in query_mapping.items():
            if params.get(local_param):
                query_value = params[local_param]
                
                # Форматируем запрос в соответствии с документацией RedMask
                # Телефон: +79991234567
                # Telegram: @username или username
                # VK: id123456789
                
                if search_type == "phone":
                    # Приводим телефон к формату +7...
                    if not query_value.startswith("+"):
                        query_value = f"+{query_value}"
                elif search_type == "telegram":
                    # Убираем @ если есть
                    if query_value.startswith("@"):
                        query_value = query_value[1:]
                elif search_type == "vk":
                    # Приводим к формату id...
                    if not str(query_value).startswith("id"):
                        query_value = f"id{query_value}"
                
                try:
                    response = requests.post(
                        self.base_url,
                        json={"api_key": self.api_key, "query": query_value},
                        headers={"X-API-Key": self.api_key},
                        timeout=15
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.append({
                            "source": "redmask",
                            "field": local_param,
                            "value": params[local_param],
                            "found": True,
                            "data": data
                        })
                    else:
                        results.append({
                            "source": "redmask",
                            "field": local_param,
                            "value": params[local_param],
                            "found": False,
                            "error": f"HTTP {response.status_code}"
                        })
                except Exception as e:
                    results.append({
                        "source": "redmask",
                        "field": local_param,
                        "value": params[local_param],
                        "found": False,
                        "error": str(e)
                    })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class IPInfoModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """IPInfo API - геолокация и информация об IP"""
    
    def __init__(self):
        self.base_url = "https://ipinfo.io"
        self.api_key = IPINFO_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                response = requests.get(
                    f"{self.base_url}/{params['ip']}/json",
                    params={"token": self.api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "ipinfo",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "ipinfo",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class IPStackModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """IPStack API - геолокация IP"""
    
    def __init__(self):
        self.base_url = "http://api.ipstack.com"
        self.api_key = IPSTACK_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                response = requests.get(
                    f"{self.base_url}/{params['ip']}",
                    params={
                        "access_key": self.api_key,
                        "fields": "main,country_code,region_code,city,zip,latitude,longitude,location,continent_code,region_name"
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "ipstack",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "ipstack",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class IPGeolocationModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """IPGeolocation API - геолокация IP"""
    
    def __init__(self):
        self.base_url = "https://api.ipgeolocation.io"
        self.api_key = IPGEOLOCATION_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                response = requests.get(
                    f"{self.base_url}/ipgeo",
                    params={
                        "apiKey": self.api_key,
                        "ip": params["ip"],
                        "fields": "country_code2,country_name,state_prov,city,zipcode,latitude,longitude"
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "ipgeolocation",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "ipgeolocation",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class IPDataModule(BaseSearchModule):
    """IPData API - информация об IP"""
    # auto-disabled: invalid API key
    ENABLED = False
    
    def __init__(self):
        self.base_url = "https://api.ipdata.co"
        self.api_key = IPDATA_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                response = requests.get(
                    f"{self.base_url}/{params['ip']}",
                    params={"api_key": self.api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "ipdata",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "ipdata",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class IPBaseModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """IPBase API - геолокация IP"""
    
    def __init__(self):
        self.base_url = "https://api.ipbase.com"
        self.api_key = IPBASE_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                response = requests.get(
                    f"{self.base_url}/v2/info",
                    params={"apikey": self.api_key, "ip": params["ip"]},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "ipbase",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "ipbase",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class IP2LocationModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """IP2Location API - геолокация IP"""
    
    def __init__(self):
        self.base_url = "https://api.ip2location.io"
        self.api_key = IP2LOCATION_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                response = requests.get(
                    f"{self.base_url}/",
                    params={
                        "key": self.api_key,
                        "ip": params["ip"],
                        "format": "json"
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "ip2location",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "ip2location",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class NumVerifyModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["phone", "number"]
    """NumVerify API - валидация телефонных номеров"""
    
    def __init__(self):
        self.base_url = "http://apilayer.net/api"
        self.api_key = NUMVERIFY_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("phone"):
            try:
                response = requests.get(
                    f"{self.base_url}/validate",
                    params={
                        "access_key": self.api_key,
                        "number": params["phone"],
                        "country_code": "",
                        "format": 1
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "numverify",
                        "field": "phone",
                        "value": params["phone"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "numverify",
                    "field": "phone",
                    "value": params["phone"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class MailboxlayerModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["email"]
    """Mailboxlayer API - валидация email"""
    
    def __init__(self):
        self.base_url = "https://apilayer.net/api"
        self.api_key = MAILBOXLAYER_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("email"):
            try:
                response = requests.get(
                    f"{self.base_url}/check",
                    params={
                        "access_key": self.api_key,
                        "email": params["email"],
                        "smtp": 1,
                        "format": 1
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "mailboxlayer",
                        "field": "email",
                        "value": params["email"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "mailboxlayer",
                    "field": "email",
                    "value": params["email"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class EmailValidModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["email"]
    """EmailValid API (APIVerve) - валидация email"""
    
    def __init__(self):
        self.base_url = "https://api.apiverve.com"
        self.api_key = EMAIL_VALID_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("email"):
            try:
                response = requests.get(
                    f"{self.base_url}/v1/emailvalidator",
                    params={"email": params["email"]},
                    headers={"x-api-key": self.api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "email_valid",
                        "field": "email",
                        "value": params["email"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "email_valid",
                    "field": "email",
                    "value": params["email"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class EmailReputationModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["email"]
    """EmailReputation API (Abstract) - проверка репутации email"""
    
    def __init__(self):
        self.base_url = "https://emailreputation.abstractapi.com"
        self.api_key = EMAIL_REPUTATION_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("email"):
            try:
                response = requests.get(
                    f"{self.base_url}/v1",
                    params={"api_key": self.api_key, "email": params["email"]},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "email_reputation",
                        "field": "email",
                        "value": params["email"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "email_reputation",
                    "field": "email",
                    "value": params["email"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class VeriPhoneModule(BaseSearchModule):
    """VeriPhone API - валидация телефонных номеров"""
    ENABLED = False  # insufficient credits (402)
    SUPPORTED_FIELDS = ["phone", "number"]
    
    def __init__(self):
        self.base_url = "https://api.veriphone.io"
        self.api_key = VERIPHONE_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("phone"):
            try:
                response = requests.get(
                    f"{self.base_url}/v2/verify",
                    params={"key": self.api_key, "phone": params["phone"]},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "veriphone",
                        "field": "phone",
                        "value": params["phone"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "veriphone",
                    "field": "phone",
                    "value": params["phone"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class ProxyCheckModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """ProxyCheck API - проверка IP на прокси/VPN"""
    
    def __init__(self):
        self.base_url = "https://proxycheck.io"
        self.api_keys = [PROXYCHECK1_API_KEY, PROXYCHECK2_API_KEY]
        self.current_key_index = 0
    
    def get_next_key(self) -> str:
        key = self.api_keys[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        return key
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                key = self.get_next_key()
                response = requests.get(
                    f"{self.base_url}/v2/{params['ip']}",
                    params={"key": key, "vpn": 1, "asn": 1},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "proxycheck",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "proxycheck",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class AbuseIPDBModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """AbuseIPDB API - проверка IP на злоупотребления"""
    
    def __init__(self):
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.api_key = ABUSEIPDB_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                response = requests.get(
                    f"{self.base_url}/check",
                    params={
                        "ipAddress": params["ip"],
                        "maxAgeInDays": 90,
                        "verbose": ""
                    },
                    headers={"Key": self.api_key, "Accept": "application/json"},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "abuseipdb",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "abuseipdb",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class ShodanModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """Shodan API - киберразведка по IP"""
    TIMEOUT = 10.0

    def __init__(self):
        self.base_url = "https://api.shodan.io"
        self.api_keys = [k for k in (SHODAN_API_KEY_ALT, SHODAN_API_KEY) if k]

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        ip = params.get("ip")
        if not ip:
            return {"success": False, "results": [], "total": 0}
        last_error = None
        for key in self.api_keys:
            response, err = self._get(
                f"{self.base_url}/shodan/host/{ip}",
                params={"key": key},
            )
            if response is not None and response.status_code == 200:
                results.append(_result_ok("shodan", "ip", ip, response.json()))
                break
            last_error = err or (f"HTTP {response.status_code}" if response is not None else "no response")
        if not results and last_error:
            logger.debug("Shodan: %s", last_error)
        return {"success": bool(results), "results": results, "total": len(results)}


class HunterModule(BaseSearchModule):
    # auto-disabled: placeholder API key
    ENABLED = False
    """Hunter API - поиск email по домену"""
    
    def __init__(self):
        self.base_url = "https://api.hunter.io/v2"
        self.api_key = HUNTER_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("domain"):
            try:
                response = requests.get(
                    f"{self.base_url}/domain-search",
                    params={"domain": params["domain"], "api_key": self.api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "hunter",
                        "field": "domain",
                        "value": params["domain"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "hunter",
                    "field": "domain",
                    "value": params["domain"],
                    "found": False,
                    "error": str(e)
                })
        
        if params.get("email"):
            try:
                response = requests.get(
                    f"{self.base_url}/email-finder",
                    params={"domain": params.get("domain", ""), "api_key": self.api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "hunter",
                        "field": "email",
                        "value": params["email"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "hunter",
                    "field": "email",
                    "value": params["email"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class HIBPModule(BaseSearchModule):
    """Have I Been Pwned — breachedaccount (email) + Pwned Passwords range API"""

    SUPPORTED_FIELDS = ["email", "password"]
    TIMEOUT = 10.0

    def __init__(self):
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.passwords_url = "https://api.pwnedpasswords.com"
        self.api_key = HIBP_API_KEY
        # placeholder keys are skipped for authenticated endpoints
        self._key_usable = bool(self.api_key) and not self.api_key.startswith("0123456789abcdef")

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        if params.get("email") and self._key_usable:
            email = params["email"]
            response, err = self._get(
                f"{self.base_url}/breachedaccount/{urllib.parse.quote(email)}",
                params={"truncateResponse": "false"},
                headers={
                    "hibp-api-key": self.api_key,
                    "user-agent": "GloomApi",
                    "Accept": "application/json",
                },
            )
            if response is not None and response.status_code == 200:
                results.append(_result_ok("hibp", "email", email, response.json()))
            elif response is not None and response.status_code == 404:
                pass  # not breached
            elif err:
                logger.debug("HIBP email: %s", err)

        # Pwned Passwords — публичный k-anonymity range API (без ключа)
        password = params.get("password")
        if password:
            sha1 = hashlib.sha1(str(password).encode("utf-8")).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            response, err = self._get(
                f"{self.passwords_url}/range/{prefix}",
                headers={"User-Agent": "GloomApi", "Add-Padding": "true"},
            )
            if response is not None and response.status_code == 200:
                count = 0
                for line in response.text.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[0].strip().upper() == suffix:
                        count = int(parts[1].strip().split("*")[0] or 0)
                        break
                results.append(_result_ok("hibp_passwords", "password", "***", {
                    "breached": count > 0,
                    "count": count,
                }))
            elif err:
                logger.debug("HIBP passwords: %s", err)

        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class LeakCheckModule(BaseSearchModule):
    """LeakCheck — Pro API v2 + Public API fallback (docs.leakcheck.io)"""

    SUPPORTED_FIELDS = ["email", "phone", "username", "nick", "domain", "ip"]
    TIMEOUT = 12.0

    def __init__(self):
        self.pro_url = "https://leakcheck.io/api/v2"
        self.public_url = "https://leakcheck.io/api/public"
        self.api_key = LEAKCHECK_API_KEY
        # ключ из репозитория — placeholder hex, Pro не пройдёт
        self._pro_usable = bool(self.api_key) and "REAL" not in self.api_key.upper() and len(self.api_key) >= 40 and not self.api_key.startswith("49535f")

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        candidates = []
        for field, qtype in (
            ("email", "email"),
            ("phone", "phone"),
            ("username", "username"),
            ("nick", "username"),
            ("domain", "domain"),
            ("ip", None),
        ):
            if params.get(field):
                candidates.append((field, params[field], qtype))
        seen = set()
        for field, query, qtype in candidates:
            if query in seen:
                continue
            seen.add(query)
            # Pro API
            if self._pro_usable:
                req_params = {"limit": 100}
                if qtype:
                    req_params["type"] = qtype
                response, err = self._get(
                    f"{self.pro_url}/query/{urllib.parse.quote(str(query), safe='')}",
                    params=req_params,
                    headers={"Accept": "application/json", "X-API-Key": self.api_key},
                )
                if response is not None and response.status_code == 200:
                    data = response.json()
                    if data.get("success") or data.get("found"):
                        results.append(_result_ok("leakcheck", field, query, data, api="pro"))
                        continue
                elif response is not None and response.status_code in (400, 401):
                    self._pro_usable = False

            # Public API — только email/username (без IP)
            if field in ("email", "username", "nick") or "@" in str(query):
                response, err = self._get(
                    self.public_url,
                    params={"check": query},
                    headers={"Accept": "application/json"},
                )
                if response is not None and response.status_code == 200:
                    data = response.json()
                    if data.get("success") and data.get("found"):
                        results.append(_result_ok("leakcheck", field, query, data, api="public"))
                elif err:
                    logger.debug("LeakCheck public: %s", err)
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class SnusbaseModule(BaseSearchModule):
    """Snusbase — POST /data/search, header Auth: <api_key>"""

    SUPPORTED_FIELDS = ["email", "username", "nick", "ip", "phone", "name", "fio", "fullname", "password", "hash"]
    TIMEOUT = 10.0

    def __init__(self):
        self.base_url = "https://api.snusbase.com"
        self.key = SNUSBASE_KEY

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        type_map = [
            ("email", "email"),
            ("username", "username"),
            ("nick", "username"),
            ("ip", "lastip"),
            ("phone", "phone"),
            ("name", "name"),
            ("fio", "name"),
            ("fullname", "name"),
            ("password", "password"),
            ("hash", "hash"),
        ]
        terms = []
        types = []
        for field, t in type_map:
            if params.get(field) and params[field] not in terms:
                terms.append(params[field])
                types.append(t)
        if not terms:
            return {"success": False, "results": [], "total": 0}

        response, err = self._post(
            f"{self.base_url}/data/search",
            json={"terms": terms[:10], "types": types[:10]},
            headers={"Auth": self.key, "Content-Type": "application/json", "Accept": "application/json"},
        )
        if response is not None and response.status_code == 200:
            data = response.json()
            if data.get("results") or data.get("size"):
                results.append(_result_ok("snusbase", "query", terms[0], data))
        elif err:
            logger.debug("Snusbase: %s", err)
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class DehashedModule(BaseSearchModule):
    # auto-disabled: placeholder API key
    ENABLED = False
    """Dehashed API - поиск в утекших базах"""
    
    def __init__(self):
        self.base_url = "https://api.dehashed.com"
        self.api_key = DEHASHED_API_KEY
        self.email = DEHASHED_EMAIL
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Dehashed supports email, username, ip, phone, name
        query = params.get("email") or params.get("username") or params.get("ip") or params.get("phone") or params.get("name")
        if query:
            try:
                import base64
                auth_str = f"{self.email}:{self.api_key}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                
                search_type = "email" if params.get("email") else "username" if params.get("username") else "ip" if params.get("ip") else "phone" if params.get("phone") else "name"
                
                response = requests.get(
                    f"{self.base_url}/search",
                    params={"query": f"{search_type}:{query}"},
                    headers={"Authorization": f"Basic {auth_b64}"},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "dehashed",
                        "field": search_type,
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "dehashed",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class WeLeakInfoModule(BaseSearchModule):
    # auto-disabled: placeholder API key
    ENABLED = False
    """WeLeakInfo API - поиск утечек данных"""
    
    def __init__(self):
        self.base_url = "https://api.weleakinfo.com"
        self.api_key = WELEAKINFO_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("email") or params.get("username") or params.get("phone")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/v3/search",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "weleakinfo",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "weleakinfo",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class CensysModule(BaseSearchModule):
    # auto-disabled: placeholder credentials
    ENABLED = False
    """Censys API - киберразведка по IP"""
    
    def __init__(self):
        self.base_url = "https://search.censys.io"
        self.api_id = CENSYS_ID
        self.api_secret = CENSYS_SECRET
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                import base64
                auth_str = f"{self.api_id}:{self.api_secret}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                
                response = requests.get(
                    f"{self.base_url}/api/v2/hosts/{params['ip']}",
                    headers={"Authorization": f"Basic {auth_b64}"},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "censys",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "censys",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class BinaryEdgeModule(BaseSearchModule):
    # auto-disabled: placeholder API key
    ENABLED = False
    """BinaryEdge API - киберразведка по IP"""
    
    def __init__(self):
        self.base_url = "https://api.binaryedge.io"
        self.api_key = BINARYEDGE_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                response = requests.get(
                    f"{self.base_url}/v2/query/ip/{params['ip']}",
                    headers={"X-Key": self.api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "binaryedge",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "binaryedge",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class GreyNoiseModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip"]
    """GreyNoise API - проверка IP на шум"""
    
    def __init__(self):
        self.base_url = "https://api.greynoise.io"
        self.api_key = GREYNOISE_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("ip"):
            try:
                # Community API: key header optional; 404 = IP not observed (валидный ответ)
                headers = {"Accept": "application/json", "key": self.api_key} if self.api_key and not str(self.api_key).startswith("gn-123") else {"Accept": "application/json"}
                response = requests.get(
                    f"{self.base_url}/v3/community/{params['ip']}",
                    headers=headers,
                    timeout=10
                )
                if response.status_code in (200, 404):
                    try:
                        data = response.json()
                    except Exception:
                        data = {"raw": response.text[:500], "status": response.status_code}
                    results.append({
                        "source": "greynoise",
                        "field": "ip",
                        "value": params["ip"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "greynoise",
                    "field": "ip",
                    "value": params["ip"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class IntelXModule(BaseSearchModule):
    # auto-disabled: placeholder API key
    ENABLED = False
    """IntelX API - поиск в утечках данных"""
    
    def __init__(self):
        self.base_url = "https://public.intelx.io"
        self.api_key = INTELX_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("email") or params.get("phone") or params.get("ip") or params.get("username")
        if query:
            try:
                # First, initiate search
                search_response = requests.post(
                    f"{self.base_url}/phonebook/search",
                    headers={"x-key": self.api_key},
                    json={"term": query, "maxresults": 100, "media": 0},
                    timeout=10
                )
                if search_response.status_code == 200:
                    search_data = search_response.json()
                    if search_data.get("id"):
                        # Then get results
                        results_response = requests.get(
                            f"{self.base_url}/phonebook/search/result/{search_data['id']}",
                            headers={"x-key": self.api_key},
                            timeout=10
                        )
                        if results_response.status_code == 200:
                            results_data = results_response.json()
                            results.append({
                                "source": "intelx",
                                "field": "query",
                                "value": query,
                                "found": True,
                                "data": results_data
                            })
            except Exception as e:
                results.append({
                    "source": "intelx",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class OFDataModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["inn", "ogrn", "name", "fio", "fullname"]
    """OFData API - поиск по российским данным"""
    
    def __init__(self):
        self.base_url = "https://ofdata.ru"
        self.api_key = OFDATA_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # OFData supports INN, OGRN, phone
        query = params.get("inn") or params.get("phone")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/search",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "ofdata",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "ofdata",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class FishAPIModule(BaseSearchModule):
    # auto-disabled: host нестабилен
    ENABLED = False
    """FishAPI - универсальный поиск"""
    
    def __init__(self):
        self.base_url = "https://fish-api--fishapi.replit.app"
        self.api_key = FISHAPI_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("phone") or params.get("email") or params.get("username") or params.get("ip")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/search",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "fishapi",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "fishapi",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class LeakIXModule(BaseSearchModule):
    SUPPORTED_FIELDS = ["ip", "domain"]
    """LeakIX API - поиск утечек данных"""
    
    def __init__(self):
        self.base_url = "https://leakix.net"
        self.api_key = LEAKIX_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("email") or params.get("phone") or params.get("ip") or params.get("domain")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/api/search",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "leakix",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "leakix",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class BlackEyeModule(BaseSearchModule):
    ENABLED = False  # connection reset
    SUPPORTED_FIELDS = ["phone", "email", "username", "nick", "ip"]
    """BlackEye API - универсальный поиск"""
    
    def __init__(self):
        self.base_url = "https://blackeyebot.duckdns.org"
        self.api_key = BLACKEYE_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("phone") or params.get("email") or params.get("username") or params.get("ip")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/search",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "blackeye",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "blackeye",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class CoreAPIModule(BaseSearchModule):
    # auto-disabled: IP endpoint нестабилен
    ENABLED = False
    """CoreAPI - универсальный поиск"""
    
    def __init__(self):
        self.base_url = "http://2.26.230.220:8081"
        self.api_key = COREAPI_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("phone") or params.get("email") or params.get("username") or params.get("ip")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/search",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "coreapi",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "coreapi",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class WhiteSearchModule(BaseSearchModule):
    # auto-disabled: эндпоинт 404
    ENABLED = False
    """WhiteSearch API - универсальный поиск"""
    
    def __init__(self):
        self.base_url = "https://api.whitesearch.workers.dev"
        self.api_key = WHITESEARCH_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("phone") or params.get("email") or params.get("username") or params.get("ip")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/api/search",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "whitesearch",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "whitesearch",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class W2SP3RModule(BaseSearchModule):
    # auto-disabled: непроверенный ключ
    ENABLED = False
    """W2SP3R API - универсальный поиск"""
    
    def __init__(self):
        self.base_url = "https://api.w2sp3r.biz"
        self.api_key = W2SP3R_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("phone") or params.get("email") or params.get("username") or params.get("ip")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/nyx",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "w2sp3r",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "w2sp3r",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class QuickFlowModule(BaseSearchModule):
    """QuickFlow Telegram lookup — GET /get-user?username=<без @>&token=..."""

    SUPPORTED_FIELDS = ["telegram", "username", "nick"]
    TIMEOUT = 15.0

    def __init__(self):
        self.base_url = "https://api.quickflow.lat/get-user"
        self.token = QUICKFLOW_TOKEN

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        raw = params.get("telegram") or params.get("username") or params.get("nick")
        if not raw:
            return {"success": False, "results": [], "total": 0}
        username = normalize_telegram_query(str(raw)).lstrip("@")
        if not username or username.isdigit():
            logger.debug("QuickFlow skip: numeric telegram_id is not supported")
            return {"success": False, "results": [], "total": 0}
        response, err = self._get(self.base_url, params={"username": username, "token": self.token})
        if err and response is None:
            results.append(_result_err("quickflow", "telegram", username, err))
            return {"success": False, "results": results, "total": len(results)}
        if response is None:
            results.append(_result_err("quickflow", "telegram", username, err or "no response"))
            return {"success": False, "results": results, "total": len(results)}
        if response.status_code != 200:
            results.append(_result_err("quickflow", "telegram", username, f"HTTP {response.status_code}"))
            return {"success": False, "results": results, "total": len(results)}
        try:
            data = response.json()
        except Exception:
            results.append(_result_err("quickflow", "telegram", username, "invalid json"))
            return {"success": False, "results": results, "total": len(results)}
        if not data or (isinstance(data, dict) and data.get("error") and not data.get("user") and not data.get("data")):
            results.append(_result_err("quickflow", "telegram", username, (data or {}).get("error") if isinstance(data, dict) else "empty"))
            return {"success": False, "results": results, "total": len(results)}
        results.append(_result_ok("quickflow", "telegram", username, data))
        return {"success": True, "results": results, "total": len(results)}

class FunStatModule(BaseSearchModule):
    # auto-disabled: непроверенный ключ
    ENABLED = False
    """FunStat API - поиск статистики"""
    
    def __init__(self):
        self.base_url = "https://api.funstat.cc"
        self.api_key = FUNSTAT_TOKEN_ALT
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("phone") or params.get("email") or params.get("username") or params.get("ip")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/search",
                    params={"token": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "funstat",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "funstat",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class GerhanoModule(BaseSearchModule):
    # auto-disabled: эндпоинт 404
    ENABLED = False
    """Gerhano API - универсальный поиск"""
    
    def __init__(self):
        self.base_url = "https://netspyapi.netlify.app"
        self.api_key = GERHANO_API_KEY
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        query = params.get("phone") or params.get("email") or params.get("username") or params.get("ip")
        if query:
            try:
                response = requests.get(
                    f"{self.base_url}/search",
                    params={"key": self.api_key, "query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "gerhano",
                        "field": "query",
                        "value": query,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "gerhano",
                    "field": "query",
                    "value": query,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}


class LocalSearchModule(BaseSearchModule):
    """LocalSearch — открытый узел GET /search?query=&type= (без авторизации)."""

    SUPPORTED_FIELDS = [
        "email", "domain", "phone", "number", "ip", "username", "nick",
        "name", "fio", "fullname", "inn", "snils", "passport", "vin",
        "car_number", "address",
    ]
    TIMEOUT = 15.0
    TYPE_MAP = {
        "email": "email",
        "domain": "domain",
        "phone": "phone",
        "number": "phone",
        "ip": "ip",
        "username": "username",
        "nick": "username",
        "name": "name",
        "fio": "name",
        "fullname": "name",
        "inn": "inn",
        "snils": "snils",
        "passport": "passport",
        "vin": "auto",
        "car_number": "auto",
        "address": "address",
    }

    def __init__(self):
        self.base_url = LOCALSEARCH_BASE_URL.rstrip("/") + "/search"

    def _query(self, search_type: str, query: str) -> Tuple[Optional[dict], Optional[str]]:
        response, err = self._get(self.base_url, params={"query": query, "type": search_type})
        if err and response is None:
            return None, err
        if response is None:
            return None, err or "no response"
        if response.status_code == 429:
            return None, "rate_limited"
        if response.status_code != 200:
            return None, f"HTTP {response.status_code}"
        try:
            data = response.json()
        except Exception:
            text = (response.text or "").strip()
            if not text:
                return None, "empty"
            return {"raw": text[:4000]}, None
        if not data:
            return None, "empty"
        if isinstance(data, dict) and data.get("error") and not data.get("results") and not data.get("data"):
            return None, str(data.get("error"))
        return data, None

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        seen = set()
        for field, search_type in self.TYPE_MAP.items():
            value = params.get(field)
            if not value:
                continue
            query = normalize_phone(value) if field in ("phone", "number") else str(value).strip()
            cache_key = (search_type, query)
            if not query or cache_key in seen:
                continue
            seen.add(cache_key)
            data, error = self._query(search_type, query)
            if data is not None:
                results.append(_result_ok("localsearch", field, value, data, method=search_type))
            elif error:
                logger.debug("LocalSearch %s/%s: %s", search_type, query, error)
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class NetSpyModule(BaseSearchModule):
    """NetSpy — POST /api/search, header X-API-Key, body {query, search_type}."""

    SUPPORTED_FIELDS = [
        "phone", "number", "email", "fio", "fullname", "name", "nick", "username",
        "telegram", "telegram_id", "vk", "vk_id", "card", "tiktok", "address", "github",
    ]
    TIMEOUT = 20.0
    FIELD_TYPE = {
        "phone": "phone",
        "number": "phone",
        "email": "email",
        "fio": "fio",
        "fullname": "fio",
        "name": "fio",
        "nick": "nick",
        "username": "nick",
        "telegram": "tg",
        "telegram_id": "tg",
        "vk": "vk",
        "vk_id": "vk",
        "card": "card",
        "tiktok": "tiktok",
        "address": "address",
        "github": "github",
    }

    def __init__(self):
        self.base_url = NETSPY_BASE_URL.rstrip("/") + "/api/search"
        self.keys = [k for k in (NETSPY_API_KEY, GERHANO_API_KEY) if k]

    def _prepare_query(self, field: str, value: str) -> Optional[str]:
        value = str(value).strip()
        if not value:
            return None
        if field in ("phone", "number"):
            return normalize_phone(value) or value
        if field in ("telegram", "telegram_id", "nick", "username"):
            return normalize_telegram_query(value).lstrip("@")
        if field in ("vk", "vk_id"):
            return extract_vk_id(value)
        if field == "tiktok":
            return value.lstrip("@").replace("https://www.tiktok.com/@", "").replace("https://tiktok.com/@", "")
        if field == "github":
            return value.replace("https://github.com/", "").replace("http://github.com/", "").strip("/")
        return value

    def _search_once(self, search_type: str, query: str) -> Tuple[Optional[dict], Optional[str]]:
        last_error = None
        for key in self.keys:
            response, err = self._post(
                self.base_url,
                json={"query": query, "search_type": search_type},
                headers={"X-API-Key": key, "Content-Type": "application/json"},
            )
            if err and response is None:
                last_error = err
                continue
            if response is None:
                last_error = err or "no response"
                continue
            if response.status_code in (401, 403):
                last_error = f"auth HTTP {response.status_code}"
                continue
            if response.status_code == 429:
                return None, "rate_limited"
            if response.status_code != 200:
                last_error = f"HTTP {response.status_code}"
                continue
            try:
                data = response.json()
            except Exception:
                last_error = "invalid json"
                continue
            if isinstance(data, dict) and data.get("error") and not data.get("results") and not data.get("data"):
                last_error = str(data.get("error"))
                continue
            if data:
                return data, None
            last_error = "empty"
        return None, last_error or "NetSpy unavailable"

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        seen = set()
        for field, search_type in self.FIELD_TYPE.items():
            value = params.get(field)
            if not value:
                continue
            query = self._prepare_query(field, value)
            cache_key = (search_type, query)
            if not query or cache_key in seen:
                continue
            seen.add(cache_key)
            data, error = self._search_once(search_type, query)
            if data is not None:
                results.append(_result_ok("netspy", field, value, data, method=search_type))
            elif error:
                logger.debug("NetSpy %s/%s: %s", search_type, query, error)
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


# ============================================================================
# МОДУЛИ ИЗ Chronosphere (vv.py) — отсутствовавшие ранее
# ============================================================================

class LeakLookupModule(BaseSearchModule):
    ENABLED = False  # сессия истекла (login page)
    """Leak-Lookup.com — поиск по phone/email через PHP-сессию"""

    SUPPORTED_FIELDS = ["phone", "number", "email"]

    def __init__(self, session_id: str = None):
        self.session_id = session_id or LEAK_LOOKUP_SESSION
        self.base_url = "https://leak-lookup.com"
        self.timeout = 30.0
        self._lock = threading.Lock()
        self.session = self._make_session(self.session_id)

    def _make_session(self, session_id: str) -> requests.Session:
        client = requests.Session()
        client.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.7",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        if session_id:
            client.cookies.set("PHPSESSID", session_id, domain="leak-lookup.com", path="/")
        return client

    def _clean_text(self, node) -> str:
        if node is None:
            return ""
        return " ".join(node.get_text(" ", strip=True).split())

    def _parse_table(self, table) -> dict:
        caption = table.find("caption")
        headers = [self._clean_text(cell) for cell in table.select("thead th")]
        rows = []
        for row in table.select("tbody tr") or table.select("tr"):
            cells = row.find_all(["th", "td"], recursive=False)
            if not cells:
                continue
            values = [self._clean_text(cell) for cell in cells]
            if headers and len(headers) == len(values):
                rows.append(dict(zip(headers, values)))
            else:
                rows.append(values)
        return {
            "title": self._clean_text(caption) if caption else "",
            "headers": headers,
            "rows": rows,
        }

    def _is_login_page(self, response: requests.Response) -> bool:
        path = response.url.lower().rstrip("/")
        if path.endswith("/login"):
            return True
        if BeautifulSoup is None:
            return "type=\"password\"" in response.text.lower()
        soup = BeautifulSoup(response.text, "html.parser")
        return bool(soup.select_one('form input[type="password"]'))

    def _hidden_form_fields(self, html: str) -> Dict[str, str]:
        if BeautifulSoup is None:
            return {}
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form", action=re.compile(r"(?:^|/)search/?$"))
        if form is None:
            return {}
        fields: Dict[str, str] = {}
        for element in form.select('input[type="hidden"][name]'):
            fields[str(element["name"])] = str(element.get("value", ""))
        return fields

    def _recent_search_count(self, html: str, query: str) -> Optional[int]:
        if BeautifulSoup is None:
            return None
        soup = BeautifulSoup(html, "html.parser")
        for item in soup.select(".recent-search"):
            if str(item.get("data-search-query", "")) != query:
                continue
            badge = item.select_one(".results-badge-count")
            if badge is None:
                continue
            digits = re.sub(r"[^0-9]", "", self._clean_text(badge))
            return int(digits) if digits else 0
        return None

    def _parse_results(self, html: str, final_url: str, query: str) -> Dict[str, Any]:
        if BeautifulSoup is None:
            return {"query": query, "url": final_url, "total_results": 0, "raw_preview": html[:2000]}
        soup = BeautifulSoup(html, "html.parser")
        tables = []
        for table in soup.select("table"):
            parsed = self._parse_table(table)
            if parsed["rows"]:
                tables.append(parsed)
        cards = []
        for card in soup.select(".card"):
            heading = card.select_one(".card-header, .card-title, h1, h2, h3, h4, h5")
            body = card.select_one(".card-body") or card
            text = self._clean_text(body)
            if text:
                cards.append({
                    "title": self._clean_text(heading) if heading else "",
                    "text": text,
                })
        flat_data: Dict[str, Any] = {"query": query, "url": final_url, "total_results": 0}
        for table in tables:
            for row in table["rows"]:
                if isinstance(row, dict):
                    for key, value in row.items():
                        if value and str(value).strip():
                            existing = flat_data.get(key)
                            if existing and existing != value:
                                flat_data[key] = f"{existing} · {value}"
                            else:
                                flat_data[key] = value
                elif isinstance(row, list) and len(row) >= 2:
                    flat_data[str(row[0])] = row[1] if len(row) == 2 else ", ".join(str(r) for r in row)
        for card in cards:
            if card["title"]:
                flat_data[card["title"]] = card["text"]
        flat_data["total_results"] = max(len(tables), len(cards), int(bool(tables or cards)))
        return flat_data

    def _search_query(self, query: str) -> Dict[str, Any]:
        with self._lock:
            try:
                form_response = self.session.get(f"{self.base_url}/search", timeout=self.timeout)
                form_response.raise_for_status()
                if self._is_login_page(form_response):
                    return {"success": False, "error": "Сессия Leak-Lookup истекла. Обновите LEAK_LOOKUP_SESSION."}

                payload = list(self._hidden_form_fields(form_response.text).items())
                payload.extend(("search-type[]", item) for item in ("1", "4"))
                payload.extend((("search-query", query), ("submit", "")))

                response = self.session.post(
                    f"{self.base_url}/search",
                    data=payload,
                    headers={
                        "Origin": self.base_url,
                        "Referer": f"{self.base_url}/search",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                response.raise_for_status()

                location = response.headers.get("Location", "")
                if location:
                    redirect_url = urllib.parse.urljoin(response.url, location)
                    response = self.session.get(
                        redirect_url,
                        headers={"Referer": f"{self.base_url}/search"},
                        timeout=self.timeout,
                    )
                    response.raise_for_status()

                if response.url.rstrip("/") == f"{self.base_url}/search":
                    count = self._recent_search_count(response.text, query)
                    if count == 0:
                        return {"success": True, "data": {"query": query, "total_results": 0, "message": "Результаты не найдены"}}
                    results_response = self.session.get(
                        f"{self.base_url}/search/results",
                        headers={"Referer": f"{self.base_url}/search"},
                        timeout=self.timeout,
                    )
                    results_response.raise_for_status()
                    if results_response.url.rstrip("/") == f"{self.base_url}/search/results":
                        response = results_response
                    elif count is not None:
                        return {"success": True, "data": {"query": query, "total_results": count, "message": "Результаты ещё обрабатываются"}}

                if self._is_login_page(response):
                    return {"success": False, "error": "Сессия Leak-Lookup истекла во время запроса"}

                flat = self._parse_results(response.text, response.url, query)
                return {"success": True, "data": flat}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        queries = []
        if params.get("phone") or params.get("number"):
            phone = params.get("phone") or params.get("number")
            queries.append(("phone", phone, normalize_phone(phone) or phone))
        if params.get("email"):
            queries.append(("email", params["email"], params["email"]))
        for field, original, query in queries:
            payload = self._search_query(str(query))
            if not payload.get("success"):
                results.append(_result_err("leak_lookup", field, original, payload.get("error") or "ошибка"))
                continue
            data = payload.get("data") or {}
            if data.get("total_results", 0) == 0 or (data.get("message") and len(data) <= 3):
                continue
            results.append(_result_ok("leak_lookup", field, original, data))
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class ZvoniliModule(BaseSearchModule):
    """Zvonili.com — отзывы и рейтинг по телефону"""

    SUPPORTED_FIELDS = ["phone", "number"]
    BASE_URL = "https://zvonili.com/phone/{}"
    HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    REVIEW_CATEGORIES = {
        "Мошенники", "Коллекторы", "Колл-центры", "Спам", "Реклама",
        "Банк", "Опрос", "Другое", "Неадекваты",
    }

    def _parse_general_info(self, text: str) -> Dict[str, Any]:
        info = {"rating": "", "views": 0, "total_reviews": 0}
        rating_match = re.search(r"Рейтинг номера:\s*([\d.]+)/5", text)
        if rating_match:
            info["rating"] = rating_match.group(1)
        views_match = re.search(r"Просмотров:\s*(\d+)", text)
        if views_match:
            info["views"] = int(views_match.group(1))
        reviews_match = re.search(r"Отзывов:\s*(\d+)", text)
        if reviews_match:
            info["total_reviews"] = int(reviews_match.group(1))
        return info

    def _parse_reviews(self, full_text: str) -> List[Dict[str, Any]]:
        reviews = []
        reviews_start = full_text.find("Отзывы по номеру")
        if reviews_start == -1:
            return reviews
        reviews_text = full_text[reviews_start:]
        new_reviews_pos = reviews_text.find("Новые отзывы")
        if new_reviews_pos != -1:
            reviews_text = reviews_text[:new_reviews_pos]
        date_pattern = re.compile(r"(\d{2}\.\d{2}\.\d{4})\s+(\d{2}:\d{2})")
        matches = list(date_pattern.finditer(reviews_text))
        for i, match in enumerate(matches):
            date = match.group(1)
            time_str = match.group(2)
            start_pos = match.start()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(reviews_text)
            before_date = reviews_text[max(0, start_pos - 100):start_pos].strip()
            author_parts = before_date.split("\n")
            author = author_parts[-1].strip() if author_parts else "Аноним"
            author = re.sub(r"^\d+\s*", "", author).strip() or "Аноним"
            after_date = re.sub(r"^\s*\.\.\.\s*", "", reviews_text[match.end():end_pos].strip())
            review_text = ""
            category = ""
            for line in after_date.split("\n"):
                line = line.strip()
                if not line:
                    continue
                if line in self.REVIEW_CATEGORIES:
                    category = line
                    continue
                if line and not line.startswith("+7") and not line.startswith("8"):
                    review_text += line + " "
            review_text = review_text.strip()
            if review_text:
                reviews.append({
                    "author": author,
                    "date": date,
                    "time": time_str,
                    "text": review_text,
                    "category": category,
                })
        return reviews

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        phone = params.get("phone") or params.get("number")
        if not phone:
            return {"success": False, "results": [], "total": 0}
        try:
            formatted = normalize_phone_e164(phone)
            if len(re.sub(r"\D", "", formatted)) < 10:
                return {"success": False, "results": [_result_err("zvonili", "phone", phone, "Номер слишком короткий")], "total": 1}
            url = self.BASE_URL.format(formatted)
            response = requests.get(url, headers=self.HEADERS, timeout=20)
            if response.status_code == 404:
                return {"success": False, "results": [], "total": 0}
            response.raise_for_status()
            if BeautifulSoup is not None:
                soup = BeautifulSoup(response.text, "html.parser")
                full_text = soup.get_text("\n", strip=True)
                plain = soup.get_text(" ", strip=True)
            else:
                full_text = response.text
                plain = re.sub(r"<[^>]+>", " ", response.text)
            info = self._parse_general_info(plain)
            reviews = self._parse_reviews(full_text)
            tags = sorted({r["category"] for r in reviews if r.get("category")})
            data = {
                "phone": formatted,
                "url": url,
                "status": "found" if reviews else "no_reviews",
                "rating": info.get("rating"),
                "views": info.get("views"),
                "total_reviews": info.get("total_reviews") or len(reviews),
                "tags": tags,
                "reviews": reviews[:30],
            }
            if data["status"] == "no_reviews" and not data.get("rating") and not data.get("views"):
                return {"success": False, "results": [], "total": 0}
            results.append(_result_ok("zvonili", "phone", phone, data))
        except Exception as exc:
            results.append(_result_err("zvonili", "phone", phone, exc))
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class SeonModule(BaseSearchModule):
    """SEON phone-api — risk score / CNAM / carrier / registrations"""

    SUPPORTED_FIELDS = ["phone", "number"]

    def __init__(self, api_key: str = None):
        self.api_key = api_key or SEON_API_KEY
        self.base_url = "https://api.seon.io/SeonRestService/phone-api/v2/"
        self.headers = {"X-API-KEY": self.api_key, "Content-Type": "application/json"}

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        phone = params.get("phone") or params.get("number")
        if not phone:
            return {"success": False, "results": [], "total": 0}
        if not self.api_key:
            return {"success": False, "results": [_result_err("seon", "phone", phone, "SEON API key не задан")], "total": 1}
        clean_phone = normalize_phone(phone)
        payload = {
            "phone": clean_phone,
            "config": {
                "timeout": 5000,
                "priority_timeout": 5000,
                "priority_sites": "",
                "include": "cnam_lookup",
                "flags_timeframe_days": 365,
            },
        }
        try:
            response = requests.post(self.base_url, json=payload, headers=self.headers, timeout=30)
            if response.status_code != 200:
                results.append(_result_err("seon", "phone", phone, f"HTTP {response.status_code}: {response.text[:300]}"))
                return {"success": False, "results": results, "total": len(results)}
            raw = response.json()
            if not raw.get("success"):
                results.append(_result_err("seon", "phone", phone, raw.get("error") or "SEON: нет данных"))
                return {"success": False, "results": results, "total": len(results)}

            payload_data = raw.get("data") or {}
            flat: Dict[str, Any] = {"phone": clean_phone}
            risk = payload_data.get("risk_scores") or {}
            for key, value in risk.items():
                flat[f"risk_{key}"] = value
            account = payload_data.get("account_aggregates") or {}
            if account.get("total_registration") is not None:
                flat["total_registrations"] = account.get("total_registration")
            personal = account.get("personal") or {}
            if personal.get("total_registration") is not None:
                flat["personal_registrations"] = personal.get("total_registration")
            business = account.get("business") or {}
            if business:
                registered = [site for site, meta in business.items() if isinstance(meta, dict) and meta.get("registered")]
                if registered:
                    flat["business_sites"] = ", ".join(registered[:40])
            cnam = payload_data.get("cnam_details") or {}
            if cnam.get("name"):
                flat["cnam_name"] = cnam.get("name")
                flat["cnam_reliability"] = cnam.get("reliability")
            carrier = payload_data.get("provider_carrier_details") or {}
            if carrier:
                flat["carrier"] = carrier.get("carrier")
                flat["country"] = carrier.get("country")
                flat["line_type"] = carrier.get("type")
                flat["phone_valid"] = carrier.get("phone_is_valid")
            flat = {k: v for k, v in flat.items() if v not in (None, "", [], {})}
            if flat:
                results.append(_result_ok("seon", "phone", phone, flat))
        except Exception as exc:
            results.append(_result_err("seon", "phone", phone, exc))
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class WhatsAppModule(BaseSearchModule):
    """WhatsApp check via whatsapp.checkleaked.cc (опционально Playwright для login)"""

    SUPPORTED_FIELDS = ["phone", "number"]
    TIMEOUT = 12.0
    BASE = "https://whatsapp.checkleaked.cc"

    def can_handle(self, params: Dict[str, Any]) -> bool:
        if not super().can_handle(params):
            return False
        # без сохранённой сессии и без WHATSAPP_AUTO_LOGIN — пропускаем
        auth_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "whatsapp_auth.json")
        if os.path.exists(auth_file) or os.getenv("WHATSAPP_AUTO_LOGIN", "0") == "1":
            return True
        return False

    def __init__(self, email: str = None, password: str = None):
        self.email = email or WHATSAPP_EMAIL
        self.password = password or WHATSAPP_PASSWORD
        self._lock = threading.Lock()
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        os.makedirs(data_dir, exist_ok=True)
        self.auth_file = os.path.join(data_dir, "whatsapp_auth.json")

    def _playwright_available(self) -> bool:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            return True
        except Exception:
            return False

    def auto_login(self) -> Optional[dict]:
        with self._lock:
            return self._auto_login_locked()

    def _auto_login_locked(self) -> Optional[dict]:
        if not self._playwright_available():
            logger.warning("Playwright не установлен — WhatsApp auth недоступен")
            return None
        if not self.email or not self.password:
            return None
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                page.goto(f"{self.BASE}/ru/79828731165", timeout=60000)
                page.get_by_role("button", name="Пользователь").click()
                page.locator("#v-menu-v-11").get_by_role("link", name="Войти / Регистрация").click()
                page.get_by_role("textbox", name="Email").fill(self.email)
                page.get_by_role("textbox", name="Пароль").fill(self.password)
                page.get_by_role("button", name="Войти", exact=True).click()
                page.wait_for_selector("button:has-text('Войти')", state="hidden", timeout=15000)
                storage = context.storage_state(path=self.auth_file)
                browser.close()
                return storage
        except Exception as exc:
            logger.warning(f"WhatsApp auto_login error: {exc}")
            return None

    def get_auth(self) -> Optional[dict]:
        if os.path.exists(self.auth_file):
            try:
                with open(self.auth_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        # Playwright login намеренно НЕ вызываем в hot-path поиска (60s+).
        # Положите data/whatsapp_auth.json заранее или задайте WHATSAPP_AUTO_LOGIN=1.
        if os.getenv("WHATSAPP_AUTO_LOGIN", "0") == "1":
            return self.auto_login()
        return None

    def _headers_and_token(self) -> Tuple[Optional[dict], Optional[str]]:
        auth = self.get_auth()
        if not auth:
            return None, None
        token = None
        cookie_strings = []
        for cookie in auth.get("cookies", []):
            if cookie.get("name") == "firebaseAuthToken":
                token = cookie.get("value")
            cookie_strings.append(f"{cookie['name']}={cookie['value']}")
        if not token:
            auth = self.auto_login()
            if not auth:
                return None, None
            cookie_strings = []
            for cookie in auth.get("cookies", []):
                if cookie.get("name") == "firebaseAuthToken":
                    token = cookie.get("value")
                cookie_strings.append(f"{cookie['name']}={cookie['value']}")
        if not token:
            return None, None
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ru-RU,ru;q=0.9",
            "Authorization": f"Bearer {token}",
            "Cookie": "; ".join(cookie_strings),
        }
        return headers, token

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        phone = params.get("phone") or params.get("number")
        if not phone:
            return {"success": False, "results": [], "total": 0}
        phone_clean = normalize_phone(phone)
        if len(phone_clean) < 10:
            return {"success": False, "results": [_result_err("whatsapp", "phone", phone, "Неверный формат номера")], "total": 1}

        headers, token = self._headers_and_token()
        if not headers or not token:
            return {"success": False, "results": [_result_err("whatsapp", "phone", phone, "Не удалось получить WhatsApp-сессию")], "total": 1}

        headers["Referer"] = f"{self.BASE}/ru/{phone_clean}"
        url = (
            f"{self.BASE}/api/authenticated/phone/{phone_clean}"
            "?googleMaps=true&websiteCheck=true&businessVerification=true"
        )
        try:
            response = requests.get(url, headers=headers, timeout=12)
            if response.status_code == 401:
                self.auto_login()
                headers, token = self._headers_and_token()
                if not headers:
                    return {"success": False, "results": [_result_err("whatsapp", "phone", phone, "Сессия WhatsApp истекла")], "total": 1}
                headers["Referer"] = f"{self.BASE}/ru/{phone_clean}"
                response = requests.get(url, headers=headers, timeout=12)
            if response.status_code != 200:
                results.append(_result_err("whatsapp", "phone", phone, f"HTTP {response.status_code}"))
                return {"success": False, "results": results, "total": len(results)}
            data = response.json()
            is_wa = data.get("isWAContact", False)
            exists = data.get("exists", False)
            if not is_wa or not exists:
                return {"success": False, "results": [], "total": 0}
            phone_val = data.get("phone", phone_clean)
            flat = {
                "status": "found",
                "phone": phone_val,
                "wa_link": f"https://wa.me/+{phone_val}",
                "is_business": data.get("isBusiness", False),
                "is_verified": data.get("isVerified", False),
                "is_banned": (data.get("checkMetadata") or {}).get("isBanned", False),
                "exists": True,
            }
            results.append(_result_ok("whatsapp", "phone", phone, flat))
        except requests.exceptions.Timeout:
            results.append(_result_err("whatsapp", "phone", phone, "Сервер WhatsApp недоступен (таймаут)"))
        except Exception as exc:
            results.append(_result_err("whatsapp", "phone", phone, exc))
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}


class PansrcModule(BaseSearchModule):
    """Pansrc — Telegram OSINT (id / @username)"""

    SUPPORTED_FIELDS = ["telegram", "telegram_id", "username", "nick"]
    TIMEOUT = 6.0

    def __init__(self, token: str = None):
        self.token = token or PANSRC_TOKEN
        self.base_url = PANSRC_URL
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "GloomApi/2.1"})

    def _search_raw(self, query: str) -> Dict[str, Any]:
        if not query:
            return {"success": False, "error": "Пустой запрос"}
        try:
            with self._lock:
                response = self.session.get(
                    self.base_url,
                    params={"q": query.strip(), "token": self.token},
                    timeout=30,
                )
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("data"):
                    return {"success": True, "data": data["data"]}
                return {"success": False, "error": data.get("error", "Данные не найдены")}
            errors = {
                401: "Требуется токен",
                141: "Токен недействителен",
                333: "Токен просрочен",
                400: "Неверный формат запроса",
                404: "Пользователь не найден",
            }
            return {"success": False, "error": errors.get(response.status_code, f"HTTP {response.status_code}")}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _flatten(self, data: Dict[str, Any]) -> Dict[str, Any]:
        flat = {}
        for key in ["id", "phone", "registration", "fio", "email", "address", "birth_date"]:
            if data.get(key):
                flat[key] = data[key]
        if data.get("names"):
            names = [f"{n.get('name', '')} ({n.get('date', '')})" for n in data["names"] if n.get("name")]
            if names:
                flat["names"] = ", ".join(names)
        if data.get("usernames"):
            usernames = [f"{u.get('username', '')} ({u.get('date', '')})" for u in data["usernames"] if u.get("username")]
            if usernames:
                flat["usernames"] = ", ".join(usernames)
        if data.get("sent_gifts"):
            flat["sent_gifts"] = ", ".join([str(g) for g in data["sent_gifts"][:10]])
        if data.get("received_gifts"):
            flat["received_gifts"] = ", ".join([str(g) for g in data["received_gifts"][:10]])
        if data.get("groups"):
            groups = [f"{g.get('group', '')} ({g.get('date', '')})" for g in data["groups"] if g.get("group")]
            if groups:
                flat["groups"] = ", ".join(groups[:10])
        return flat

    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        candidates = []
        for field in ("telegram", "telegram_id", "username", "nick"):
            value = params.get(field)
            if not value:
                continue
            query = normalize_telegram_query(str(value))
            if len(query) < 3 and not query.isdigit():
                continue
            candidates.append((field, value, query))
        seen = set()
        for field, original, query in candidates:
            if query in seen:
                continue
            seen.add(query)
            payload = self._search_raw(query)
            if not payload.get("success"):
                results.append(_result_err("pansrc", field, original, payload.get("error") or "ошибка"))
                continue
            flat = self._flatten(payload.get("data") or {})
            if flat:
                results.append(_result_ok("pansrc", field, original, flat))
        return {"success": any(r.get("found") for r in results), "results": results, "total": len(results)}



# ============================================================================
# АУТЕНТИФИКАЦИЯ
# ============================================================================

security = HTTPBearer()

def _secure_eq(a: Optional[str], b: Optional[str]) -> bool:
    """Constant-time сравнение строк разной длины."""
    if a is None or b is None:
        return False
    a_b, b_b = str(a).encode(), str(b).encode()
    if len(a_b) != len(b_b):
        # всё равно делаем фиктивное сравнение, чтобы не падать и не утекать по времени слишком явно
        hmac.compare_digest(a_b, a_b)
        return False
    return hmac.compare_digest(a_b, b_b)


def get_client_ip(request: Optional[Request]) -> str:
    """IP клиента. X-Forwarded-For учитывается только при TRUST_PROXY=1."""
    if request is None:
        return ""
    if TRUST_PROXY:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()[:64]
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()[:64]
    if request.client:
        return (request.client.host or "")[:64]
    return ""


_GEO_CACHE: Dict[str, Tuple[float, Dict[str, str]]] = {}
_GEO_CACHE_LOCK = threading.Lock()
_GEO_CACHE_TTL = 24 * 3600
_GEO_CACHE_FAIL_TTL = 10 * 60
_GEO_CACHE_MAX = 2048


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_link_local
            or addr.is_unspecified
        )
    except ValueError:
        return False


def _geo_cache_get(ip: str) -> Optional[Dict[str, str]]:
    now = time()
    with _GEO_CACHE_LOCK:
        hit = _GEO_CACHE.get(ip)
        if not hit:
            return None
        ts, data = hit
        ttl = _GEO_CACHE_TTL if data.get("city") or data.get("country") else _GEO_CACHE_FAIL_TTL
        if now - ts > ttl:
            _GEO_CACHE.pop(ip, None)
            return None
        return dict(data)


def _geo_cache_set(ip: str, data: Dict[str, str]) -> None:
    with _GEO_CACHE_LOCK:
        if len(_GEO_CACHE) >= _GEO_CACHE_MAX:
            oldest = sorted(_GEO_CACHE.items(), key=lambda kv: kv[1][0])[: max(1, _GEO_CACHE_MAX // 10)]
            for key, _ in oldest:
                _GEO_CACHE.pop(key, None)
        _GEO_CACHE[ip] = (time(), dict(data))


def format_place(city: str = "", region: str = "", country: str = "") -> str:
    parts: List[str] = []
    for item in (city, region, country):
        val = (item or "").strip()
        if val and not any(val.lower() == p.lower() for p in parts):
            parts.append(val)
    return ", ".join(parts)


def format_geo_label(ip: str, city: str = "", region: str = "", country: str = "") -> str:
    place = format_place(city, region, country)
    ip = (ip or "").strip()
    if place and ip:
        return f"{place} ({ip})"
    return place or ip or "неизвестно"


def _geo_http_json(url: str, params: Optional[dict] = None) -> Optional[dict]:
    try:
        response = HTTP_SESSION.get(url, params=params, timeout=2.5)
        if response.status_code != 200:
            return None
        data = response.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _pick_geo_fields(data: dict, city_keys: Tuple[str, ...], region_keys: Tuple[str, ...], country_keys: Tuple[str, ...]) -> Dict[str, str]:
    def first(keys: Tuple[str, ...]) -> str:
        for key in keys:
            val = data.get(key)
            if val not in (None, "", [], {}):
                return str(val).strip()[:128]
        return ""
    return {
        "city": first(city_keys),
        "region": first(region_keys),
        "country": first(country_keys),
    }


def lookup_client_geo(ip: str) -> Dict[str, str]:
    """Город/регион/страна клиента по IP через цепочку geo-API."""
    ip = (ip or "").strip()[:64]
    empty = {"ip": ip, "city": "", "region": "", "country": "", "label": "IP неизвестен"}
    if not ip:
        return empty
    if not _is_public_ip(ip):
        return {
            "ip": ip,
            "city": "локальная сеть",
            "region": "",
            "country": "",
            "label": format_geo_label(ip, "локальная сеть"),
        }
    cached = _geo_cache_get(ip)
    if cached:
        return cached

    sources = (
        lambda: _pick_geo_fields(
            _geo_http_json(f"https://ipinfo.io/{ip}/json", {"token": IPINFO_API_KEY}) or {},
            ("city",), ("region",), ("country", "country_name"),
        ),
        lambda: _pick_geo_fields(
            _geo_http_json("https://api.ipgeolocation.io/ipgeo", {"apiKey": IPGEOLOCATION_API_KEY, "ip": ip}) or {},
            ("city",), ("state_prov", "district"), ("country_name", "country"),
        ),
        lambda: _pick_geo_fields(
            _geo_http_json(f"http://api.ipstack.com/{ip}", {"access_key": IPSTACK_API_KEY}) or {},
            ("city",), ("region_name",), ("country_name", "country_code"),
        ),
        lambda: _pick_geo_fields(
            _geo_http_json(f"http://ip-api.com/json/{ip}", {"lang": "ru", "fields": "status,country,regionName,city,query"}) or {},
            ("city",), ("regionName", "region"), ("country",),
        ),
    )
    result = {"ip": ip, "city": "", "region": "", "country": "", "label": ip}
    for fetch in sources:
        try:
            parsed = fetch()
        except Exception:
            continue
        if not parsed:
            continue
        if parsed.get("city") or parsed.get("country"):
            result["city"] = parsed.get("city") or ""
            result["region"] = parsed.get("region") or ""
            result["country"] = parsed.get("country") or ""
            result["label"] = format_geo_label(ip, result["city"], result["region"], result["country"])
            break
    if not result.get("city") and not result.get("country"):
        result["label"] = f"{ip} (город не определён)"
    _geo_cache_set(ip, result)
    return result


def format_log_place(log: Optional["SearchLog"]) -> str:
    if log is None:
        return ""
    return format_place(
        getattr(log, "client_city", None) or "",
        getattr(log, "client_region", None) or "",
        getattr(log, "client_country", None) or "",
    )


def verify_admin_ip(request: Request) -> bool:
    """Проверка IP адреса для админских операций"""
    if not ADMIN_IP_WHITELIST:
        return True
    client_ip = get_client_ip(request)
    return client_ip in ADMIN_IP_WHITELIST


def hash_key(key: str) -> str:
    """Хеширование ключа для безопасного хранения"""
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()


def generate_api_key_value() -> str:
    """Клиентский ключ GloomApi: plut_ + urlsafe token."""
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


def _dt_to_iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    try:
        if getattr(value, "tzinfo", None):
            return value.isoformat()
        return value.isoformat() + "Z"
    except Exception:
        return str(value)


def _parse_iso_dt(value: Any) -> Optional[datetime]:
    if value in (None, "", 0, "null"):
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    text = str(value).strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed.replace(tzinfo=None)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%d.%m.%Y %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def collect_usage_report(db: Session, logs_limit: int = 10000) -> Dict[str, Any]:
    """Сводка использования всех ключей: IP, город, история запросов."""
    keys = db.query(APIKey).order_by(APIKey.id.asc()).all()
    logs = (
        db.query(SearchLog)
        .order_by(SearchLog.created_at.desc())
        .limit(max(1, int(logs_limit)))
        .all()
    )
    by_key: Dict[int, List[SearchLog]] = defaultdict(list)
    for log in logs:
        by_key[log.api_key_id].append(log)

    key_blocks = []
    total_logged = 0
    for key in keys:
        key_logs = by_key.get(key.id) or []
        total_logged += len(key_logs)
        last = key_logs[0] if key_logs else None
        ips: List[str] = []
        places: List[str] = []
        seen_ip = set()
        seen_place = set()
        recent = []
        for log in key_logs:
            ip = (getattr(log, "client_ip", None) or "").strip()
            place = format_log_place(log)
            if ip and ip not in seen_ip:
                seen_ip.add(ip)
                ips.append(ip)
            if place and place not in seen_place:
                seen_place.add(place)
                places.append(place)
            try:
                params = json.loads(log.search_params or "{}")
            except (TypeError, json.JSONDecodeError):
                params = {}
            recent.append({
                "at": _dt_to_iso(log.created_at),
                "ip": ip or None,
                "city": getattr(log, "client_city", None),
                "region": getattr(log, "client_region", None),
                "country": getattr(log, "client_country", None),
                "place": place or None,
                "results": log.results_count,
                "params": list(params.keys()) if isinstance(params, dict) else [],
            })
        key_blocks.append({
            "id": key.id,
            "name": key.name,
            "key": key.key,
            "status": key.status,
            "searches_used": key.searches_used or 0,
            "search_limit": key.search_limit,
            "last_used_at": _dt_to_iso(key.last_used_at),
            "last_ip": getattr(last, "client_ip", None) if last else None,
            "last_place": format_log_place(last) if last else None,
            "unique_ips": ips,
            "unique_places": places,
            "recent": recent,
        })
    return {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "total_keys": len(keys),
        "active_keys": sum(1 for k in keys if k.status == "active"),
        "total_searches": int(sum(k.searches_used or 0 for k in keys)),
        "logged_events": total_logged,
        "keys": key_blocks,
    }


def render_usage_report_text(report: Dict[str, Any]) -> str:
    lines = [
        "GloomApi — статистика использования ключей",
        f"Экспорт: {report.get('exported_at')}",
        f"Ключей: {report.get('total_keys')} (активных: {report.get('active_keys')})",
        f"Поисков: {report.get('total_searches')}",
        f"Записей в логах: {report.get('logged_events')}",
        "",
    ]
    for block in report.get("keys") or []:
        limit = block.get("search_limit")
        used = block.get("searches_used") or 0
        quota = f"{used}/{limit}" if limit else f"{used}/∞"
        lines.append(f"=== {block.get('name')} (id={block.get('id')}) ===")
        lines.append(f"Ключ: {block.get('key')}")
        lines.append(f"Статус: {block.get('status')} | Использовано: {quota}")
        last_ip = block.get("last_ip") or "нет данных"
        last_place = block.get("last_place") or "город не определён"
        lines.append(f"Последний IP: {last_ip}")
        lines.append(f"Последний город: {last_place}")
        if block.get("unique_ips"):
            lines.append("IP: " + ", ".join(block["unique_ips"]))
        if block.get("unique_places"):
            lines.append("Города: " + ", ".join(block["unique_places"]))
        recent = block.get("recent") or []
        if not recent:
            lines.append("Запросов пока нет.")
        else:
            for row in recent:
                at = row.get("at") or "?"
                ip = row.get("ip") or "IP неизвестен"
                place = row.get("place") or "город не определён"
                params = ", ".join(row.get("params") or []) or "-"
                lines.append(f"  [{at}] IP={ip} | Город={place} | params={params} | results={row.get('results')}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def serialize_api_key(key: APIKey) -> Dict[str, Any]:
    return {
        "id": key.id,
        "key": key.key,
        "name": key.name,
        "created_at": _dt_to_iso(key.created_at),
        "expires_at": _dt_to_iso(key.expires_at),
        "search_limit": key.search_limit,
        "searches_used": key.searches_used or 0,
        "status": key.status or "active",
        "created_by": key.created_by,
        "last_used_at": _dt_to_iso(key.last_used_at),
        "ip_restrictions": key.ip_restrictions,
    }


def build_keys_backup(keys: List[APIKey]) -> Dict[str, Any]:
    return {
        "version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "count": len(keys),
        "keys": [serialize_api_key(k) for k in keys],
    }


_KEY_LINE_RE = re.compile(
    rf"^(?:{re.escape(API_KEY_PREFIX)}|{re.escape(LEGACY_API_KEY_PREFIX)})[A-Za-z0-9_-]{{16,120}}$"
)


def parse_keys_backup(raw: bytes) -> List[Dict[str, Any]]:
    """Разбор JSON-бэкапа или текстового списка ключей."""
    if not raw:
        raise ValueError("Пустой файл")
    if len(raw) > KEYS_BACKUP_MAX_BYTES:
        raise ValueError("Файл слишком большой (лимит 512 КБ)")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Файл должен быть в UTF-8") from exc
    text = text.strip()
    if not text:
        raise ValueError("Пустой файл")

    items: List[Dict[str, Any]] = []
    if text[0] in "{[":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Некорректный JSON: {exc.msg}") from exc
        if isinstance(data, dict):
            raw_items = data.get("keys")
            if raw_items is None and data.get("key"):
                raw_items = [data]
            if raw_items is None:
                raise ValueError("В JSON нет массива keys")
        elif isinstance(data, list):
            raw_items = data
        else:
            raise ValueError("Неизвестный JSON-формат")
        if not isinstance(raw_items, list):
            raise ValueError("keys должен быть массивом")
        for idx, row in enumerate(raw_items, start=1):
            if isinstance(row, str):
                row = {"key": row.strip()}
            if not isinstance(row, dict):
                raise ValueError(f"Элемент #{idx} не объект")
            key_value = str(row.get("key") or "").strip()
            if not key_value:
                raise ValueError(f"Элемент #{idx}: нет ключа")
            items.append({
                "key": key_value,
                "name": str(row.get("name") or f"imported-{idx}")[:255],
                "expires_at": _parse_iso_dt(row.get("expires_at")),
                "search_limit": row.get("search_limit"),
                "searches_used": row.get("searches_used") or 0,
                "status": str(row.get("status") or "active")[:20],
                "created_by": row.get("created_by"),
                "ip_restrictions": row.get("ip_restrictions"),
                "created_at": _parse_iso_dt(row.get("created_at")),
                "last_used_at": _parse_iso_dt(row.get("last_used_at")),
            })
    else:
        for idx, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = None
            key_value = line
            if "|" in line:
                left, right = line.split("|", 1)
                left, right = left.strip(), right.strip()
                if _KEY_LINE_RE.match(left) and not _KEY_LINE_RE.match(right):
                    key_value, name = left, right
                else:
                    name, key_value = left, right
            if not _KEY_LINE_RE.match(key_value):
                raise ValueError(f"Строка {idx}: не похоже на ключ plut_/sk_")
            items.append({
                "key": key_value,
                "name": (name or f"imported-{idx}")[:255],
                "expires_at": None,
                "search_limit": None,
                "searches_used": 0,
                "status": "active",
                "created_by": None,
                "ip_restrictions": None,
                "created_at": None,
                "last_used_at": None,
            })

    if not items:
        raise ValueError("В файле нет ключей")
    if len(items) > KEYS_BACKUP_MAX_ITEMS:
        raise ValueError(f"Слишком много ключей (лимит {KEYS_BACKUP_MAX_ITEMS})")
    return items


def import_api_keys(db: Session, items: List[Dict[str, Any]], created_by: Optional[int] = None) -> Dict[str, int]:
    """Импорт ключей без дублей. Существующие (по key/hash) пропускаются."""
    added = skipped = failed = 0
    for item in items:
        key_value = str(item.get("key") or "").strip()
        if not key_value or len(key_value) < 16 or len(key_value) > 128:
            failed += 1
            continue
        digest = hash_key(key_value)
        exists = db.query(APIKey).filter(
            or_(APIKey.key == key_value, APIKey.key_hash == digest)
        ).first()
        if exists:
            skipped += 1
            continue
        ip_restrictions = item.get("ip_restrictions")
        if isinstance(ip_restrictions, (list, dict)):
            ip_restrictions = json.dumps(ip_restrictions, ensure_ascii=False)
        elif ip_restrictions is not None:
            ip_restrictions = str(ip_restrictions)
        try:
            used = int(item.get("searches_used") or 0)
        except (TypeError, ValueError):
            used = 0
        limit = item.get("search_limit")
        try:
            limit = int(limit) if limit not in (None, "", "null") else None
        except (TypeError, ValueError):
            limit = None
        status = str(item.get("status") or "active").lower()
        if status not in ("active", "inactive"):
            status = "active"
        created_by_val = item.get("created_by")
        try:
            created_by_val = int(created_by_val) if created_by_val not in (None, "") else created_by
        except (TypeError, ValueError):
            created_by_val = created_by
        try:
            api_key = APIKey(
                key=key_value,
                key_hash=digest,
                name=str(item.get("name") or "imported")[:255],
                expires_at=item.get("expires_at"),
                search_limit=limit,
                searches_used=max(0, used),
                status=status,
                created_by=created_by_val,
                created_at=item.get("created_at") or datetime.utcnow(),
                last_used_at=item.get("last_used_at"),
                ip_restrictions=ip_restrictions,
            )
            db.add(api_key)
            db.commit()
            added += 1
        except IntegrityError:
            db.rollback()
            skipped += 1
        except Exception as exc:
            logger.warning("import key failed: %s", exc)
            db.rollback()
            failed += 1
    return {"added": added, "skipped": skipped, "failed": failed}


def verify_ip_restrictions(api_key: APIKey, client_ip: str) -> bool:
    """Проверка IP ограничений ключа"""
    if not api_key.ip_restrictions:
        return True
    try:
        allowed_ips = json.loads(api_key.ip_restrictions)
        if not isinstance(allowed_ips, list):
            return False
        return client_ip in allowed_ips or "*" in allowed_ips
    except (TypeError, ValueError, json.JSONDecodeError):
        return False


def reserve_search_slot(db: Session, api_key_id: int) -> Optional[APIKey]:
    """Атомарно резервирует слот поиска (защита от гонок по search_limit)."""
    now = datetime.utcnow()
    stmt = (
        update(APIKey)
        .where(APIKey.id == api_key_id)
        .where(APIKey.status == "active")
        .where((APIKey.expires_at.is_(None)) | (APIKey.expires_at > now))
        .where(
            (APIKey.search_limit.is_(None))
            | (APIKey.searches_used < APIKey.search_limit)
        )
        .values(
            searches_used=APIKey.searches_used + 1,
            last_used_at=now,
        )
    )
    result = db.execute(stmt)
    if result.rowcount != 1:
        db.rollback()
        return None
    db.commit()
    return db.query(APIKey).filter(APIKey.id == api_key_id).first()


def refund_search_slot(db: Session, api_key_id: int) -> None:
    """Возврат слота при критическом сбое до получения результата."""
    try:
        db.execute(
            update(APIKey)
            .where(APIKey.id == api_key_id)
            .where(APIKey.searches_used > 0)
            .values(searches_used=APIKey.searches_used - 1)
        )
        db.commit()
    except Exception as exc:
        logger.warning("refund_search_slot failed: %s", exc)
        db.rollback()


def sanitize_params_for_log(params: Dict[str, Any]) -> Dict[str, Any]:
    """Маскирует чувствительные поля перед записью в SearchLog."""
    out = {}
    for k, v in params.items():
        if k in ("password", "card", "passport", "snils"):
            s = str(v)
            out[k] = ("*" * min(8, len(s))) if s else None
        else:
            out[k] = v
    return out


def safe_output_path(filename: Optional[str]) -> Optional[str]:
    """Разрешает запись только внутри OUTPUT_DIR (anti path-traversal)."""
    if not filename:
        return None
    raw = str(filename).strip()
    # любые попытки обхода директорий — отказ
    if ".." in raw or "/" in raw or "\\" in raw or raw.startswith("."):
        return None
    name = os.path.basename(raw)
    if not name or name in (".", ".."):
        return None
    if not re.match(r"^[A-Za-z0-9._-]{1,200}\.json$", name):
        if re.match(r"^[A-Za-z0-9._-]{1,200}$", name):
            name = name + ".json"
        else:
            return None
    full = os.path.abspath(os.path.join(OUTPUT_DIR, name))
    out_root = os.path.abspath(OUTPUT_DIR)
    if not full.startswith(out_root + os.sep):
        return None
    return full


def get_master_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Аутентификация для админских операций через MASTER_API_KEY"""
    if not MASTER_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="MASTER_API_KEY не настроен в переменных окружения",
        )

    token = credentials.credentials
    if not _secure_eq(token, MASTER_API_KEY):
        raise HTTPException(status_code=401, detail="Неверный мастер-ключ")

    if not verify_admin_ip(request):
        raise HTTPException(status_code=403, detail="IP адрес не в белом списке")

    return True


def get_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials or ""
    if len(token) < 16 or len(token) > 256:
        raise HTTPException(status_code=401, detail="Неверный ключ")

    key_hash = hash_key(token)
    api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
    if not api_key or not _secure_eq(api_key.key, token):
        raise HTTPException(status_code=401, detail="Неверный ключ")

    if not api_key.is_valid:
        raise HTTPException(status_code=401, detail="Ключ недействителен или истёк")

    client_ip = get_client_ip(request)
    if not verify_ip_restrictions(api_key, client_ip):
        raise HTTPException(status_code=403, detail="IP адрес не разрешён")

    # last_used обновляется атомарно в reserve_search_slot при /search
    return api_key

# ============================================================================
# FASTAPI
# ============================================================================

# Глобальный экземпляр бота
bot_manager = None
bot_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan: DB init, bot start, graceful shutdown."""
    global bot_manager, bot_task
    init_db()
    if TELEGRAM_BOT_TOKEN:
        bot_manager = TelegramBotManager()
        bot_task = asyncio.create_task(bot_manager.run_async())
    try:
        yield
    finally:
        if bot_task:
            bot_task.cancel()
            try:
                await bot_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.warning("bot shutdown error: %s", exc)
        try:
            SEARCH_EXECUTOR.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            SEARCH_EXECUTOR.shutdown(wait=False)
        except Exception as exc:
            logger.warning("executor shutdown error: %s", exc)
        try:
            HTTP_SESSION.close()
        except Exception:
            pass

app = FastAPI(title="GloomApi - Search API", version="2.2", lifespan=lifespan)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled: %s", exc)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# CORS: credentials + "*" несовместимы — при пустом ALLOWED_ORIGINS credentials выключаем
_cors_origins = ALLOWED_ORIGINS if ALLOWED_ORIGINS else ["*"]
_cors_credentials = bool(ALLOWED_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    max_age=600,
)


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    """Rate limit + базовые security headers."""
    client_ip = get_client_ip(request) or "unknown"

    # admin bypass only with valid master key (constant-time)
    path = request.url.path
    if path.startswith("/key") or path.startswith("/keys") or path == "/stats":
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and MASTER_API_KEY:
            token = auth_header[7:].strip()
            if _secure_eq(token, MASTER_API_KEY):
                response = await call_next(request)
                _set_security_headers(response)
                return response

    if not rate_limiter.is_allowed(client_ip):
        remaining = rate_limiter.get_remaining(client_ip)
        resp = JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "remaining": remaining,
                "limit": RATE_LIMIT_REQUESTS,
                "period": RATE_LIMIT_PERIOD,
            },
        )
        _set_security_headers(resp)
        resp.headers["Retry-After"] = str(RATE_LIMIT_PERIOD)
        return resp

    try:
        response = await call_next(request)
    except Exception as exc:
        logger.exception("unhandled request error: %s", exc)
        response = JSONResponse(status_code=500, content={"error": "Internal server error"})
    _set_security_headers(response)
    response.headers["X-RateLimit-Remaining"] = str(rate_limiter.get_remaining(client_ip))
    return response


def _set_security_headers(response: Response) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

# Инициализация всех поисковых модулей
search_modules = [
    JitlerSearchModule(),
    NightSearchModule(),
    DepSearchModule(),
    TelegramHistoryModule(),
    RaidFindModule(),
    VKAPIModule(),
    TruecallerModule(),
    InfinitySearchModule(),
    LeakLookupModule(),
    ZvoniliModule(),
    SeonModule(),
    WhatsAppModule(),
    PansrcModule(),
    FaceSearchModule(),
    DeepScanModule(),
    BigBaseModule(),
    OnuxModule(),
    TulasayModule(),
    RedMaskModule(),
    IPInfoModule(),
    IPStackModule(),
    IPGeolocationModule(),
    IPDataModule(),
    IPBaseModule(),
    IP2LocationModule(),
    NumVerifyModule(),
    MailboxlayerModule(),
    EmailValidModule(),
    EmailReputationModule(),
    VeriPhoneModule(),
    ProxyCheckModule(),
    AbuseIPDBModule(),
    ShodanModule(),
    HunterModule(),
    HIBPModule(),
    LeakCheckModule(),
    SnusbaseModule(),
    DehashedModule(),
    WeLeakInfoModule(),
    CensysModule(),
    BinaryEdgeModule(),
    GreyNoiseModule(),
    IntelXModule(),
    OFDataModule(),
    FishAPIModule(),
    LeakIXModule(),
    BlackEyeModule(),
    CoreAPIModule(),
    WhiteSearchModule(),
    W2SP3RModule(),
    QuickFlowModule(),
    FunStatModule(),
    GerhanoModule(),
    LocalSearchModule(),
    NetSpyModule(),
]

# ============================================================================
# ENDPOINTS
# ============================================================================

def _normalize_search_params(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
    """Нормализация, clamp длины и обогащение параметров поиска."""
    params: Dict[str, Any] = {}
    for k, v in raw.items():
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        if len(s) > MAX_QUERY_VALUE_LEN:
            s = s[:MAX_QUERY_VALUE_LEN]
        params[k] = s

    output_file = params.pop("output_file", None)

    if "number" in params and "phone" not in params:
        params["phone"] = params["number"]

    if "first_name" in params and "last_name" in params and "fio" not in params and "fullname" not in params:
        params["fio"] = f"{params['first_name']} {params['last_name']}".strip()
    if "first_name" in params and "last_name" not in params and "fio" not in params and "fullname" not in params and "name" not in params:
        params["fio"] = params["first_name"]
    if "last_name" in params and "first_name" not in params and "fio" not in params and "fullname" not in params and "name" not in params:
        params["fio"] = params["last_name"]

    if params.get("phone"):
        params["phone"] = normalize_phone(params["phone"]) or params["phone"]
    if params.get("vk") or params.get("vk_id"):
        raw_vk = params.get("vk") or params.get("vk_id")
        params["vk"] = extract_vk_id(raw_vk)
        params["vk_id"] = params["vk"]
    if params.get("telegram") or params.get("telegram_id") or params.get("username"):
        tg = params.get("telegram") or params.get("telegram_id") or params.get("username")
        params["telegram"] = normalize_telegram_query(str(tg))

    return params, output_file


def _result_fingerprint(row: Dict[str, Any]) -> str:
    """Стабильный ключ дедупликации результатов."""
    try:
        payload = {
            "source": row.get("source"),
            "field": row.get("field"),
            "value": row.get("value"),
            "method": row.get("method"),
            "data": row.get("data"),
        }
        blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        blob = f"{row.get('source')}|{row.get('field')}|{row.get('value')}"
    return hashlib.sha1(blob.encode("utf-8", errors="ignore")).hexdigest()


def _dedupe_results(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for row in rows:
        fp = _result_fingerprint(row)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(row)
        if len(out) >= MAX_SEARCH_RESULTS:
            break
    return out


def _run_single_module(module: BaseSearchModule, params: Dict[str, Any]) -> Dict[str, Any]:
    name = module.__class__.__name__
    try:
        if hasattr(module, "can_handle") and not module.can_handle(params):
            reason = "disabled_or_circuit" if not getattr(module, "ENABLED", True) else "unsupported_fields"
            if not circuit_breaker.allow(name):
                reason = "circuit_open"
            return {"success": False, "results": [], "skipped": True, "module": name, "reason": reason}
        started = time()
        result = module.search(params) or {"success": False, "results": []}
        result["module"] = name
        result["elapsed_ms"] = int((time() - started) * 1000)
        return result
    except Exception as exc:
        circuit_breaker.failure(name)
        logger.warning("%s failed: %s", name, exc)
        return {"success": False, "module": name, "results": [], "error": str(exc)}


async def run_search_modules_parallel(params: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Параллельный запуск только релевантных модулей с общим таймаутом."""
    loop = asyncio.get_running_loop()
    to_run: List[BaseSearchModule] = []
    skipped_pre: List[Dict[str, str]] = []
    for module in search_modules:
        name = module.__class__.__name__
        if not getattr(module, "ENABLED", True):
            skipped_pre.append({"module": name, "reason": "disabled"})
            continue
        if not circuit_breaker.allow(name):
            skipped_pre.append({"module": name, "reason": "circuit_open"})
            continue
        if hasattr(module, "can_handle") and not module.can_handle(params):
            skipped_pre.append({"module": name, "reason": "unsupported_fields"})
            continue
        to_run.append(module)

    meta = {
        "modules_total": len(search_modules),
        "modules_scheduled": len(to_run),
        "modules_ran": 0,
        "modules_skipped": len(skipped_pre),
        "modules_with_hits": 0,
        "elapsed_by_module": {},
        "skipped": skipped_pre[:80],
    }
    if not to_run:
        return [], meta

    futures = [
        loop.run_in_executor(SEARCH_EXECUTOR, _run_single_module, module, params)
        for module in to_run
    ]
    try:
        gathered = await asyncio.wait_for(
            asyncio.gather(*futures, return_exceptions=True),
            timeout=SEARCH_TIMEOUT_SEC,
        )
    except asyncio.TimeoutError:
        logger.warning("Search timed out after %ss", SEARCH_TIMEOUT_SEC)
        return [], {**meta, "timeout": True, "timeout_sec": SEARCH_TIMEOUT_SEC}

    all_results: List[Dict[str, Any]] = []
    for item in gathered:
        if isinstance(item, Exception):
            logger.warning("module exception: %s", item)
            continue
        if not isinstance(item, dict):
            continue
        name = item.get("module") or "?"
        if item.get("elapsed_ms") is not None:
            meta["elapsed_by_module"][name] = item["elapsed_ms"]
        if item.get("skipped"):
            meta["modules_skipped"] += 1
            if len(meta["skipped"]) < 80:
                meta["skipped"].append({"module": name, "reason": item.get("reason")})
            continue
        meta["modules_ran"] += 1
        hits = [row for row in (item.get("results") or []) if row.get("found")]
        if hits:
            meta["modules_with_hits"] += 1
            all_results.extend(hits)
        elif item.get("error"):
            logger.debug("%s: %s", name, item.get("error"))

    deduped = _dedupe_results(all_results)
    meta["deduped_from"] = len(all_results)
    meta["deduped_to"] = len(deduped)
    return deduped, meta


@app.post("/search")
async def search(
    payload: SearchRequest,
    request: Request,
    api_key: APIKey = Depends(get_api_key),
    db: Session = Depends(get_db),
):
    raw = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
    params, output_file = _normalize_search_params(raw)

    if not params:
        raise HTTPException(status_code=400, detail="Укажите хотя бы один параметр")

    client_ip = get_client_ip(request)
    geo_task = asyncio.get_running_loop().run_in_executor(SEARCH_EXECUTOR, lookup_client_geo, client_ip)

    # атомарный резерв слота ДО тяжёлой работы
    reserved = reserve_search_slot(db, api_key.id)
    if reserved is None:
        geo_task.cancel()
        raise HTTPException(status_code=401, detail="Ключ недействителен или лимит исчерпан")

    try:
        all_results, search_meta = await run_search_modules_parallel(params)
    except Exception as exc:
        logger.exception("search orchestration failed: %s", exc)
        refund_search_slot(db, api_key.id)
        raise HTTPException(status_code=500, detail="Ошибка выполнения поиска")

    geo = {"ip": client_ip, "city": "", "region": "", "country": ""}
    try:
        geo = await asyncio.wait_for(geo_task, timeout=8)
    except Exception as exc:
        logger.debug("geo lookup skipped: %s", exc)
        try:
            geo_task.cancel()
        except Exception:
            pass

    source_api_keys = set()
    for r in all_results:
        if r.get("api_key"):
            source_api_keys.add(r["api_key"])

    source_api_key_str = ", ".join(sorted(source_api_keys)) if source_api_keys else None
    try:
        db.add(SearchLog(
            api_key_id=api_key.id,
            search_params=json.dumps(sanitize_params_for_log(params), ensure_ascii=False),
            results_count=len(all_results),
            source_api_key=source_api_key_str,
            client_ip=(geo.get("ip") or client_ip or None),
            client_city=(geo.get("city") or None),
            client_region=(geo.get("region") or None),
            client_country=(geo.get("country") or None),
        ))
        db.commit()
    except Exception as exc:
        logger.warning("SearchLog write failed: %s", exc)
        db.rollback()

    # не отдаём password в query_params клиенту
    public_params = sanitize_params_for_log(params)
    sources = sorted({str(r.get("source")) for r in all_results if r.get("source")})
    response_data = {
        "success": len(all_results) > 0,
        "results": all_results,
        "total": len(all_results),
        "sources": sources,
        "sources_count": len(sources),
        "meta": search_meta,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "query_params": public_params,
        "quota": {
            "searches_used": reserved.searches_used,
            "search_limit": reserved.search_limit,
        },
    }

    safe_path = safe_output_path(output_file)
    if output_file and not safe_path:
        response_data["save_error"] = "Недопустимый output_file (только имя *.json в OUTPUT_DIR)"
    elif safe_path:
        try:
            with open(safe_path, "w", encoding="utf-8") as f:
                json.dump(response_data, f, ensure_ascii=False, indent=2)
            response_data["saved_to"] = os.path.basename(safe_path)
        except Exception as e:
            response_data["save_error"] = "Не удалось сохранить файл"

    return response_data

@app.post("/key")
async def create_key(request: CreateKeyRequest, db: Session = Depends(get_db), authenticated: bool = Depends(get_master_api_key)):
    key_value = generate_api_key_value()
    key_hash = hash_key(key_value)
    expires_at = datetime.utcnow() + timedelta(days=request.days) if request.days else None
    ip_restrictions_json = json.dumps(request.ip_restrictions) if request.ip_restrictions else None

    try:
        api_key = APIKey(
            key=key_value,
            key_hash=key_hash,
            name=request.name,
            expires_at=expires_at,
            search_limit=request.limit,
            ip_restrictions=ip_restrictions_json
        )
        db.add(api_key)
        db.commit()
        db.refresh(api_key)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Не удалось создать уникальный ключ, повторите запрос")
    except SQLAlchemyError:
        db.rollback()
        logger.exception("create_key db error")
        raise HTTPException(status_code=500, detail="Ошибка сохранения ключа")

    return {
        "id": api_key.id,
        "key": api_key.key,
        "name": api_key.name,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "search_limit": api_key.search_limit,
        "searches_used": api_key.searches_used,
        "status": api_key.status,
        "ip_restrictions": request.ip_restrictions,
    }

@app.get("/keys")
async def list_keys(db: Session = Depends(get_db), authenticated: bool = Depends(get_master_api_key)):
    keys = db.query(APIKey).all()
    return [serialize_api_key(key) for key in keys]


@app.get("/keys/export")
async def export_keys(db: Session = Depends(get_db), authenticated: bool = Depends(get_master_api_key)):
    keys = db.query(APIKey).order_by(APIKey.id.asc()).all()
    return build_keys_backup(keys)


@app.post("/keys/import")
async def import_keys_http(request: Request, db: Session = Depends(get_db), authenticated: bool = Depends(get_master_api_key)):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Ожидается JSON")
    try:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        items = parse_keys_backup(raw)
        stats = import_api_keys(db, items)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        logger.exception("HTTP keys import failed")
        raise HTTPException(status_code=500, detail="Не удалось импортировать ключи")
    return {"success": True, **stats}

@app.get("/key/{key_id}")
async def get_key(key_id: int, db: Session = Depends(get_db), authenticated: bool = Depends(get_master_api_key)):
    api_key = db.query(APIKey).filter(APIKey.id == key_id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="Ключ не найден")
    # Возвращаем полный ключ только при запросе
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key": api_key.key,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "search_limit": api_key.search_limit,
        "searches_used": api_key.searches_used,
        "status": api_key.status,
        "created_by": api_key.created_by,
        "last_used_at": api_key.last_used_at,
        "ip_restrictions": json.loads(api_key.ip_restrictions) if api_key.ip_restrictions else None
    }

@app.delete("/key/{key_id}")
async def delete_key(key_id: int, db: Session = Depends(get_db), authenticated: bool = Depends(get_master_api_key)):
    api_key = db.query(APIKey).filter(APIKey.id == key_id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="Ключ не найден")
    db.delete(api_key)
    db.commit()
    return {"message": "Ключ удален"}

@app.get("/stats")
async def get_stats(db: Session = Depends(get_db), authenticated: bool = Depends(get_master_api_key)):
    try:
        report = collect_usage_report(db)
    except Exception:
        logger.exception("stats collect failed")
        raise HTTPException(status_code=500, detail="Не удалось собрать статистику")
    keys_short = []
    for block in report.get("keys") or []:
        keys_short.append({
            "id": block.get("id"),
            "name": block.get("name"),
            "key": block.get("key"),
            "status": block.get("status"),
            "searches_used": block.get("searches_used"),
            "search_limit": block.get("search_limit"),
            "last_used_at": block.get("last_used_at"),
            "last_ip": block.get("last_ip"),
            "last_city": block.get("last_place"),
            "unique_ips": block.get("unique_ips"),
            "unique_cities": block.get("unique_places"),
            "recent": block.get("recent"),
        })
    return {
        "total_keys": report.get("total_keys"),
        "active_keys": report.get("active_keys"),
        "expired_keys": max(0, int(report.get("total_keys") or 0) - int(report.get("active_keys") or 0)),
        "total_searches": report.get("total_searches"),
        "logged_events": report.get("logged_events"),
        "keys": keys_short,
    }

@app.get("/")
async def root():
    module_names = [m.__class__.__name__ for m in search_modules]
    enabled = [m.__class__.__name__ for m in search_modules if getattr(m, "ENABLED", True)]
    return {
        "name": "GloomApi - Search API",
        "version": "2.2",
        "docs": "/docs",
        "modules_count": len(module_names),
        "modules_enabled": len(enabled),
        "modules": module_names,
        "enabled_modules": enabled,
        "endpoints": {
            "/search": "POST - параллельный поиск по всем источникам",
            "/key": "POST - создать ключ (master)",
            "/keys": "GET - список ключей (master, полные значения)",
            "/keys/export": "GET - бэкап ключей JSON (master)",
            "/keys/import": "POST - восстановить ключи из JSON (master)",
            "/key/{id}": "GET/DELETE - ключ (master)",
            "/stats": "GET - статистика (master)",
        },
    }

# ============================================================================
# TELEGRAM BOT
# ============================================================================

class TelegramBotManager:
    def __init__(self):
        self.application = None

    def get_db(self):
        return SessionLocal()

    @contextmanager
    def db_session(self):
        db = self.get_db()
        try:
            yield db
        finally:
            db.close()

    def _is_admin(self, user_id: Optional[int]) -> bool:
        if not ADMIN_TELEGRAM_IDS:
            return True
        return bool(user_id) and int(user_id) in ADMIN_TELEGRAM_IDS

    def _esc(self, value: Any) -> str:
        return html.escape(str(value or ""), quote=False)

    def _menu_keyboard(self) -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("🔑 Создать ключ", callback_data="create_key")],
            [InlineKeyboardButton("📋 Мои ключи", callback_data="list_keys")],
            [InlineKeyboardButton("📥 Скачать ключи", callback_data="export_keys")],
            [InlineKeyboardButton("📤 Загрузить ключи", callback_data="import_keys")],
            [InlineKeyboardButton("📊 Статистика", callback_data="stats")],
            [InlineKeyboardButton("❓ Помощь", callback_data="help")],
        ])

    def _keys_action_keyboard(self, keys: List[APIKey]) -> InlineKeyboardMarkup:
        keyboard = []
        for key in keys:
            row = []
            if key.status == "active":
                row.append(InlineKeyboardButton("🚫 Деактивировать", callback_data=f"deactivate_key_{key.id}"))
            else:
                row.append(InlineKeyboardButton("✅ Активировать", callback_data=f"activate_key_{key.id}"))
            row.append(InlineKeyboardButton("🗑 Удалить", callback_data=f"delete_key_{key.id}"))
            row.append(InlineKeyboardButton("📊 Логи", callback_data=f"key_logs_{key.id}"))
            keyboard.append(row)
        keyboard.append([InlineKeyboardButton("📥 Скачать ключи", callback_data="export_keys")])
        keyboard.append([InlineKeyboardButton("📤 Загрузить ключи", callback_data="import_keys")])
        keyboard.append([InlineKeyboardButton("↩️ Меню", callback_data="menu")])
        return InlineKeyboardMarkup(keyboard)

    def _format_key_block(self, key: APIKey) -> str:
        status_emoji = "✅" if key.status == "active" else "❌"
        block = f"{status_emoji} <b>{self._esc(key.name)}</b>\n"
        block += f"   Ключ: <code>{self._esc(key.key)}</code>\n"
        block += f"   Использовано: {key.searches_used or 0}"
        if key.search_limit:
            block += f"/{key.search_limit}"
        else:
            block += "/∞"
        block += "\n"
        if key.expires_at:
            try:
                block += f"   Истекает: {key.expires_at.strftime('%d.%m.%Y %H:%M')}\n"
            except Exception:
                block += "   Истекает: неизвестно\n"
        else:
            block += "   Истекает: без срока\n"
        block += "\n"
        return block

    def _build_keys_message(self, keys: List[APIKey]) -> str:
        if not keys:
            return "📋 Нет созданных ключей"
        header = "📋 Все ключи (значения полностью):\n\n"
        body = "".join(self._format_key_block(k) for k in keys)
        footer = "\nЧтобы не потерять ключи после пересборки — скачайте файл и загрузите его обратно."
        text = header + body + footer
        if len(text) <= TELEGRAM_HTML_LIMIT:
            return text
        shown = header
        for key in keys:
            block = self._format_key_block(key)
            if len(shown) + len(block) + 180 > TELEGRAM_HTML_LIMIT:
                break
            shown += block
        shown += (
            f"… и ещё {max(0, len(keys) - shown.count('Ключ:'))} ключ(ей).\n"
            "Полный список в файле по кнопке «Скачать ключи»."
        )
        return shown

    async def _safe_edit(self, query, text: str, reply_markup=None, parse_mode="HTML"):
        try:
            await query.edit_message_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
        except BadRequest as exc:
            msg = str(exc).lower()
            if "message is not modified" in msg:
                return
            if "message is too long" in msg or "can't parse entities" in msg:
                await query.edit_message_text(
                    "Текст слишком длинный для сообщения. Скачайте файл.",
                    reply_markup=InlineKeyboardMarkup([
                        [InlineKeyboardButton("📥 Скачать статистику всех ключей", callback_data="export_stats")],
                        [InlineKeyboardButton("📥 Скачать ключи", callback_data="export_keys")],
                        [InlineKeyboardButton("↩️ Меню", callback_data="menu")],
                    ]),
                )
                return
            logger.warning("edit_message_text failed: %s", exc)
            try:
                await query.message.reply_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
            except Exception as inner:
                logger.warning("fallback reply failed: %s", inner)
        except Exception as exc:
            logger.warning("edit_message_text error: %s", exc)

    async def _show_keys_list(self, query):
        with self.db_session() as db:
            keys = db.query(APIKey).order_by(APIKey.id.asc()).all()
        if not keys:
            await self._safe_edit(
                query,
                "📋 Нет созданных ключей\n\nЗагрузите файл бэкапа, если ключи были раньше.",
                InlineKeyboardMarkup([
                    [InlineKeyboardButton("📤 Загрузить ключи", callback_data="import_keys")],
                    [InlineKeyboardButton("↩️ Меню", callback_data="menu")],
                ]),
            )
            return
        await self._safe_edit(query, self._build_keys_message(keys), self._keys_action_keyboard(keys))

    def _create_key_record(self, *, name: str, days: int, limit: Optional[int], created_by: int) -> Tuple[Optional[APIKey], Optional[str], Optional[str]]:
        key_value = generate_api_key_value()
        expires_at = datetime.utcnow() + timedelta(days=days) if days and days > 0 else None
        try:
            with self.db_session() as db:
                api_key = APIKey(
                    key=key_value,
                    key_hash=hash_key(key_value),
                    name=str(name)[:255],
                    expires_at=expires_at,
                    search_limit=limit,
                    created_by=created_by,
                )
                db.add(api_key)
                db.commit()
                db.refresh(api_key)
                return api_key, key_value, None
        except IntegrityError:
            logger.exception("duplicate api key")
            return None, None, "Не удалось создать уникальный ключ, попробуйте ещё раз."
        except SQLAlchemyError:
            logger.exception("create key db error")
            return None, None, "Ошибка базы данных при создании ключа."
        except Exception as exc:
            logger.exception("create key failed")
            return None, None, f"Не удалось создать ключ: {exc}"

    def _created_key_text(self, api_key: APIKey, key_value: str) -> str:
        text = "✅ Ключ успешно создан!\n\n"
        text += "🔑 <b>Ваш API ключ:</b>\n"
        text += f"<code>{self._esc(key_value)}</code>\n\n"
        text += f"📝 Название: {self._esc(api_key.name)}\n"
        if api_key.expires_at:
            text += f"⏰ Истекает: {api_key.expires_at.strftime('%d.%m.%Y %H:%M')}\n"
        else:
            text += "⏰ Срок: без ограничений\n"
        text += f"🔍 Лимит поисков: {api_key.search_limit if api_key.search_limit else 'Безлимит'}\n\n"
        text += "Ключ также виден в разделе «Мои ключи». Скачайте файл бэкапа, чтобы не потерять его после пересборки."
        return text

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id if update.effective_user else 0
        try:
            if not self._is_admin(user_id):
                await update.message.reply_text("🚫 У вас нет доступа к этому боту.")
                return
            await update.message.reply_text(
                "👋 Добро пожаловать в GloomApi Bot!\n\n"
                "Ключи имеют префикс <code>plut_</code>.\n"
                "Скачайте файл с ключами перед пересборкой хоста и загрузите его после деплоя.",
                reply_markup=self._menu_keyboard(),
                parse_mode="HTML",
            )
        except Exception:
            logger.exception("start_command failed for %s", user_id)
            if update.message:
                try:
                    await update.message.reply_text("Не удалось открыть меню. Попробуйте /start ещё раз.")
                except Exception:
                    pass

    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        if not query:
            return
        try:
            await query.answer()
        except Exception:
            pass

        user_id = update.effective_user.id if update.effective_user else 0
        data = query.data or ""
        try:
            if not self._is_admin(user_id):
                await self._safe_edit(query, "🚫 Этот бот доступен только для администраторов.")
                return

            if data == "create_key":
                context.user_data["state"] = "creating_key_name"
                await self._safe_edit(query, "🔑 Создание нового ключа\n\nВведите название для ключа:")

            elif data == "list_keys":
                await self._show_keys_list(query)

            elif data == "export_keys":
                await self._export_keys_file(query)

            elif data == "import_keys":
                context.user_data["state"] = "awaiting_keys_file"
                await self._safe_edit(
                    query,
                    "📤 Отправьте файл с ключами.\n\n"
                    "Поддерживается JSON-бэкап с бота или текстовый список "
                    "(<code>plut_...</code> / <code>sk_...</code>, по одному на строку).\n\n"
                    "Существующие ключи не затираются — добавляются только новые.",
                    InlineKeyboardMarkup([[InlineKeyboardButton("↩️ Меню", callback_data="menu")]]),
                )

            elif data == "stats":
                await self._show_stats(query)

            elif data == "export_stats":
                await self._export_stats_file(query)

            elif data == "help":
                text = (
                    "❓ Помощь\n\n"
                    "🔑 <b>Создать ключ</b> — новый ключ с префиксом <code>plut_</code>\n"
                    "📋 <b>Мои ключи</b> — полный список значений\n"
                    "📥 <b>Скачать ключи</b> — JSON-файл для бэкапа перед пересборкой\n"
                    "📤 <b>Загрузить ключи</b> — восстановить ключи из файла после деплоя\n"
                    "📊 <b>Статистика</b> — IP и город каждого использования ключа\n\n"
                    "Использование:\n"
                    "<code>Authorization: Bearer plut_...</code>"
                )
                await self._safe_edit(
                    query,
                    text,
                    InlineKeyboardMarkup([[InlineKeyboardButton("↩️ Меню", callback_data="menu")]]),
                )

            elif data == "menu":
                context.user_data.pop("state", None)
                await self._safe_edit(query, "👋 Главное меню\n\nВыберите действие:", self._menu_keyboard(), parse_mode=None)

            elif data.startswith("deactivate_key_"):
                await self._set_key_status(query, data, "inactive", "Ключ деактивирован")

            elif data.startswith("activate_key_"):
                await self._set_key_status(query, data, "active", "Ключ активирован")

            elif data.startswith("delete_key_"):
                await self._delete_key(query, data)

            elif data.startswith("key_logs_"):
                await self._show_key_logs(query, data)

            else:
                await query.answer("Неизвестная команда", show_alert=True)
        except Exception:
            logger.exception("button_callback failed for %s data=%s", user_id, data)
            try:
                await query.answer("Ошибка обработки. Попробуйте ещё раз.", show_alert=True)
            except Exception:
                pass

    async def _set_key_status(self, query, data: str, status: str, ok_text: str):
        try:
            key_id = int(data.rsplit("_", 1)[-1])
        except (TypeError, ValueError):
            await query.answer("Некорректный идентификатор ключа", show_alert=True)
            return
        with self.db_session() as db:
            key = db.query(APIKey).filter(APIKey.id == key_id).first()
            if not key:
                await query.answer("Ключ не найден", show_alert=True)
                return
            key.status = status
            db.commit()
        await query.answer(ok_text)
        await self._show_keys_list(query)

    async def _delete_key(self, query, data: str):
        try:
            key_id = int(data.rsplit("_", 1)[-1])
        except (TypeError, ValueError):
            await query.answer("Некорректный идентификатор ключа", show_alert=True)
            return
        with self.db_session() as db:
            key = db.query(APIKey).filter(APIKey.id == key_id).first()
            if not key:
                await query.answer("Ключ не найден", show_alert=True)
                return
            db.delete(key)
            db.commit()
        await query.answer("Ключ удалён")
        await self._show_keys_list(query)

    def _stats_keyboard(self, truncated: bool) -> InlineKeyboardMarkup:
        rows = []
        if truncated:
            rows.append([InlineKeyboardButton("📥 Скачать статистику всех ключей", callback_data="export_stats")])
        rows.append([InlineKeyboardButton("↩️ Меню", callback_data="menu")])
        return InlineKeyboardMarkup(rows)

    def _build_stats_message(self, report: Dict[str, Any]) -> Tuple[str, bool]:
        header = (
            "📊 <b>Статистика использования</b>\n\n"
            f"🔑 Всего ключей: {report.get('total_keys')}\n"
            f"✅ Активных: {report.get('active_keys')}\n"
            f"🔍 Всего поисков: {report.get('total_searches')}\n"
            f"📝 Записей в логах: {report.get('logged_events')}\n\n"
        )
        parts = [header]
        for block in report.get("keys") or []:
            status_emoji = "✅" if block.get("status") == "active" else "❌"
            used = block.get("searches_used") or 0
            limit = block.get("search_limit")
            quota = f"{used}/{limit}" if limit else f"{used}/∞"
            chunk = f"{status_emoji} <b>{self._esc(block.get('name'))}</b>\n"
            chunk += f"   Ключ: <code>{self._esc(block.get('key'))}</code>\n"
            chunk += f"   Использовано: {quota}\n"
            last_ip = block.get("last_ip") or "нет данных"
            last_place = block.get("last_place") or "город не определён"
            chunk += f"   Последний IP: <code>{self._esc(last_ip)}</code>\n"
            chunk += f"   Город: {self._esc(last_place)}\n"
            unique_ips = block.get("unique_ips") or []
            unique_places = block.get("unique_places") or []
            if unique_ips:
                shown_ips = ", ".join(unique_ips[:8])
                if len(unique_ips) > 8:
                    shown_ips += f" … +{len(unique_ips) - 8}"
                chunk += f"   IP: <code>{self._esc(shown_ips)}</code>\n"
            if unique_places:
                shown_places = ", ".join(unique_places[:6])
                if len(unique_places) > 6:
                    shown_places += f" … +{len(unique_places) - 6}"
                chunk += f"   Города: {self._esc(shown_places)}\n"
            for row in (block.get("recent") or [])[:3]:
                at = row.get("at") or "?"
                if isinstance(at, str) and "T" in at:
                    at = at.replace("T", " ")[:16]
                ip = row.get("ip") or "IP неизвестен"
                place = row.get("place") or "город не определён"
                chunk += f"   • {self._esc(at)} | {self._esc(ip)} | {self._esc(place)}\n"
            chunk += "\n"
            parts.append(chunk)

        text = "".join(parts).rstrip()
        if len(text) <= TELEGRAM_HTML_LIMIT:
            return text, False
        shown = header
        hidden = 0
        for chunk in parts[1:]:
            if hidden or len(shown) + len(chunk) + 220 > TELEGRAM_HTML_LIMIT:
                hidden += 1
                continue
            shown += chunk
        shown += "\nТекст слишком длинный — полный отчёт по всем ключам в файле."
        if hidden:
            shown += f" Скрыто ключей: {hidden}."
        return shown, True

    async def _show_stats(self, query):
        try:
            with self.db_session() as db:
                report = collect_usage_report(db)
        except Exception:
            logger.exception("bot stats collect failed")
            await self._safe_edit(
                query,
                "Не удалось собрать статистику. Попробуйте ещё раз.",
                InlineKeyboardMarkup([[InlineKeyboardButton("↩️ Меню", callback_data="menu")]]),
                parse_mode=None,
            )
            return
        text, truncated = self._build_stats_message(report)
        await self._safe_edit(query, text, self._stats_keyboard(truncated))

    async def _export_stats_file(self, query):
        try:
            with self.db_session() as db:
                report = collect_usage_report(db)
            body = render_usage_report_text(report)
            bio = BytesIO(body.encode("utf-8"))
            filename = f"gloomapi_stats_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
            await query.message.reply_document(
                document=InputFile(bio, filename=filename),
                caption=(
                    "📥 Статистика всех ключей\n"
                    f"Ключей: {report.get('total_keys')} | "
                    f"поисков: {report.get('total_searches')} | "
                    f"записей: {report.get('logged_events')}"
                ),
            )
            await query.answer("Файл отправлен")
        except Forbidden:
            await query.answer("Бот не может отправить файл. Напишите /start.", show_alert=True)
        except TelegramError as exc:
            logger.warning("export stats failed: %s", exc)
            await query.answer("Не удалось отправить файл статистики", show_alert=True)
        except Exception:
            logger.exception("export stats failed")
            await query.answer("Ошибка выгрузки статистики", show_alert=True)

    async def _show_key_logs(self, query, data: str):
        try:
            key_id = int(data.rsplit("_", 1)[-1])
        except (TypeError, ValueError):
            await query.answer("Некорректный идентификатор ключа", show_alert=True)
            return
        with self.db_session() as db:
            key = db.query(APIKey).filter(APIKey.id == key_id).first()
            if not key:
                await query.answer("Ключ не найден", show_alert=True)
                return
            logs = (
                db.query(SearchLog)
                .filter(SearchLog.api_key_id == key_id)
                .order_by(SearchLog.created_at.desc())
                .limit(50)
                .all()
            )
            text = f"📊 Логи ключа: {self._esc(key.name)}\n"
            text += f"Ключ: <code>{self._esc(key.key)}</code>\n\n"
            if not logs:
                text += "Нет записей"
            else:
                for log in logs:
                    try:
                        params = json.loads(log.search_params or "{}")
                    except (TypeError, json.JSONDecodeError):
                        params = {}
                    created = log.created_at.strftime("%d.%m.%Y %H:%M") if log.created_at else "?"
                    ip = (getattr(log, "client_ip", None) or "").strip() or "IP неизвестен"
                    place = format_log_place(log) or "город не определён"
                    text += f"🔍 {created}\n"
                    text += f"   IP: <code>{self._esc(ip)}</code>\n"
                    text += f"   Город: {self._esc(place)}\n"
                    if isinstance(params, dict) and params:
                        text += f"   Параметры: {self._esc(', '.join(map(str, params.keys())))}\n"
                    text += f"   Результатов: {log.results_count}\n\n"
        keyboard = [[InlineKeyboardButton("↩️ Назад к ключам", callback_data="list_keys")]]
        truncated = len(text) > TELEGRAM_HTML_LIMIT
        if truncated:
            text = text[: TELEGRAM_HTML_LIMIT - 80].rstrip() + "\n\n… полный отчёт в файле."
            keyboard.insert(0, [InlineKeyboardButton("📥 Скачать статистику всех ключей", callback_data="export_stats")])
        await self._safe_edit(query, text, InlineKeyboardMarkup(keyboard))

    async def _export_keys_file(self, query):
        with self.db_session() as db:
            keys = db.query(APIKey).order_by(APIKey.id.asc()).all()
        if not keys:
            await query.answer("Нет ключей для выгрузки", show_alert=True)
            return
        payload = build_keys_backup(keys)
        raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        bio = BytesIO(raw)
        filename = f"gloomapi_keys_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            await query.message.reply_document(
                document=InputFile(bio, filename=filename),
                caption=(
                    f"📥 Бэкап ключей: {len(keys)} шт.\n"
                    "Сохраните файл и загрузите его в бота после пересборки хоста."
                ),
            )
            await query.answer("Файл отправлен")
        except Forbidden:
            await query.answer("Бот не может отправить файл. Напишите /start.", show_alert=True)
        except TelegramError as exc:
            logger.warning("export document failed: %s", exc)
            await query.answer("Не удалось отправить файл", show_alert=True)

    async def message_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.message or not update.message.text:
            return
        user_id = update.effective_user.id if update.effective_user else 0
        text = update.message.text.strip()
        state = (context.user_data or {}).get("state")
        try:
            if not self._is_admin(user_id):
                await update.message.reply_text("🚫 Этот бот доступен только для администраторов.")
                return

            if state == "creating_key_name":
                if not text or len(text) > 255:
                    await update.message.reply_text("❌ Название должно быть от 1 до 255 символов.")
                    return
                context.user_data["key_name"] = text
                context.user_data["state"] = "creating_key_days"
                keyboard = [
                    [InlineKeyboardButton("7 дней", callback_data="days_7")],
                    [InlineKeyboardButton("30 дней", callback_data="days_30")],
                    [InlineKeyboardButton("90 дней", callback_data="days_90")],
                    [InlineKeyboardButton("180 дней", callback_data="days_180")],
                    [InlineKeyboardButton("365 дней", callback_data="days_365")],
                    [InlineKeyboardButton("Без ограничений", callback_data="days_0")],
                    [InlineKeyboardButton("✏️ Свое число дней", callback_data="days_custom")],
                ]
                await update.message.reply_text(
                    f"📝 Название: {self._esc(text)}\n\n⏰ Выберите срок действия ключа:",
                    reply_markup=InlineKeyboardMarkup(keyboard),
                    parse_mode="HTML",
                )
                return

            if state == "creating_key_days_custom":
                try:
                    days = int(text)
                except ValueError:
                    await update.message.reply_text("❌ Введите целое число дней.")
                    return
                if days < 1 or days > 3650:
                    await update.message.reply_text("❌ Количество дней — от 1 до 3650.")
                    return
                context.user_data["key_days"] = days
                context.user_data["state"] = "creating_key_limit"
                await update.message.reply_text(
                    f"⏰ Срок: {days} дней\n\n🔢 Выберите лимит поисков или введите своё число:",
                    reply_markup=self._limit_keyboard(),
                )
                return

            if state == "creating_key_limit":
                try:
                    limit = int(text)
                except ValueError:
                    await update.message.reply_text("❌ Введите корректное число лимита.")
                    return
                if limit < 1 or limit > 10_000_000:
                    await update.message.reply_text("❌ Лимит — от 1 до 10000000.")
                    return
                await self._finish_key_creation(update, context, user_id, limit)
                return

            if state == "awaiting_keys_file":
                await update.message.reply_text("Отправьте документ (файл), а не текст.")
                return

            await update.message.reply_text("Выберите действие в меню или отправьте /start.", reply_markup=self._menu_keyboard())
        except Exception:
            logger.exception("message_handler failed for %s", user_id)
            try:
                await update.message.reply_text("Ошибка обработки сообщения. Попробуйте ещё раз.")
            except Exception:
                pass

    def _limit_keyboard(self) -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("100", callback_data="limit_100")],
            [InlineKeyboardButton("1000", callback_data="limit_1000")],
            [InlineKeyboardButton("10000", callback_data="limit_10000")],
            [InlineKeyboardButton("Безлимит", callback_data="limit_0")],
        ])

    async def _finish_key_creation(self, update, context, user_id: int, limit: Optional[int], via_query=None):
        name = (context.user_data or {}).get("key_name")
        if not name:
            msg = "Сначала введите название ключа через «Создать ключ»."
            if via_query:
                await self._safe_edit(via_query, msg, self._menu_keyboard(), parse_mode=None)
            elif update.message:
                await update.message.reply_text(msg, reply_markup=self._menu_keyboard())
            return
        days = int((context.user_data or {}).get("key_days") or 0)
        api_key, key_value, error = self._create_key_record(name=name, days=days, limit=limit, created_by=user_id)
        context.user_data.clear()
        if error or not api_key or not key_value:
            text = error or "Не удалось создать ключ."
            if via_query:
                await self._safe_edit(via_query, text, self._menu_keyboard(), parse_mode=None)
            elif update.message:
                await update.message.reply_text(text, reply_markup=self._menu_keyboard())
            return
        text = self._created_key_text(api_key, key_value)
        markup = InlineKeyboardMarkup([[InlineKeyboardButton("↩️ Меню", callback_data="menu")]])
        if via_query:
            await self._safe_edit(via_query, text, markup)
        elif update.message:
            await update.message.reply_text(text, reply_markup=markup, parse_mode="HTML")

    async def days_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        if not query:
            return
        try:
            await query.answer()
        except Exception:
            pass
        user_id = update.effective_user.id if update.effective_user else 0
        if not self._is_admin(user_id):
            await self._safe_edit(query, "🚫 Нет доступа.")
            return
        days_str = (query.data or "").replace("days_", "", 1)
        try:
            if days_str == "custom":
                context.user_data["state"] = "creating_key_days_custom"
                await self._safe_edit(query, "✏️ Введите количество дней (число):")
                return
            days = int(days_str)
            if days < 0 or days > 3650:
                await query.answer("Некорректный срок", show_alert=True)
                return
            context.user_data["key_days"] = days
            context.user_data["state"] = "creating_key_limit"
            label = "Без ограничений" if days == 0 else f"{days} дней"
            await self._safe_edit(
                query,
                f"⏰ Срок: {label}\n\n🔢 Выберите лимит поисков или введите своё число:",
                self._limit_keyboard(),
                parse_mode=None,
            )
        except Exception:
            logger.exception("days_callback failed")
            try:
                await query.answer("Ошибка выбора срока", show_alert=True)
            except Exception:
                pass

    async def limit_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        if not query:
            return
        try:
            await query.answer()
        except Exception:
            pass
        user_id = update.effective_user.id if update.effective_user else 0
        if not self._is_admin(user_id):
            await self._safe_edit(query, "🚫 Нет доступа.")
            return
        try:
            limit_str = (query.data or "").replace("limit_", "", 1)
            limit = int(limit_str) if limit_str != "0" else None
            if limit is not None and (limit < 1 or limit > 10_000_000):
                await query.answer("Некорректный лимит", show_alert=True)
                return
            await self._finish_key_creation(update, context, user_id, limit, via_query=query)
        except Exception:
            logger.exception("limit_callback failed")
            try:
                await query.answer("Ошибка создания ключа", show_alert=True)
            except Exception:
                pass

    async def document_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.message or not update.message.document:
            return
        user_id = update.effective_user.id if update.effective_user else 0
        if not self._is_admin(user_id):
            await update.message.reply_text("🚫 Этот бот доступен только для администраторов.")
            return
        state = (context.user_data or {}).get("state")
        doc = update.message.document
        filename = (doc.file_name or "").lower()
        looks_like_backup = "key" in filename or filename.endswith(".json") or filename.endswith(".txt")
        if state != "awaiting_keys_file" and not looks_like_backup:
            await update.message.reply_text(
                "Чтобы восстановить ключи, нажмите «Загрузить ключи» и пришлите файл.",
                reply_markup=self._menu_keyboard(),
            )
            return
        if doc.file_size and doc.file_size > KEYS_BACKUP_MAX_BYTES:
            await update.message.reply_text("❌ Файл больше 512 КБ.")
            return
        try:
            tg_file = await context.bot.get_file(doc.file_id)
            raw = bytes(await tg_file.download_as_bytearray())
            items = parse_keys_backup(raw)
            with self.db_session() as db:
                stats = import_api_keys(db, items, created_by=user_id)
            context.user_data.pop("state", None)
            await update.message.reply_text(
                "✅ Импорт завершён.\n\n"
                f"Добавлено: {stats['added']}\n"
                f"Пропущено (уже есть): {stats['skipped']}\n"
                f"Ошибок: {stats['failed']}",
                reply_markup=self._menu_keyboard(),
            )
        except ValueError as exc:
            await update.message.reply_text(f"❌ {exc}")
        except TelegramError as exc:
            logger.warning("document download failed: %s", exc)
            await update.message.reply_text("Не удалось скачать файл из Telegram. Попробуйте ещё раз.")
        except Exception:
            logger.exception("document_handler failed")
            await update.message.reply_text("Не удалось обработать файл. Проверьте формат JSON/TXT.")

    async def on_error(self, update: object, context: ContextTypes.DEFAULT_TYPE):
        logger.exception("telegram handler error: %s", context.error)
        try:
            if isinstance(update, Update) and update.effective_message:
                await update.effective_message.reply_text("Произошла внутренняя ошибка. Попробуйте ещё раз.")
        except Exception:
            pass

    async def run_async(self):
        if not TELEGRAM_BOT_TOKEN:
            logger.warning("TELEGRAM_BOT_TOKEN не установлен. Бот не запущен.")
            return

        try:
            self.application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
            self.application.add_handler(CommandHandler("start", self.start_command))
            self.application.add_handler(CallbackQueryHandler(self.days_callback, pattern="^days_"))
            self.application.add_handler(CallbackQueryHandler(self.limit_callback, pattern="^limit_"))
            self.application.add_handler(CallbackQueryHandler(self.button_callback))
            self.application.add_handler(MessageHandler(filters.Document.ALL, self.document_handler))
            self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.message_handler))
            self.application.add_error_handler(self.on_error)

            await self.application.initialize()
            await self.application.start()
            await self.application.updater.start_polling(drop_pending_updates=True)
            logger.info("Telegram bot polling started")
            while self.application.updater and self.application.updater.is_running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            logger.info("Telegram polling cancelled")
            raise
        except Exception:
            logger.exception("Telegram polling failed")
            raise
        finally:
            if self.application:
                try:
                    if self.application.updater and self.application.updater.is_running:
                        await self.application.updater.stop()
                except Exception:
                    logger.warning("updater stop failed", exc_info=True)
                try:
                    await self.application.stop()
                except Exception:
                    logger.warning("application stop failed", exc_info=True)
                try:
                    await self.application.shutdown()
                except Exception:
                    logger.warning("application shutdown failed", exc_info=True)
            logger.info("Telegram bot stopped")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
