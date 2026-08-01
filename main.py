#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified Search API - Простой поиск по данным
Один файл - всё включено
Интеграция всех API из ресурсов
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from sqlalchemy.sql import func
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import secrets
import json
import os
import requests
import random
import hashlib
import asyncio
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# НАСТРОЙКИ
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./search.db")
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ADMIN_TELEGRAM_IDS = [int(x) for x in os.getenv("ADMIN_TELEGRAM_IDS", "").split(",") if x]

# Для PostgreSQL на Railway
if DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://"):
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
else:
    # Для локального SQLite
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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
    key = Column(String(64), unique=True, index=True, nullable=False)
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

# Создание таблиц (отложено до запуска приложения)
def init_db():
    """Инициализация базы данных"""
    Base.metadata.create_all(bind=engine)

# ============================================================================
# МОДЕЛИ
# ============================================================================

class SearchRequest(BaseModel):
    phone: Optional[str] = None
    email: Optional[str] = None
    nick: Optional[str] = None
    username: Optional[str] = None
    name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    fio: Optional[str] = None
    fullname: Optional[str] = None
    passport: Optional[str] = None
    inn: Optional[str] = None
    snils: Optional[str] = None
    vin: Optional[str] = None
    car_number: Optional[str] = None
    ip: Optional[str] = None
    telegram: Optional[str] = None
    telegram_id: Optional[str] = None
    vk: Optional[str] = None
    vk_id: Optional[str] = None
    card: Optional[str] = None
    imei: Optional[str] = None
    address: Optional[str] = None
    social: Optional[str] = None
    number: Optional[str] = None
    bdate: Optional[str] = None
    domain: Optional[str] = None
    photo_url: Optional[str] = None
    output_file: Optional[str] = None

class CreateKeyRequest(BaseModel):
    name: str
    days: Optional[int] = None
    limit: Optional[int] = None
    ip_restrictions: Optional[List[str]] = None

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
TRUECALLER_INSTALLATION_ID = "a1i2N--Ql8rEHHVAS8AVeQ"

# ============================================================================
# ПОИСКОВЫЕ МОДУЛИ ДЛЯ КАЖДОГО API
# ============================================================================

class BaseSearchModule:
    """Базовый класс для поисковых модулей"""
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Базовый метод поиска"""
        return {"success": False, "error": "Not implemented", "results": []}

class JitlerSearchModule(BaseSearchModule):
    """Jitler API - поиск по номеру, VK, Telegram"""
    
    def __init__(self):
        self.base_url = "https://api.jitler.top"
        self.keys = JITLER_KEYS
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Поиск по номеру телефона
        if params.get("phone"):
            try:
                key = random.choice(self.keys)
                response = requests.post(
                    f"{self.base_url}/search",
                    json={"type": "number", "query": params["phone"]},
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "jitler",
                        "field": "phone",
                        "value": params["phone"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "jitler",
                    "field": "phone",
                    "value": params["phone"],
                    "found": False,
                    "error": str(e)
                })
        
        # Поиск по VK
        if params.get("vk") or params.get("vk_id"):
            vk_id = params.get("vk") or params.get("vk_id")
            try:
                key = random.choice(self.keys)
                response = requests.post(
                    f"{self.base_url}/search",
                    json={"type": "vk", "query": vk_id},
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "jitler",
                        "field": "vk",
                        "value": vk_id,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "jitler",
                    "field": "vk",
                    "value": vk_id,
                    "found": False,
                    "error": str(e)
                })
        
        # Поиск по Telegram
        if params.get("telegram") or params.get("telegram_id"):
            tg = params.get("telegram") or params.get("telegram_id")
            try:
                key = random.choice(self.keys)
                response = requests.post(
                    f"{self.base_url}/search",
                    json={"type": "telegram", "query": tg},
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "jitler",
                        "field": "telegram",
                        "value": tg,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "jitler",
                    "field": "telegram",
                    "value": tg,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class NightSearchModule(BaseSearchModule):
    """NightSearch API - поиск по phone, email, nick, name, fio, inn, SNILS"""
    
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
            "name": "name",
            "fio": "fio",
            "fullname": "fio",
            "inn": "inn",
            "snils": "SNILS"
        }
        
        for local_param, search_type in param_mapping.items():
            if params.get(local_param):
                try:
                    response = requests.post(
                        self.base_url,
                        json={"type": search_type, "query": params[local_param]},
                        headers={"Authorization": f"Bearer {self.api_key}"},
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.append({
                            "source": "nightsearch",
                            "field": local_param,
                            "value": params[local_param],
                            "found": True,
                            "data": data
                        })
                except Exception as e:
                    results.append({
                        "source": "nightsearch",
                        "field": local_param,
                        "value": params[local_param],
                        "found": False,
                        "error": str(e)
                    })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class DepSearchModule(BaseSearchModule):
    """DepSearch API - универсальный поиск"""
    
    def __init__(self):
        self.base_url = "https://api.depsearch.sbs"
        self.token = DEPSEARCH_TOKEN
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Mapping параметров к типам поиска DepSearch
        param_mapping = {
            "phone": "phone",
            "email": "email",
            "nick": "nick",
            "name": "name",
            "passport": "passport",
            "inn": "inn",
            "snils": "snils",
            "vin": "vin",
            "car_number": "car_number",
            "ip": "ip",
            "telegram": "telegram",
            "vk": "vk",
            "card": "card",
            "imei": "imei",
            "address": "address",
            "social": "social"
        }
        
        for local_param, search_type in param_mapping.items():
            if params.get(local_param):
                try:
                    response = requests.get(
                        f"{self.base_url}/quest",
                        params={"type": search_type, "q": params[local_param]},
                        headers={"Authorization": f"Bearer {self.token}"},
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        results.append({
                            "source": "depsearch",
                            "field": local_param,
                            "value": params[local_param],
                            "found": True,
                            "data": data
                        })
                except Exception as e:
                    results.append({
                        "source": "depsearch",
                        "field": local_param,
                        "value": params[local_param],
                        "found": False,
                        "error": str(e)
                    })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class TelegramHistoryModule(BaseSearchModule):
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
    """VK API - поиск информации о пользователях, группах, друзьях, постах"""
    
    def __init__(self):
        self.base_url = "https://api.vk.com/method"
        self.token = VK_TOKEN
        self.version = VK_API_VERSION
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        # Поиск по VK ID
        vk_id = params.get("vk") or params.get("vk_id")
        if vk_id:
            # Извлечение числового ID из строки (например, из "id853724500" или "853724500")
            import re
            numeric_id = re.sub(r'[^0-9]', '', str(vk_id))
            if not numeric_id:
                numeric_id = vk_id
            
            # users.get
            try:
                response = requests.get(
                    f"{self.base_url}/users.get",
                    params={
                        "user_ids": numeric_id,
                        "fields": "photo_max,verified,sex,bdate,city,country,home_town,status,education,universities,schools,occupation,career,interests,music,movies,tv,books,games,about,activities,quotes,followers_count,online,last_seen",
                        "access_token": self.token,
                        "v": self.version
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "vk_api",
                        "method": "users.get",
                        "field": "vk",
                        "value": vk_id,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "vk_api",
                    "method": "users.get",
                    "field": "vk",
                    "value": vk_id,
                    "found": False,
                    "error": str(e)
                })
            
            # groups.get
            try:
                response = requests.get(
                    f"{self.base_url}/groups.get",
                    params={
                        "user_id": numeric_id,
                        "extended": 1,
                        "fields": "screen_name,description,members_count",
                        "access_token": self.token,
                        "v": self.version
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "vk_api",
                        "method": "groups.get",
                        "field": "vk",
                        "value": vk_id,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "vk_api",
                    "method": "groups.get",
                    "field": "vk",
                    "value": vk_id,
                    "found": False,
                    "error": str(e)
                })
            
            # friends.get
            try:
                response = requests.get(
                    f"{self.base_url}/friends.get",
                    params={
                        "user_id": numeric_id,
                        "fields": "photo_50,online,last_seen",
                        "access_token": self.token,
                        "v": self.version
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "vk_api",
                        "method": "friends.get",
                        "field": "vk",
                        "value": vk_id,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "vk_api",
                    "method": "friends.get",
                    "field": "vk",
                    "value": vk_id,
                    "found": False,
                    "error": str(e)
                })
            
            # wall.get
            try:
                response = requests.get(
                    f"{self.base_url}/wall.get",
                    params={
                        "owner_id": numeric_id,
                        "count": 20,
                        "extended": 1,
                        "access_token": self.token,
                        "v": self.version
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "vk_api",
                        "method": "wall.get",
                        "field": "vk",
                        "value": vk_id,
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "vk_api",
                    "method": "wall.get",
                    "field": "vk",
                    "value": vk_id,
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class TruecallerModule(BaseSearchModule):
    """Truecaller API - поиск по номеру телефона"""
    
    def __init__(self):
        self.base_url = "https://search5-noneu.truecaller.com/v2/search"
        self.installation_id = TRUECALLER_INSTALLATION_ID
    
    def search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        
        if params.get("phone"):
            try:
                response = requests.get(
                    self.base_url,
                    params={"q": params["phone"]},
                    headers={"X-Installation-Id": self.installation_id},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "source": "truecaller",
                        "field": "phone",
                        "value": params["phone"],
                        "found": True,
                        "data": data
                    })
            except Exception as e:
                results.append({
                    "source": "truecaller",
                    "field": "phone",
                    "value": params["phone"],
                    "found": False,
                    "error": str(e)
                })
        
        return {"success": len(results) > 0, "results": results, "total": len(results)}

class FaceSearchModule(BaseSearchModule):
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

# ============================================================================
# АУТЕНТИФИКАЦИЯ
# ============================================================================

security = HTTPBearer()

def get_api_key(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db), request: Request = None):
    token = credentials.credentials
    key_hash = hash_key(token)
    api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
    
    if not api_key:
        raise HTTPException(status_code=401, detail="Неверный ключ")
    
    # Проверка по оригинальному ключу для обратной совместимости
    if api_key.key != token:
        raise HTTPException(status_code=401, detail="Неверный ключ")
    
    if not api_key.is_valid:
        raise HTTPException(status_code=401, detail="Ключ недействителен или истёк")
    
    # Проверка IP ограничений
    if request:
        client_ip = request.client.host
        if not verify_ip_restrictions(api_key, client_ip):
            raise HTTPException(status_code=403, detail="IP адрес не разрешён")
    
    # Обновление времени последнего использования
    api_key.last_used_at = datetime.utcnow()
    db.commit()
    
    return api_key

# ============================================================================
# FASTAPI
# ============================================================================

# Глобальный экземпляр бота
bot_manager = None
bot_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager для управления ботом"""
    global bot_manager, bot_task
    # Startup
    init_db()
    
    if TELEGRAM_BOT_TOKEN:
        bot_manager = TelegramBotManager()
        bot_task = asyncio.create_task(bot_manager.run_async())
    
    yield
    
    # Shutdown
    if bot_task:
        bot_task.cancel()
        try:
            await bot_task
        except asyncio.CancelledError:
            pass

app = FastAPI(title="GloomApi - Search API", version="2.0", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Инициализация всех поисковых модулей
search_modules = [
    JitlerSearchModule(),
    NightSearchModule(),
    DepSearchModule(),
    TelegramHistoryModule(),
    RaidFindModule(),
    VKAPIModule(),
    TruecallerModule(),
    FaceSearchModule()
]

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.post("/search")
async def search(request: SearchRequest, api_key: APIKey = Depends(get_api_key), db: Session = Depends(get_db)):
    params = {k: v for k, v in request.dict().items() if v is not None}
    output_file = params.pop("output_file", None)
    
    if not params:
        raise HTTPException(status_code=400, detail="Укажите хотя бы один параметр")
    
    # Поиск по всем модулям
    all_results = []
    for module in search_modules:
        try:
            result = module.search(params)
            if result.get("success"):
                all_results.extend(result.get("results", []))
        except Exception as e:
            all_results.append({
                "source": module.__class__.__name__,
                "error": str(e),
                "found": False
            })
    
    # Логирование
    api_key.searches_used += 1
    db.add(SearchLog(api_key_id=api_key.id, search_params=json.dumps(params), results_count=len(all_results)))
    db.commit()
    
    response_data = {
        "success": len(all_results) > 0,
        "results": all_results,
        "total": len(all_results),
        "timestamp": datetime.utcnow().isoformat(),
        "query_params": params
    }
    
    # Сохранение в файл если указан
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(response_data, f, ensure_ascii=False, indent=2)
            response_data["saved_to"] = output_file
        except Exception as e:
            response_data["save_error"] = str(e)
    
    return response_data

def hash_key(key: str) -> str:
    """Хеширование ключа для безопасного хранения"""
    return hashlib.sha256(key.encode()).hexdigest()

def verify_ip_restrictions(api_key: APIKey, client_ip: str) -> bool:
    """Проверка IP ограничений"""
    if not api_key.ip_restrictions:
        return True
    try:
        allowed_ips = json.loads(api_key.ip_restrictions)
        return client_ip in allowed_ips or "*" in allowed_ips
    except:
        return True

@app.post("/key")
async def create_key(request: CreateKeyRequest, db: Session = Depends(get_db)):
    key_value = f"sk_{secrets.token_urlsafe(32)}"
    key_hash = hash_key(key_value)
    expires_at = datetime.utcnow() + timedelta(days=request.days) if request.days else None
    ip_restrictions_json = json.dumps(request.ip_restrictions) if request.ip_restrictions else None
    
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
    return api_key

@app.get("/keys")
async def list_keys(db: Session = Depends(get_db)):
    keys = db.query(APIKey).all()
    # Скрываем реальные ключи в ответе
    result = []
    for key in keys:
        key_dict = {
            "id": key.id,
            "name": key.name,
            "key": f"sk_{key.key[:8]}...{key.key[-4:]}",
            "created_at": key.created_at,
            "expires_at": key.expires_at,
            "search_limit": key.search_limit,
            "searches_used": key.searches_used,
            "status": key.status,
            "created_by": key.created_by,
            "last_used_at": key.last_used_at
        }
        result.append(key_dict)
    return result

@app.get("/key/{key_id}")
async def get_key(key_id: int, db: Session = Depends(get_db)):
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
async def delete_key(key_id: int, db: Session = Depends(get_db)):
    api_key = db.query(APIKey).filter(APIKey.id == key_id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="Ключ не найден")
    db.delete(api_key)
    db.commit()
    return {"message": "Ключ удален"}

@app.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    total_keys = db.query(APIKey).count()
    active_keys = db.query(APIKey).filter(APIKey.status == "active").count()
    expired_keys = db.query(APIKey).filter(APIKey.status != "active").count()
    total_searches = db.query(APIKey).with_entities(func.sum(APIKey.searches_used)).scalar() or 0
    
    return {
        "total_keys": total_keys,
        "active_keys": active_keys,
        "expired_keys": expired_keys,
        "total_searches": total_searches
    }

@app.get("/")
async def root():
    return {
        "name": "GloomApi - Search API",
        "version": "2.0",
        "docs": "/docs",
        "endpoints": {
            "/search": "POST - поиск",
            "/key": "POST - создать ключ",
            "/keys": "GET - список ключей",
            "/key/{id}": "GET - информация о ключе",
            "/stats": "GET - статистика"
        }
    }

# ============================================================================
# TELEGRAM BOT
# ============================================================================

class TelegramBotManager:
    def __init__(self):
        self.application = None
        
    def get_db(self):
        return SessionLocal()
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработка команды /start"""
        user_id = update.effective_user.id
        print(f"🚀 ENTER start_command for user {user_id}")
        
        try:
            if ADMIN_TELEGRAM_IDS and user_id not in ADMIN_TELEGRAM_IDS:
                await update.message.reply_text(
                    "🚫 У вас нет доступа к этому боту.\n"
                    "Свяжитесь с администратором для получения доступа."
                )
                print(f"✅ EXIT start_command for user {user_id} (access denied)")
                return
            
            keyboard = [
                [InlineKeyboardButton("🔑 Создать ключ", callback_data="create_key")],
                [InlineKeyboardButton("📋 Мои ключи", callback_data="list_keys")],
                [InlineKeyboardButton("📊 Статистика", callback_data="stats")],
                [InlineKeyboardButton("❓ Помощь", callback_data="help")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(
                "👋 Добро пожаловать в GloomApi Bot!\n\n"
                "🔍 Универсальное API для поиска по данным\n\n"
                "Выберите действие:",
                reply_markup=reply_markup
            )
            
            print(f"✅ EXIT start_command for user {user_id}")
        except Exception as e:
            print(f"❌ ERROR in start_command for user {user_id}: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработка нажатий на кнопки"""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        data = query.data
        print(f"🚀 ENTER button_callback for user {user_id}, data: {data}")
        
        try:
            if ADMIN_TELEGRAM_IDS and user_id not in ADMIN_TELEGRAM_IDS:
                await query.edit_message_text("🚫 Нет доступа")
                print(f"✅ EXIT button_callback for user {user_id} (access denied)")
                return
            
            if data == "create_key":
                context.user_data["state"] = "creating_key_name"
                await query.edit_message_text(
                    "🔑 Создание нового ключа\n\n"
                    "Введите название для ключа:"
                )
            
            elif data == "list_keys":
                db = self.get_db()
                keys = db.query(APIKey).filter(APIKey.created_by == user_id).all()
                
                if not keys:
                    await query.edit_message_text("📋 У вас нет созданных ключей")
                    print(f"✅ EXIT button_callback for user {user_id} (no keys)")
                    return
                
                text = "📋 Ваши ключи:\n\n"
                for key in keys:
                    status_emoji = "✅" if key.status == "active" else "❌"
                    text += f"{status_emoji} <b>{key.name}</b>\n"
                    text += f"   Ключ: <code>sk_{key.key[:8]}...{key.key[-4:]}</code>\n"
                    text += f"   Использовано: {key.searches_used}"
                    if key.search_limit:
                        text += f"/{key.search_limit}"
                    text += "\n"
                    if key.expires_at:
                        text += f"   Истекает: {key.expires_at.strftime('%d.%m.%Y %H:%M')}\n"
                    text += "\n"
                
                keyboard = [[InlineKeyboardButton("↩️ Меню", callback_data="menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text, reply_markup=reply_markup, parse_mode="HTML")
            
            elif data == "stats":
                db = self.get_db()
                total_keys = db.query(APIKey).count()
                active_keys = db.query(APIKey).filter(APIKey.status == "active").count()
                total_searches = db.query(APIKey).with_entities(func.sum(APIKey.searches_used)).scalar() or 0
                
                text = "📊 Статистика системы:\n\n"
                text += f"🔑 Всего ключей: {total_keys}\n"
                text += f"✅ Активных ключей: {active_keys}\n"
                text += f"🔍 Всего поисков: {total_searches}\n"
                
                keyboard = [[InlineKeyboardButton("↩️ Меню", callback_data="menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text, reply_markup=reply_markup)
            
            elif data == "help":
                text = "❓ Помощь\n\n"
                text += "🔑 <b>Создать ключ</b> - Создать новый API ключ\n"
                text += "📋 <b>Мои ключи</b> - Посмотреть список ваших ключей\n"
                text += "📊 <b>Статистика</b> - Общая статистика системы\n\n"
                text += "Для использования ключа в запросах:\n"
                text += "<code>Authorization: Bearer YOUR_API_KEY</code>\n"
                
                keyboard = [[InlineKeyboardButton("↩️ Меню", callback_data="menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text, reply_markup=reply_markup, parse_mode="HTML")
            
            elif data == "menu":
                keyboard = [
                    [InlineKeyboardButton("🔑 Создать ключ", callback_data="create_key")],
                    [InlineKeyboardButton("📋 Мои ключи", callback_data="list_keys")],
                    [InlineKeyboardButton("📊 Статистика", callback_data="stats")],
                    [InlineKeyboardButton("❓ Помощь", callback_data="help")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(
                    "👋 Главное меню\n\nВыберите действие:",
                    reply_markup=reply_markup
                )
            
            print(f"✅ EXIT button_callback for user {user_id}")
        except Exception as e:
            print(f"❌ ERROR in button_callback for user {user_id}: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    async def message_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработка текстовых сообщений"""
        user_id = update.effective_user.id
        text = update.message.text
        state = context.user_data.get("state")
        print(f"🚀 ENTER message_handler for user {user_id}, state: {state}, text: {text[:30]}")
        
        try:
            if ADMIN_TELEGRAM_IDS and user_id not in ADMIN_TELEGRAM_IDS:
                await update.message.reply_text("🚫 Нет доступа")
                print(f"✅ EXIT message_handler for user {user_id} (access denied)")
                return
            
            if state == "creating_key_name":
                context.user_data["key_name"] = text
                context.user_data["state"] = "creating_key_days"
                
                keyboard = [
                    [InlineKeyboardButton("7 дней", callback_data="days_7")],
                    [InlineKeyboardButton("30 дней", callback_data="days_30")],
                    [InlineKeyboardButton("90 дней", callback_data="days_90")],
                    [InlineKeyboardButton("Без ограничений", callback_data="days_0")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await update.message.reply_text(
                    f"📝 Название: {text}\n\n"
                    "⏰ Выберите срок действия ключа:",
                    reply_markup=reply_markup
                )
                print(f"✅ EXIT message_handler for user {user_id} (creating_key_name)")
            
            elif state == "creating_key_limit":
                try:
                    limit = int(text)
                    if limit < 1:
                        await update.message.reply_text("❌ Лимит должен быть положительным числом")
                        print(f"⚠️ EXIT message_handler for user {user_id} (invalid limit)")
                        return
                    
                    context.user_data["key_limit"] = limit
                    
                    # Создаем ключ
                    db = self.get_db()
                    key_value = f"sk_{secrets.token_urlsafe(32)}"
                    key_hash = hash_key(key_value)
                    
                    days = context.user_data.get("key_days", 30)
                    expires_at = datetime.utcnow() + timedelta(days=days) if days > 0 else None
                    
                    api_key = APIKey(
                        key=key_value,
                        key_hash=key_hash,
                        name=context.user_data["key_name"],
                        expires_at=expires_at,
                        search_limit=limit,
                        created_by=user_id
                    )
                    db.add(api_key)
                    db.commit()
                    db.refresh(api_key)
                    
                    text = f"✅ Ключ успешно создан!\n\n"
                    text += f"🔑 <b>Ваш API ключ:</b>\n"
                    text += f"<code>{key_value}</code>\n\n"
                    text += f"📝 Название: {api_key.name}\n"
                    if expires_at:
                        text += f"⏰ Истекает: {expires_at.strftime('%d.%m.%Y %H:%M')}\n"
                    text += f"🔍 Лимит поисков: {limit}\n\n"
                    text += "⚠️ Сохраните этот ключ, он больше не будет показан!"
                    
                    keyboard = [[InlineKeyboardButton("↩️ Меню", callback_data="menu")]]
                    reply_markup = InlineKeyboardMarkup(keyboard)
                    
                    context.user_data.clear()
                    await update.message.reply_text(text, reply_markup=reply_markup, parse_mode="HTML")
                    print(f"✅ EXIT message_handler for user {user_id} (key created)")
                    
                except ValueError:
                    await update.message.reply_text("❌ Введите корректное число")
                    print(f"⚠️ EXIT message_handler for user {user_id} (invalid number)")
            
            print(f"✅ EXIT message_handler for user {user_id}")
        except Exception as e:
            print(f"❌ ERROR in message_handler for user {user_id}: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    async def days_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработка выбора срока действия"""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        days_str = query.data.replace("days_", "")
        days = int(days_str)
        print(f"🚀 ENTER days_callback for user {user_id}, days: {days}")
        
        try:
            context.user_data["key_days"] = days
            
            context.user_data["state"] = "creating_key_limit"
            
            keyboard = [
                [InlineKeyboardButton("100", callback_data="limit_100")],
                [InlineKeyboardButton("1000", callback_data="limit_1000")],
                [InlineKeyboardButton("10000", callback_data="limit_10000")],
                [InlineKeyboardButton("Безлимит", callback_data="limit_0")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await query.edit_message_text(
                f"⏰ Срок: {days if days > 0 else 'Без ограничений'} дней\n\n"
                "🔢 Выберите лимит поисков или введите своё число:",
                reply_markup=reply_markup
            )
            
            print(f"✅ EXIT days_callback for user {user_id}")
        except Exception as e:
            print(f"❌ ERROR in days_callback for user {user_id}: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    async def limit_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработка выбора лимита"""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        limit_str = query.data.replace("limit_", "")
        limit = int(limit_str) if limit_str != "0" else None
        print(f"🚀 ENTER limit_callback for user {user_id}, limit: {limit}")
        
        try:
            context.user_data["key_limit"] = limit
            
            # Создаем ключ
            db = self.get_db()
            key_value = f"sk_{secrets.token_urlsafe(32)}"
            key_hash = hash_key(key_value)
            
            days = context.user_data.get("key_days", 30)
            expires_at = datetime.utcnow() + timedelta(days=days) if days > 0 else None
            
            api_key = APIKey(
                key=key_value,
                key_hash=key_hash,
                name=context.user_data["key_name"],
                expires_at=expires_at,
                search_limit=limit,
                created_by=query.from_user.id
            )
            db.add(api_key)
            db.commit()
            db.refresh(api_key)
            
            text = f"✅ Ключ успешно создан!\n\n"
            text += f"🔑 <b>Ваш API ключ:</b>\n"
            text += f"<code>{key_value}</code>\n\n"
            text += f"📝 Название: {api_key.name}\n"
            if expires_at:
                text += f"⏰ Истекает: {expires_at.strftime('%d.%m.%Y %H:%M')}\n"
            text += f"🔍 Лимит поисков: {limit if limit else 'Безлимит'}\n\n"
            text += "⚠️ Сохраните этот ключ, он больше не будет показан!"
            
            keyboard = [[InlineKeyboardButton("↩️ Меню", callback_data="menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            context.user_data.clear()
            await query.edit_message_text(text, reply_markup=reply_markup, parse_mode="HTML")
            
            print(f"✅ EXIT limit_callback for user {user_id}")
        except Exception as e:
            print(f"❌ ERROR in limit_callback for user {user_id}: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    async def run_async(self):
        """Асинхронный запуск бота с polling"""
        import traceback
        
        if not TELEGRAM_BOT_TOKEN:
            print("⚠️ TELEGRAM_BOT_TOKEN не установлен. Бот не запущен.")
            return
        
        try:
            print("🔧 Создание Application...")
            self.application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
            print("✅ Application создан")
            
            # Регистрация обработчиков
            print("📝 Регистрация обработчиков...")
            self.application.add_handler(CommandHandler("start", self.start_command))
            self.application.add_handler(CallbackQueryHandler(self.button_callback, pattern="^(create_key|list_keys|stats|help|menu)$"))
            self.application.add_handler(CallbackQueryHandler(self.days_callback, pattern="^days_"))
            self.application.add_handler(CallbackQueryHandler(self.limit_callback, pattern="^limit_"))
            self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.message_handler))
            print("✅ Обработчики зарегистрированы")
            
            # Запуск polling (современный метод PTB 20+)
            print("🚀 Запуск polling...")
            await self.application.run_polling(
                drop_pending_updates=True,
                allowed_updates=Update.ALL_TYPES
            )
        except asyncio.CancelledError:
            print("🛑 Polling отменен (CancelledError)")
            raise
        except Exception as e:
            print(f"❌ Ошибка в polling: {e}")
            print(f"📋 Traceback:\n{traceback.format_exc()}")
            raise
        finally:
            print("🛑 Остановка Telegram бота...")
            if self.application:
                await self.application.shutdown()
            print("✅ Telegram бот остановлен")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
