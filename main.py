"""
Простой backend мессенджера на FastAPI.

Этап 1: регистрация, логин, список пользователей с базой SQLite.
Запуск: `uvicorn main:app --reload`
"""

import asyncio
import hashlib
import json
import os
import secrets
import time
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Set

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, func, select
from sqlalchemy import desc, or_
from sqlalchemy import inspect
from pywebpush import webpush, WebPushException
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# --- База данных ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SQLITE = f"sqlite:///{os.path.join(BASE_DIR, 'messenger.db')}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE)
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", os.path.join(STATIC_DIR, "uploads"))
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY")
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY")
VAPID_CLAIMS = {"sub": os.getenv("VAPID_EMAIL", "mailto:example@example.com")}


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    password_hash = Column(String(128), nullable=False)
    status = Column(String(20), nullable=False, server_default="offline")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, nullable=False, index=True)
    receiver_id = Column(Integer, nullable=False, index=True)
    content = Column(Text, nullable=False)
    attachment_url = Column(Text, nullable=True)
    attachment_type = Column(String(100), nullable=True)
    attachment_name = Column(String(255), nullable=True)
    reply_to_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    read_at = Column(DateTime(timezone=True), nullable=True, index=True)


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    owner_id = Column(Integer, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class GroupMember(Base):
    __tablename__ = "group_members"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=False)
    joined_at = Column(DateTime(timezone=True), server_default=func.now())


class GroupMessage(Base):
    __tablename__ = "group_messages"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, index=True, nullable=False)
    sender_id = Column(Integer, index=True, nullable=False)
    content = Column(Text, nullable=False)
    attachment_url = Column(Text, nullable=True)
    attachment_type = Column(String(100), nullable=True)
    attachment_name = Column(String(255), nullable=True)
    reply_to_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class GroupMessageRead(Base):
    __tablename__ = "group_message_reads"

    id = Column(Integer, primary_key=True)
    message_id = Column(Integer, index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=False)
    read_at = Column(DateTime(timezone=True), server_default=func.now())


class PushSubscription(Base):
    __tablename__ = "push_subscriptions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, nullable=False)
    endpoint = Column(Text, unique=True, nullable=False)
    p256dh = Column(String(255), nullable=False)
    auth = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class CallLog(Base):
    __tablename__ = "call_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, nullable=False)
    peer_id = Column(Integer, index=True, nullable=False)
    media = Column(String(20), nullable=False)  # audio | video
    direction = Column(String(10), nullable=False)  # out | in
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class MessageReaction(Base):
    __tablename__ = "message_reactions"

    id = Column(Integer, primary_key=True)
    message_id = Column(Integer, index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=False)
    emoji = Column(String(16), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class GroupMessageReaction(Base):
    __tablename__ = "group_message_reactions"

    id = Column(Integer, primary_key=True)
    message_id = Column(Integer, index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=False)
    emoji = Column(String(16), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# --- Модели запросов/ответов ---
class RegisterRequest(BaseModel):
    username: str
    password: str


class RegisterEmailRequest(BaseModel):
    email: str
    username: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    token: str


class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    status: Optional[str] = "online"
    created_at: datetime

    class Config:
        orm_mode = True


class AdminUserOut(UserOut):
    password_hash: Optional[str] = None


class AdminResetPasswordIn(BaseModel):
    password: str


class MessageIn(BaseModel):
    receiver_id: int
    content: str


class MessageOut(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    attachment_url: Optional[str] = None
    attachment_type: Optional[str] = None
    attachment_name: Optional[str] = None
    reply_to_id: Optional[int] = None
    created_at: datetime
    read_at: Optional[datetime] = None
    reactions: List[ReactionOut] = []

    class Config:
        orm_mode = True


class CallLogCreate(BaseModel):
    peer_id: int
    media: str
    direction: str


class CallLogOut(BaseModel):
    id: int
    user_id: int
    peer_id: int
    peer_name: Optional[str] = None
    media: str
    direction: str
    created_at: datetime


class GroupCreate(BaseModel):
    name: str
    member_usernames: List[str] = []


class GroupOut(BaseModel):
    id: int
    name: str
    owner_id: int
    created_at: datetime

    class Config:
        orm_mode = True


class GroupMessageOut(BaseModel):
    id: int
    group_id: int
    sender_id: int
    content: str
    attachment_url: Optional[str] = None
    attachment_type: Optional[str] = None
    attachment_name: Optional[str] = None
    reply_to_id: Optional[int] = None
    created_at: datetime
    read_by: List[int] = []
    reactions: List[dict] = []

    class Config:
        orm_mode = True


class PushSubscriptionIn(BaseModel):
    endpoint: str
    keys: Dict[str, str]


class StatusIn(BaseModel):
    status: str


class UsernameIn(BaseModel):
    username: str


class GroupMemberOut(BaseModel):
    user_id: int
    username: str
    joined_at: datetime | None = None


class PushUnsubscribeIn(BaseModel):
    endpoint: str


class ReactionIn(BaseModel):
    emoji: str


class ReactionOut(BaseModel):
    emoji: str
    count: int
    me: bool = False


def reaction_dict_list(reactions: List[ReactionOut]) -> List[dict]:
    return [r.dict() for r in reactions]


# --- Безопасность ---
security = HTTPBearer()
# Простое хранилище активных токенов в памяти: token -> user_id
active_tokens: Dict[str, int] = {}


class ConnectionManager:
    """Отслеживаем WebSocket-подключения пользователей."""

    def __init__(self) -> None:
        self.connections: Dict[int, List[WebSocket]] = {}
        self.online_users: Set[int] = set()

    async def connect(self, user_id: int, websocket: WebSocket) -> None:
        # Закрываем старые подключения, чтобы не было дублей
        for ws in self.connections.get(user_id, []):
            try:
                await ws.close(code=1000)
            except Exception:
                pass
        await websocket.accept()
        self.connections[user_id] = [websocket]

    def disconnect(self, user_id: int, websocket: WebSocket) -> None:
        conns = self.connections.get(user_id, [])
        if websocket in conns:
            conns.remove(websocket)
        if not conns:
            self.connections.pop(user_id, None)

    async def send_to_user(self, user_id: int, message: dict) -> None:
        conns = self.connections.get(user_id, [])
        for ws in list(conns):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(user_id, ws)

    async def broadcast(self, message: dict) -> None:
        # Рассылаем всем активным подключениям
        for uid in list(self.connections.keys()):
            await self.send_to_user(uid, message)

    def get_online_ids(self) -> List[int]:
        return list(self.online_users)

    async def ensure_online(self, user_id: int) -> None:
        if user_id not in self.online_users:
            self.online_users.add(user_id)
            await self.broadcast({"type": "user_online", "user_id": user_id})


manager = ConnectionManager()


def hash_password(password: str) -> str:
    """Генерация hash с солью (pbkdf2)."""
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{salt.hex()}${hashed.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return secrets.compare_digest(candidate, expected)


def create_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    active_tokens[token] = user_id
    return token


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials
    user_id = active_tokens.get(token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_admin(credentials: HTTPAuthorizationCredentials = Depends(security)) -> None:
    if not ADMIN_TOKEN or credentials.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin token required")


async def get_user_by_token(token: str, db: Session) -> User | None:
    user_id = active_tokens.get(token)
    if not user_id:
        return None
    return db.get(User, user_id)


def push_enabled() -> bool:
    return bool(VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY)


def smtp_enabled() -> bool:
    return all(
        [
            os.getenv("SMTP_HOST"),
            os.getenv("SMTP_PORT"),
            os.getenv("SMTP_USER"),
            os.getenv("SMTP_PASSWORD"),
            os.getenv("SMTP_FROM"),
        ]
    )


async def send_push_to_user(user_id: int, title: str, body: str, db: Session) -> None:
    if not push_enabled():
        return
    subs = (
        db.execute(select(PushSubscription).where(PushSubscription.user_id == user_id))
        .scalars()
        .all()
    )
    for sub in subs:
        payload = {"title": title, "body": body}
        try:
            await asyncio.to_thread(
                webpush,
                subscription_info={
                    "endpoint": sub.endpoint,
                    "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
                },
                data=json.dumps(payload),
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=VAPID_CLAIMS,
            )
        except WebPushException:
            # Если пуш не доставился, удалим подписку
            db.delete(sub)
            db.commit()


# --- Приложение ---
app = FastAPI(title="Simple Messenger")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
# Отдельный маунт для загрузок (может лежать вне static)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


@app.on_event("startup")
def on_startup() -> None:
    # Создаем таблицы при запуске (для демо)
    os.makedirs(STATIC_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    # Добавляем read_at в messages, если нет
    inspector = inspect(engine)
    cols = [c["name"] for c in inspector.get_columns("messages")]
    if "read_at" not in cols:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN read_at TIMESTAMP")
    if "attachment_url" not in cols:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN attachment_url TEXT")
    if "attachment_type" not in cols:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN attachment_type VARCHAR(100)")
    if "attachment_name" not in cols:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN attachment_name VARCHAR(255)")
    if "reply_to_id" not in cols:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN reply_to_id INTEGER")
    user_cols = [c["name"] for c in inspector.get_columns("users")]
    if "status" not in user_cols:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT 'offline'")
    if "email" not in user_cols:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN email VARCHAR(255)")
    # Создаем таблицу group_message_reads, если отсутствует
    if "group_message_reads" not in inspector.get_table_names():
        GroupMessageRead.__table__.create(bind=engine)
    if "push_subscriptions" not in inspector.get_table_names():
        PushSubscription.__table__.create(bind=engine)
    if "verify_codes" not in inspector.get_table_names():
        VerifyCode.__table__.create(bind=engine)
    cols_group = [c["name"] for c in inspector.get_columns("group_messages")]
    if "attachment_url" not in cols_group:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE group_messages ADD COLUMN attachment_url TEXT")
    if "attachment_type" not in cols_group:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE group_messages ADD COLUMN attachment_type VARCHAR(100)")
    if "attachment_name" not in cols_group:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE group_messages ADD COLUMN attachment_name VARCHAR(255)")
    if "reply_to_id" not in cols_group:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE group_messages ADD COLUMN reply_to_id INTEGER")
    # создаём таблицы реакций, если отсутствуют
    if "message_reactions" not in inspector.get_table_names():
        MessageReaction.__table__.create(bind=engine)
    if "group_message_reactions" not in inspector.get_table_names():
        GroupMessageReaction.__table__.create(bind=engine)


@app.get("/", response_class=FileResponse)
def root():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return FileResponse(os.devnull)


@app.head("/")
def root_head():
    return {"status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/admin", response_class=FileResponse)
def admin_page():
    admin_html = os.path.join(STATIC_DIR, "admin.html")
    if os.path.exists(admin_html):
        return FileResponse(admin_html)
    return {"detail": "Admin page not found"}


@app.get("/push/public_key")
def push_public_key():
    return {"publicKey": VAPID_PUBLIC_KEY or ""}


@app.post("/push/subscribe")
def push_subscribe(
    payload: PushSubscriptionIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not push_enabled():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Push not configured")
    endpoint = payload.endpoint
    p256dh = payload.keys.get("p256dh")
    auth_key = payload.keys.get("auth")
    if not endpoint or not p256dh or not auth_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid subscription")
    existing = (
        db.execute(select(PushSubscription).where(PushSubscription.endpoint == endpoint))
        .scalar_one_or_none()
    )
    if existing:
        existing.user_id = current_user.id
        existing.p256dh = p256dh
        existing.auth = auth_key
    else:
        db.add(
            PushSubscription(
                user_id=current_user.id,
                endpoint=endpoint,
                p256dh=p256dh,
                auth=auth_key,
            )
        )
    db.commit()
    return {"status": "ok"}


@app.post("/push/unsubscribe")
def push_unsubscribe(
    payload: PushUnsubscribeIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db.query(PushSubscription).filter(
        PushSubscription.endpoint == payload.endpoint, PushSubscription.user_id == current_user.id
    ).delete()
    db.commit()
    return {"status": "removed"}


@app.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    user = User(username=payload.username, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    # Уведомляем всех онлайн-пользователей о новом участнике
    await manager.broadcast(
        {
            "type": "user_created",
            "user": {
                "id": user.id,
                "username": user.username,
                "status": user.status,
                "created_at": user.created_at.isoformat(),
            },
        }
    )
    return user


def send_email_code(email: str, code: str) -> None:
    import smtplib
    from email.mime.text import MIMEText

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM", user)

    msg = MIMEText(f"Ваш код для входа в Messenger: {code}")
    msg["Subject"] = "Код подтверждения"
    msg["From"] = sender
    msg["To"] = email

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, password)
        server.send_message(msg)


def generate_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


@app.post("/register_email")
async def register_email(payload: RegisterEmailRequest, db: Session = Depends(get_db)):
    if not smtp_enabled():
        raise HTTPException(status_code=400, detail="SMTP not configured")
    email = (payload.email or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    # создаём код и отправляем
    code = generate_code()
    db.add(VerifyCode(email=email, code=code))
    db.commit()
    try:
        await asyncio.to_thread(send_email_code, email, code)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email failed: {e}")
    return {"sent": True}


class VerifyEmailIn(BaseModel):
    email: str
    code: str
    username: Optional[str] = None


@app.post("/verify_email", response_model=TokenResponse)
async def verify_email(payload: VerifyEmailIn, db: Session = Depends(get_db)):
    email = (payload.email or "").strip().lower()
    code = (payload.code or "").strip()
    if not email or not code:
        raise HTTPException(status_code=400, detail="Email and code required")
    rec = (
        db.execute(
            select(VerifyCode)
            .where(VerifyCode.email == email, VerifyCode.code == code, VerifyCode.used_at.is_(None))
            .order_by(VerifyCode.id.desc())
        )
        .scalar_one_or_none()
    )
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid code")
    # отмечаем использованным
    rec.used_at = datetime.utcnow()
    # ищем пользователя
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        username = payload.username.strip() if payload.username else email.split("@")[0]
        # гарантируем уникальность имени
        base = username
        i = 1
        while db.execute(select(User).where(User.username == username)).scalar_one_or_none():
            username = f"{base}{i}"
            i += 1
        user = User(username=username, email=email, password_hash=hash_password(secrets.token_urlsafe(12)))
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        db.commit()
    token = create_token(user.id)
    return TokenResponse(token=token)


@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    name = (payload.username or "").strip()
    user = db.execute(
        select(User).where(or_(User.username == name, User.email == name))
    ).scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_token(user.id)
    return TokenResponse(token=token)


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    """Загрузка вложений. Возвращает относительную ссылку для вставки в сообщение."""
    upload_dir = UPLOAD_DIR
    os.makedirs(upload_dir, exist_ok=True)
    filename = file.filename or "file"
    ext = os.path.splitext(filename)[1]
    safe_name = f"{int(time.time()*1000)}_{secrets.token_hex(4)}{ext}"
    dest_path = os.path.join(upload_dir, safe_name)
    with open(dest_path, "wb") as out:
        shutil.copyfileobj(file.file, out)

    # Отдаём через маунт /uploads, чтобы работало и при внешнем пути
    url = f"/uploads/{safe_name}"
    return {
        "url": url,
        "content_type": file.content_type or "application/octet-stream",
        "name": filename,
        "size": os.path.getsize(dest_path),
    }


@app.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/users", response_model=List[UserOut])
def list_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.execute(select(User).order_by(User.id)).scalars().all()
    return users


def build_reaction_map(
    reactions: List[tuple[int, int, str]],
    current_user_id: int,
) -> Dict[int, List[ReactionOut]]:
    result: Dict[int, Dict[str, ReactionOut]] = {}
    for msg_id, user_id, emoji in reactions:
        if msg_id not in result:
            result[msg_id] = {}
        bucket = result[msg_id]
        if emoji not in bucket:
            bucket[emoji] = ReactionOut(emoji=emoji, count=0, me=False)
        bucket[emoji].count += 1
        if user_id == current_user_id:
            bucket[emoji].me = True
    # convert to list
    return {mid: list(b.values()) for mid, b in result.items()}


@app.post("/status")
async def set_status(
    payload: StatusIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    value = (payload.status or "").strip().lower()
    allowed = {"online", "chat", "dnd", "offline"}
    if value not in allowed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bad status")
    current_user.status = value
    db.commit()
    await manager.broadcast({"type": "status", "user_id": current_user.id, "status": value})
    return {"status": value}


@app.post("/calls", response_model=CallLogOut)
def log_call(
    payload: CallLogCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    media = (payload.media or "").lower()
    direction = (payload.direction or "").lower()
    if media not in {"audio", "video"}:
        raise HTTPException(status_code=400, detail="Bad media")
    if direction not in {"out", "in", "missed"}:
        raise HTTPException(status_code=400, detail="Bad direction")
    peer = db.get(User, payload.peer_id)
    entry = CallLog(
        user_id=current_user.id,
        peer_id=payload.peer_id,
        media=media,
        direction=direction,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return CallLogOut(
        id=entry.id,
        user_id=entry.user_id,
        peer_id=entry.peer_id,
        peer_name=peer.username if peer else None,
        media=entry.media,
        direction=entry.direction,
        created_at=entry.created_at,
    )


@app.get("/calls", response_model=List[CallLogOut])
def list_calls(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.execute(
            select(CallLog)
            .where(CallLog.user_id == current_user.id)
            .order_by(desc(CallLog.created_at))
            .limit(200)
        )
        .scalars()
        .all()
    )
    peer_ids = {row.peer_id for row in rows}
    peers = (
        db.execute(select(User.id, User.username).where(User.id.in_(peer_ids)))
        .all()
        if peer_ids
        else []
    )
    peer_map = {pid: uname for pid, uname in peers}
    return [
        CallLogOut(
            id=row.id,
            user_id=row.user_id,
            peer_id=row.peer_id,
            peer_name=peer_map.get(row.peer_id),
            media=row.media,
            direction=row.direction,
            created_at=row.created_at,
        )
        for row in rows
    ]


@app.post("/username")
async def change_username(
    payload: UsernameIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    new_name = (payload.username or "").strip()
    if not new_name or len(new_name) < 2:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bad username")
    existing = db.execute(select(User).where(User.username == new_name)).scalar_one_or_none()
    if existing and existing.id != current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    current_user.username = new_name
    db.commit()
    await manager.broadcast({"type": "user_renamed", "user_id": current_user.id, "username": new_name})
    return {"username": new_name}


# --- Админ API ---
@app.get("/admin/users", response_model=List[AdminUserOut])
def admin_list_users(
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return db.execute(select(User).order_by(User.id)).scalars().all()


@app.post("/admin/users", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED)
def admin_create_user(
    payload: RegisterRequest,
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    existing = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    user = User(username=payload.username, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_user(
    user_id: int,
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    # Удаляем связанные сущности
    db.query(Message).filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).delete()
    db.query(GroupMember).filter(GroupMember.user_id == user_id).delete()
    db.query(GroupMessageRead).filter(GroupMessageRead.user_id == user_id).delete()
    db.query(GroupMessage).filter(GroupMessage.sender_id == user_id).delete()
    db.query(PushSubscription).filter(PushSubscription.user_id == user_id).delete()
    # Удаляем группы, где он владелец
    owned_groups = db.execute(select(Group.id).where(Group.owner_id == user_id)).scalars().all()
    for gid in owned_groups:
        db.query(GroupMessage).filter(GroupMessage.group_id == gid).delete()
        db.query(GroupMember).filter(GroupMember.group_id == gid).delete()
        db.query(Group).filter(Group.id == gid).delete()
    db.delete(user)
    db.commit()


@app.post("/admin/users/{user_id}/reset_password", response_model=AdminUserOut)
def admin_reset_password(
    user_id: int,
    payload: AdminResetPasswordIn,
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    new_pwd = (payload.password or "").strip()
    if len(new_pwd) < 4:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password too short")
    user.password_hash = hash_password(new_pwd)
    db.commit()
    db.refresh(user)
    return user
    return None


@app.get("/admin/messages", response_model=List[MessageOut])
def admin_messages(
    limit: int = 200,
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    msgs = (
        db.execute(select(Message).order_by(Message.id.desc()).limit(limit))
        .scalars()
        .all()
    )
    return list(msgs)


@app.get("/admin/group_messages", response_model=List[GroupMessageOut])
def admin_group_messages(
    limit: int = 200,
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    msgs = (
        db.execute(select(GroupMessage).order_by(GroupMessage.id.desc()).limit(limit))
        .scalars()
        .all()
    )
    # Добавим read_by
    ids = [m.id for m in msgs]
    read_map = {}
    if ids:
        reads = db.execute(
            select(GroupMessageRead.message_id, GroupMessageRead.user_id).where(
                GroupMessageRead.message_id.in_(ids)
            )
        ).all()
        for mid, uid in reads:
            read_map.setdefault(mid, []).append(uid)
    for m in msgs:
        m.read_by = read_map.get(m.id, [])
    return list(msgs)


@app.delete("/admin/messages/{msg_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_message(
    msg_id: int,
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    deleted = db.query(Message).filter(Message.id == msg_id).delete()
    db.commit()
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return None


@app.delete("/admin/group_messages/{msg_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_group_message(
    msg_id: int,
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db.query(GroupMessageRead).filter(GroupMessageRead.message_id == msg_id).delete()
    deleted = db.query(GroupMessage).filter(GroupMessage.id == msg_id).delete()
    db.commit()
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return None


@app.get("/messages/{peer_id}", response_model=List[MessageOut])
def history(
    peer_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50,
):
    stmt = (
        select(Message)
        .where(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == peer_id))
            | ((Message.sender_id == peer_id) & (Message.receiver_id == current_user.id))
        )
        .order_by(Message.id.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).scalars().all()
    # реакции
    ids = [m.id for m in rows]
    if ids:
        reaction_rows = db.execute(
            select(MessageReaction.message_id, MessageReaction.user_id, MessageReaction.emoji).where(
                MessageReaction.message_id.in_(ids)
            )
        ).all()
        reaction_map = build_reaction_map(reaction_rows, current_user.id)
        for m in rows:
            m.reactions = reaction_map.get(m.id, [])
    # Вернём в обратном порядке, чтобы шло по времени
    return list(reversed(rows))


@app.post("/messages/{peer_id}/read")
async def mark_read(
    peer_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Отмечаем все входящие для текущего пользователя как прочитанные
    stmt = (
        select(Message).where(
            Message.sender_id == peer_id,
            Message.receiver_id == current_user.id,
            Message.read_at.is_(None),
        )
    )
    to_mark = db.execute(stmt).scalars().all()
    now = datetime.utcnow()
    ids: list[int] = []
    for m in to_mark:
        m.read_at = now
        ids.append(m.id)
    if ids:
        db.commit()
        # Уведомляем собеседника
        payload = {"type": "message_read", "message_ids": ids, "peer_id": current_user.id}
        await manager.send_to_user(peer_id, payload)
    return {"marked": len(ids)}


@app.post("/groups", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: GroupCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    group_name = payload.name.strip()
    if not group_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group name required")

    # Ищем пользователей по username
    member_names = [n.strip() for n in payload.member_usernames if n.strip()]
    members = []
    if member_names:
        rows = db.execute(select(User).where(User.username.in_(member_names))).scalars().all()
        found = {u.username for u in rows}
        missing = [n for n in member_names if n not in found]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Users not found: {', '.join(missing)}",
            )
        members = [u.id for u in rows]

    group = Group(name=group_name, owner_id=current_user.id)
    db.add(group)
    db.commit()
    db.refresh(group)

    # Добавляем владельца и приглашенных
    member_ids = set(members + [current_user.id])
    for uid in member_ids:
        db.add(GroupMember(group_id=group.id, user_id=uid))
    db.commit()
    # Рассылаем онлайн-участникам уведомление о новой группе
    payload_out = {
        "type": "group_created",
        "group": {
            "id": group.id,
            "name": group.name,
            "owner_id": group.owner_id,
            "created_at": group.created_at.isoformat(),
        },
    }
    for uid in member_ids:
        await manager.send_to_user(uid, payload_out)
    return group


@app.get("/groups", response_model=List[GroupOut])
def my_groups(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    stmt = (
        select(Group)
        .join(GroupMember, GroupMember.group_id == Group.id)
        .where(GroupMember.user_id == current_user.id)
        .order_by(Group.id)
    )
    groups = db.execute(stmt).scalars().all()
    return groups


@app.get("/groups/{group_id}/members", response_model=List[GroupMemberOut])
def group_members(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # проверка участия
    member = (
        db.execute(
            select(GroupMember).where(
                GroupMember.group_id == group_id, GroupMember.user_id == current_user.id
            )
        )
        .scalar_one_or_none()
    )
    if not member:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not in group")

    stmt = (
        select(GroupMember.user_id, User.username, GroupMember.joined_at)
        .join(User, User.id == GroupMember.user_id)
        .where(GroupMember.group_id == group_id)
        .order_by(User.username)
    )
    rows = db.execute(stmt).all()
    return [
        GroupMemberOut(user_id=r.user_id, username=r.username, joined_at=r.joined_at)
        for r in rows
    ]


@app.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    group = db.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    if group.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only owner can delete")

    # Получаем участников для уведомления
    member_ids = (
        db.execute(select(GroupMember.user_id).where(GroupMember.group_id == group_id))
        .scalars()
        .all()
    )
    # Удаляем сообщения, участников, группу
    db.query(GroupMessage).filter(GroupMessage.group_id == group_id).delete()
    db.query(GroupMember).filter(GroupMember.group_id == group_id).delete()
    db.delete(group)
    db.commit()

    payload = {"type": "group_deleted", "group_id": group_id}
    for uid in member_ids:
        await manager.send_to_user(uid, payload)
    return None


@app.get("/group_messages/{group_id}", response_model=List[GroupMessageOut])
def group_history(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50,
):
    # проверим участие
    member = (
        db.execute(
            select(GroupMember).where(
                GroupMember.group_id == group_id, GroupMember.user_id == current_user.id
            )
        )
        .scalar_one_or_none()
    )
    if not member:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not in group")

    stmt = (
        select(GroupMessage)
        .where(GroupMessage.group_id == group_id)
        .order_by(GroupMessage.id.desc())
        .limit(limit)
    )
    msgs = db.execute(stmt).scalars().all()
    # добавим read_by для сообщений текущего пользователя
    ids = [m.id for m in msgs]
    read_map = {}
    reaction_map: Dict[int, List[ReactionOut]] = {}
    if ids:
        reads = db.execute(
            select(GroupMessageRead.message_id, GroupMessageRead.user_id).where(
                GroupMessageRead.message_id.in_(ids)
            )
        ).all()
        for mid, uid in reads:
            read_map.setdefault(mid, []).append(uid)
        reaction_rows = db.execute(
            select(GroupMessageReaction.message_id, GroupMessageReaction.user_id, GroupMessageReaction.emoji).where(
                GroupMessageReaction.message_id.in_(ids)
            )
        ).all()
        reaction_map = build_reaction_map(reaction_rows, current_user.id)
    for m in msgs:
        m.read_by = read_map.get(m.id, [])
        m.reactions = reaction_map.get(m.id, [])
    return list(reversed(msgs))


@app.post("/group_messages/{group_id}/read")
async def group_mark_read(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Проверяем участие
    member = (
        db.execute(
            select(GroupMember).where(
                GroupMember.group_id == group_id, GroupMember.user_id == current_user.id
            )
        )
        .scalar_one_or_none()
    )
    if not member:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not in group")

    # Находим непрочитанные сообщения группы (не свои)
    msgs = db.execute(
        select(GroupMessage.id, GroupMessage.sender_id)
        .where(
            GroupMessage.group_id == group_id,
            GroupMessage.sender_id != current_user.id,
        )
    ).all()
    to_mark = []
    for mid, sender_id in msgs:
        exists = db.execute(
            select(GroupMessageRead).where(
                GroupMessageRead.message_id == mid, GroupMessageRead.user_id == current_user.id
            )
        ).scalar_one_or_none()
        if not exists:
            to_mark.append((mid, sender_id))

    if not to_mark:
        return {"marked": 0}

    now = datetime.utcnow()
    for mid, _ in to_mark:
        db.add(GroupMessageRead(message_id=mid, user_id=current_user.id, read_at=now))
    db.commit()

    # Оповещаем авторов сообщений
    for mid, sender_id in to_mark:
        await manager.send_to_user(
            sender_id,
            {
                "type": "group_message_read",
                "group_id": group_id,
                "message_ids": [mid],
                "reader_id": current_user.id,
            },
        )
        await send_push_to_user(
            sender_id,
            f"Сообщение прочитано",
            f"{current_user.username} прочитал(а) сообщение в группе",
            db,
        )
    return {"marked": len(to_mark)}


def build_reactions_for_message(db: Session, message_id: int, current_user_id: int) -> List[ReactionOut]:
    rows = db.execute(
        select(MessageReaction.user_id, MessageReaction.emoji).where(MessageReaction.message_id == message_id)
    ).all()
    tmp: Dict[str, ReactionOut] = {}
    for uid, emoji in rows:
        if emoji not in tmp:
            tmp[emoji] = ReactionOut(emoji=emoji, count=0, me=False)
        tmp[emoji].count += 1
        if uid == current_user_id:
            tmp[emoji].me = True
    return list(tmp.values())


def build_reactions_for_group_message(db: Session, message_id: int, current_user_id: int) -> List[ReactionOut]:
    rows = db.execute(
        select(GroupMessageReaction.user_id, GroupMessageReaction.emoji).where(GroupMessageReaction.message_id == message_id)
    ).all()
    tmp: Dict[str, ReactionOut] = {}
    for uid, emoji in rows:
        if emoji not in tmp:
            tmp[emoji] = ReactionOut(emoji=emoji, count=0, me=False)
        tmp[emoji].count += 1
        if uid == current_user_id:
            tmp[emoji].me = True
    return list(tmp.values())


@app.post("/messages/{message_id}/react", response_model=List[ReactionOut])
async def react_message(
    message_id: int,
    payload: ReactionIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    emoji = (payload.emoji or "").strip()
    if not emoji:
        raise HTTPException(status_code=400, detail="Emoji required")
    msg = db.get(Message, message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Not found")
    if current_user.id not in (msg.sender_id, msg.receiver_id):
        raise HTTPException(status_code=403, detail="Forbidden")

    existing = (
        db.execute(
            select(MessageReaction).where(
                MessageReaction.message_id == message_id, MessageReaction.user_id == current_user.id
            )
        )
        .scalar_one_or_none()
    )
    if existing and existing.emoji == emoji:
        db.delete(existing)
    else:
        if existing:
            db.delete(existing)
        db.add(MessageReaction(message_id=message_id, user_id=current_user.id, emoji=emoji))
    db.commit()

    reactions = build_reactions_for_message(db, message_id, current_user.id)
    payload_ws = {
        "type": "reaction",
        "message_id": message_id,
        "reactions": reaction_dict_list(reactions),
    }
    await manager.send_to_user(msg.sender_id, payload_ws)
    if msg.receiver_id != msg.sender_id:
        await manager.send_to_user(msg.receiver_id, payload_ws)
    return reactions


@app.post("/group_messages/{message_id}/react", response_model=List[ReactionOut])
async def react_group_message(
    message_id: int,
    payload: ReactionIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    emoji = (payload.emoji or "").strip()
    if not emoji:
        raise HTTPException(status_code=400, detail="Emoji required")
    msg = db.get(GroupMessage, message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Not found")
    member = (
        db.execute(
            select(GroupMember).where(
                GroupMember.group_id == msg.group_id, GroupMember.user_id == current_user.id
            )
        )
        .scalar_one_or_none()
    )
    if not member:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not in group")

    existing = (
        db.execute(
            select(GroupMessageReaction).where(
                GroupMessageReaction.message_id == message_id, GroupMessageReaction.user_id == current_user.id
            )
        )
        .scalar_one_or_none()
    )
    if existing and existing.emoji == emoji:
        db.delete(existing)
    else:
        if existing:
            db.delete(existing)
        db.add(GroupMessageReaction(message_id=message_id, user_id=current_user.id, emoji=emoji))
    db.commit()

    reactions = build_reactions_for_group_message(db, message_id, current_user.id)
    payload_ws = {
        "type": "group_reaction",
        "group_id": msg.group_id,
        "message_id": message_id,
        "reactions": reaction_dict_list(reactions),
    }
    await manager.broadcast(payload_ws)
    return reactions


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    db = SessionLocal()
    try:
        user = await get_user_by_token(token, db)
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await manager.connect(user.id, websocket)
        # Отправим приветствие
        manager.online_users.add(user.id)
        await websocket.send_json(
            {
                "type": "welcome",
                "user_id": user.id,
                "online_ids": manager.get_online_ids(),
            }
        )
        await manager.broadcast({"type": "user_online", "user_id": user.id})

        while True:
            data = await websocket.receive_json()
            # WebRTC-сигнальные события не храним в БД, просто ретранслируем
            if data.get("type") == "signal":
                receiver_id = int(data.get("receiver_id", 0))
                if not receiver_id:
                    await websocket.send_json({"type": "error", "message": "receiver_id required"})
                    continue
                signal_payload = {
                    "type": "signal",
                    "signal_type": data.get("signal_type"),
                    "sender_id": user.id,
                    "receiver_id": receiver_id,
                    "sdp": data.get("sdp"),
                    "candidate": data.get("candidate"),
                    "media": data.get("media"),
                }
                await manager.send_to_user(receiver_id, signal_payload)
                continue

            if data.get("type") == "ping":
                await manager.ensure_online(user.id)
                await websocket.send_json({"type": "pong"})
                continue

            if data.get("type") == "typing":
                receiver_id = int(data.get("receiver_id", 0))
                if not receiver_id:
                    await websocket.send_json({"type": "error", "message": "receiver_id required"})
                    continue
                typing_payload = {
                    "type": "typing",
                    "sender_id": user.id,
                    "receiver_id": receiver_id,
                    "is_typing": bool(data.get("is_typing")),
                }
                await manager.send_to_user(receiver_id, typing_payload)
                continue

            if data.get("type") == "message_read":
                ids = data.get("message_ids") or []
                if not ids:
                    continue
                # обновим read_at
                now = datetime.utcnow()
                msg_rows = db.execute(
                    select(Message).where(
                        Message.id.in_(ids),
                        Message.sender_id == user.id,
                    )
                ).scalars().all()
                for m in msg_rows:
                    m.read_at = now
                db.commit()
                continue

            # Групповые сообщения
            if data.get("type") == "group_message":
                group_id = int(data.get("group_id", 0))
                content = (data.get("content") or "").strip()
                attachment_url = data.get("attachment_url")
                attachment_type = data.get("attachment_type")
                attachment_name = data.get("attachment_name")
                reply_to_id = data.get("reply_to_id")
                if not group_id or (not content and not attachment_url):
                    await websocket.send_json({"type": "error", "message": "group_id and content required"})
                    continue
                # Проверка участия
                member = (
                    db.execute(
                        select(GroupMember).where(
                            GroupMember.group_id == group_id, GroupMember.user_id == user.id
                        )
                    )
                    .scalar_one_or_none()
                )
                if not member:
                    await websocket.send_json({"type": "error", "message": "Not in group"})
                    continue

                gmsg = GroupMessage(
                    group_id=group_id,
                    sender_id=user.id,
                    content=content or "",
                    attachment_url=attachment_url,
                    attachment_type=attachment_type,
                    attachment_name=attachment_name,
                    reply_to_id=reply_to_id,
                )
                db.add(gmsg)
                db.commit()
                db.refresh(gmsg)

                payload = {
                    "type": "group_message",
                    "id": gmsg.id,
                    "group_id": gmsg.group_id,
                    "sender_id": gmsg.sender_id,
                    "content": gmsg.content,
                    "attachment_url": gmsg.attachment_url,
                    "attachment_type": gmsg.attachment_type,
                    "attachment_name": gmsg.attachment_name,
                    "reply_to_id": gmsg.reply_to_id,
                    "created_at": gmsg.created_at.isoformat(),
                    "read_by": [],
                }
                # Рассылаем всем участникам группы, кто онлайн
                member_ids = (
                    db.execute(select(GroupMember.user_id).where(GroupMember.group_id == group_id))
                    .scalars()
                    .all()
                )
                for uid in member_ids:
                    await manager.send_to_user(uid, payload)
                    if uid != user.id:
                        await send_push_to_user(
                            uid,
                            user.username,
                            gmsg.content or (gmsg.attachment_name or "Вложение"),
                            db,
                        )
                continue
            if data.get("type") == "group_typing":
                group_id = int(data.get("group_id", 0))
                is_typing = bool(data.get("is_typing"))
                if not group_id:
                    await websocket.send_json({"type": "error", "message": "group_id required"})
                    continue
                member_ids = (
                    db.execute(select(GroupMember.user_id).where(GroupMember.group_id == group_id))
                    .scalars()
                    .all()
                )
                for uid in member_ids:
                    if uid == user.id:
                        continue
                    await manager.send_to_user(
                        uid,
                        {"type": "group_typing", "group_id": group_id, "sender_id": user.id, "is_typing": is_typing},
                    )
                continue

            # Обычные сообщения чата сохраняем
            receiver_id = int(data.get("receiver_id", 0))
            content = (data.get("content") or "").strip()
            attachment_url = data.get("attachment_url")
            attachment_type = data.get("attachment_type")
            attachment_name = data.get("attachment_name")
            reply_to_id = data.get("reply_to_id")
            if not receiver_id or (not content and not attachment_url):
                await websocket.send_json({"type": "error", "message": "receiver_id and content required"})
                continue

            msg = Message(
                sender_id=user.id,
                receiver_id=receiver_id,
                content=content or "",
                attachment_url=attachment_url,
                attachment_type=attachment_type,
                attachment_name=attachment_name,
                reply_to_id=reply_to_id,
            )
            db.add(msg)
            db.commit()
            db.refresh(msg)

            payload = {
                "type": "message",
                "id": msg.id,
                "sender_id": msg.sender_id,
                "receiver_id": msg.receiver_id,
                "content": msg.content,
                "attachment_url": msg.attachment_url,
                "attachment_type": msg.attachment_type,
                "attachment_name": msg.attachment_name,
                "reply_to_id": msg.reply_to_id,
                "created_at": msg.created_at.isoformat(),
            }
            # Отправляем: если чат с самим собой — один раз, иначе себе и получателю
            if receiver_id == user.id:
                await manager.send_to_user(user.id, payload)
            else:
                await manager.send_to_user(user.id, payload)
                await manager.send_to_user(receiver_id, payload)
                await send_push_to_user(
                    receiver_id,
                    user.username,
                    msg.content or (msg.attachment_name or "Вложение"),
                    db,
                )
    except WebSocketDisconnect:
        manager.disconnect(user.id if "user" in locals() else 0, websocket)
        if "user" in locals():
            if not manager.connections.get(user.id):
                manager.online_users.discard(user.id)
                asyncio.create_task(manager.broadcast({"type": "user_offline", "user_id": user.id}))
    finally:
        db.close()
class VerifyCode(Base):
    __tablename__ = "verify_codes"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), index=True, nullable=False)
    code = Column(String(10), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    used_at = Column(DateTime(timezone=True), nullable=True)
