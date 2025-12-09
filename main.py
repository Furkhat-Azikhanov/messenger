"""
Простой backend мессенджера на FastAPI.

Этап 1: регистрация, логин, список пользователей с базой SQLite.
Запуск: `uvicorn main:app --reload`
"""

import asyncio
import hashlib
import os
import secrets
from datetime import datetime
from typing import Dict, List, Optional, Set

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, func, select
from sqlalchemy import inspect
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# --- База данных ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'messenger.db')}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
STATIC_DIR = os.path.join(BASE_DIR, "static")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, nullable=False, index=True)
    receiver_id = Column(Integer, nullable=False, index=True)
    content = Column(Text, nullable=False)
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# --- Модели запросов/ответов ---
class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    token: str


class UserOut(BaseModel):
    id: int
    username: str
    created_at: datetime

    class Config:
        orm_mode = True


class MessageIn(BaseModel):
    receiver_id: int
    content: str


class MessageOut(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    created_at: datetime
    read_at: Optional[datetime] = None

    class Config:
        orm_mode = True


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
    created_at: datetime

    class Config:
        orm_mode = True


class GroupMemberOut(BaseModel):
    user_id: int
    username: str
    joined_at: datetime | None = None


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


async def get_user_by_token(token: str, db: Session) -> User | None:
    user_id = active_tokens.get(token)
    if not user_id:
        return None
    return db.get(User, user_id)


# --- Приложение ---
app = FastAPI(title="Simple Messenger")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def on_startup() -> None:
    # Создаем таблицы при запуске (для демо)
    os.makedirs(STATIC_DIR, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    # Добавляем read_at в messages, если нет
    inspector = inspect(engine)
    cols = [c["name"] for c in inspector.get_columns("messages")]
    if "read_at" not in cols:
        with engine.connect() as conn:
            conn.exec_driver_sql("ALTER TABLE messages ADD COLUMN read_at TIMESTAMP")


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


@app.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    user = User(username=payload.username, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    # Уведомляем всех онлайн-пользователей о новом участнике
    try:
        asyncio.create_task(
            manager.broadcast(
                {
                    "type": "user_created",
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "created_at": user.created_at.isoformat(),
                    },
                }
            )
        )
    except RuntimeError:
        # Нет активного loop (например, в тестах) — пропускаем
        pass
    return user


@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_token(user.id)
    return TokenResponse(token=token)


@app.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/users", response_model=List[UserOut])
def list_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.execute(select(User).order_by(User.id)).scalars().all()
    return users


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
    return list(reversed(msgs))


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
                if not group_id or not content:
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

                gmsg = GroupMessage(group_id=group_id, sender_id=user.id, content=content)
                db.add(gmsg)
                db.commit()
                db.refresh(gmsg)

                payload = {
                    "type": "group_message",
                    "id": gmsg.id,
                    "group_id": gmsg.group_id,
                    "sender_id": gmsg.sender_id,
                    "content": gmsg.content,
                    "created_at": gmsg.created_at.isoformat(),
                }
                # Рассылаем всем участникам группы, кто онлайн
                member_ids = (
                    db.execute(select(GroupMember.user_id).where(GroupMember.group_id == group_id))
                    .scalars()
                    .all()
                )
                for uid in member_ids:
                    await manager.send_to_user(uid, payload)
                continue

            # Обычные сообщения чата сохраняем
            receiver_id = int(data.get("receiver_id", 0))
            content = (data.get("content") or "").strip()
            if not receiver_id or not content:
                await websocket.send_json({"type": "error", "message": "receiver_id and content required"})
                continue

            msg = Message(sender_id=user.id, receiver_id=receiver_id, content=content)
            db.add(msg)
            db.commit()
            db.refresh(msg)

            payload = {
                "type": "message",
                "id": msg.id,
                "sender_id": msg.sender_id,
                "receiver_id": msg.receiver_id,
                "content": msg.content,
                "created_at": msg.created_at.isoformat(),
            }
            # Отправляем: если чат с самим собой — один раз, иначе себе и получателю
            if receiver_id == user.id:
                await manager.send_to_user(user.id, payload)
            else:
                await manager.send_to_user(user.id, payload)
                await manager.send_to_user(receiver_id, payload)
    except WebSocketDisconnect:
        manager.disconnect(user.id if "user" in locals() else 0, websocket)
        if "user" in locals():
            if not manager.connections.get(user.id):
                manager.online_users.discard(user.id)
                asyncio.create_task(manager.broadcast({"type": "user_offline", "user_id": user.id}))
    finally:
        db.close()
