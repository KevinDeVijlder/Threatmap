"""
Authentication & User Profile API Routes
========================================
Handles user registration, login, session verification, avatar updates,
custom OSINT feed persistence, and logout.
"""

import sqlite3
from typing import Optional
from fastapi import APIRouter, Header, HTTPException

from database import (
    authenticate_user,
    create_user_and_session,
    delete_session,
    get_user_by_token,
    update_user_avatar,
    update_user_sources,
)
from models import AuthRequest, AvatarUpdateRequest, CustomSourcesUpdateRequest
from ws_manager import manager

router = APIRouter(prefix="/api", tags=["auth"])


@router.post("/register")
async def register_user(req: AuthRequest):
    username = req.username.strip()
    if len(username) < 3 or len(req.password) < 4:
        raise HTTPException(
            status_code=400, detail="Username (min 3) and password (min 4) required."
        )

    try:
        token, user = create_user_and_session(username, req.password, req.avatar or "")
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists.")

    return {"token": token, "user": user}


@router.post("/login")
async def login_user(req: AuthRequest):
    username = req.username.strip()
    result = authenticate_user(username, req.password)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token, user = result
    return {"token": token, "user": user}


@router.get("/me")
async def get_current_user(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return {"user": user}


@router.post("/profile/avatar")
async def update_avatar(
    req: AvatarUpdateRequest, authorization: Optional[str] = Header(None)
):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    update_user_avatar(user["id"], req.avatar)
    user["avatar"] = req.avatar
    return {"user": user}


@router.post("/profile/sources")
async def update_custom_sources(
    req: CustomSourcesUpdateRequest, authorization: Optional[str] = Header(None)
):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    update_user_sources(user["id"], req.custom_sources)
    manager.invalidate_user_cache(user["id"])
    user["custom_sources"] = req.custom_sources
    return {"user": user}


@router.post("/logout")
async def logout_user(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        delete_session(token)
    return {"status": "ok"}
