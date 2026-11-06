"""
Authentication, User Profile & Asset Configuration API Routes
=============================================================
Handles user registration, login, session verification, avatar updates,
custom OSINT feed persistence, monitored map location persistence,
and on-demand IP geolocation lookup.
"""

import sqlite3
from typing import Optional
import httpx
from fastapi import APIRouter, Header, HTTPException

from config import IPV4_REGEX, OSINT_USER_AGENT
from database import (
    authenticate_user,
    create_user_and_session,
    delete_session,
    get_user_by_token,
    update_user_avatar,
    update_user_locations,
    update_user_password,
    update_user_sources,
)
from models import (
    AuthRequest,
    AvatarUpdateRequest,
    CustomLocationsUpdateRequest,
    CustomSourcesUpdateRequest,
    GeolocateIpRequest,
    PasswordUpdateRequest,
)
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


@router.post("/profile/password")
async def change_password(
    req: PasswordUpdateRequest, authorization: Optional[str] = Header(None)
):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if len(req.new_password) < 4:
        raise HTTPException(status_code=400, detail="New password must be at least 4 characters.")
    if not update_user_password(user["id"], req.current_password, req.new_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    return {"status": "ok"}


@router.post("/profile/sources")
async def update_custom_sources(
    req: CustomSourcesUpdateRequest, authorization: Optional[str] = Header(None)
):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    normalized = update_user_sources(user["id"], req.custom_sources)
    manager.invalidate_user_cache(user["id"])
    user["custom_sources"] = normalized
    return {"user": user}


@router.post("/profile/locations")
async def update_custom_locations(
    req: CustomLocationsUpdateRequest, authorization: Optional[str] = Header(None)
):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    update_user_locations(user["id"], req.custom_locations)
    user["custom_locations"] = req.custom_locations
    return {"user": user}


@router.post("/geolocate")
async def geolocate_ip(req: GeolocateIpRequest):
    """Resolves an IPv4 address or hostname to geographical coordinates and city/country metadata."""
    raw_target = req.ip.strip()
    if not raw_target:
        raise HTTPException(status_code=400, detail="IP address or host is required.")

    match = IPV4_REGEX.search(raw_target)
    query_ip = match.group(1) if match else raw_target

    headers = {"User-Agent": OSINT_USER_AGENT}
    try:
        async with httpx.AsyncClient(timeout=8.0, headers=headers) as client:
            resp = await client.get(f"http://ip-api.com/json/{query_ip}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query", query_ip),
                        "lat": float(data.get("lat", 0.0)),
                        "lon": float(data.get("lon", 0.0)),
                        "city": data.get("city") or data.get("regionName") or "Unknown City",
                        "country": data.get("country") or "Unknown Country",
                        "code": (data.get("countryCode") or "un").lower(),
                        "asn": (data.get("as") or "AS_EDGE").split(" ")[0],
                        "isp": data.get("isp") or data.get("org") or "Unknown ISP",
                    }
                raise HTTPException(
                    status_code=422,
                    detail=data.get("message") or f"Could not geolocate '{query_ip}'.",
                )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=502, detail=f"Geolocation lookup service error: {e}"
        )

    raise HTTPException(status_code=502, detail="Failed to resolve IP geolocation.")


@router.post("/logout")
async def logout_user(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        delete_session(token)
    return {"status": "ok"}
