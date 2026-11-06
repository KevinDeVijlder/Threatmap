"""
Pydantic Request Schemas
========================
Data validation models for authentication, user profile, custom feeds,
and monitored map locations.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class AuthRequest(BaseModel):
    username: str
    password: str
    avatar: Optional[str] = ""


class AvatarUpdateRequest(BaseModel):
    avatar: str


class PasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str


class CustomSourcesUpdateRequest(BaseModel):
    custom_sources: List[Dict[str, Any]]


class CustomLocationsUpdateRequest(BaseModel):
    custom_locations: List[Dict[str, Any]]


class GeolocateIpRequest(BaseModel):
    ip: str
