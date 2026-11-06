"""
Pydantic Request Schemas
========================
Data validation models for authentication and user profile endpoints.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel


class AuthRequest(BaseModel):
    username: str
    password: str
    avatar: Optional[str] = ""


class AvatarUpdateRequest(BaseModel):
    avatar: str


class CustomSourcesUpdateRequest(BaseModel):
    custom_sources: List[Dict[str, str]]
