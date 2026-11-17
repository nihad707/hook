"""Pydantic schemas with strict length limits.

The trap payload is special: it comes from our own SDK on behalf of an attacker, so instead of rejecting an
oversized field with 422 we TRUNCATE it first (before-validators) and only then enforce max_length.
The trap therefore never fails on attacker-controlled input.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, Field, ValidationInfo, field_validator

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,24}$")


class RegisterPayload(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)


class LoginPayload(BaseModel):
    email: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


_TRAP_LIMITS = {"attacker_ip": 45, "user_agent": 512, "request_path": 1024, "payload_data": 2048, "method": 10}
_TRAP_DEFAULTS = {"attacker_ip": "unknown", "request_path": "/", "method": "GET"}


class SandboxHookPayload(BaseModel):
    attacker_ip: str = Field(default="unknown", min_length=1, max_length=45)      # IPv6 max length
    user_agent: str = Field(default="", max_length=512)
    request_path: str = Field(default="/", min_length=1, max_length=1024)
    payload_data: str | None = Field(default="", max_length=2048)                # query string sent by the SDK
    method: str = Field(default="GET", min_length=1, max_length=10)

    @field_validator("attacker_ip", "user_agent", "request_path", "payload_data", "method", mode="before")
    @classmethod
    def _fit(cls, v, info: ValidationInfo):
        name = info.field_name
        text = "" if v is None else str(v)
        text = text[:_TRAP_LIMITS[name]]
        return text or _TRAP_DEFAULTS.get(name, "")
