import hashlib
import hmac
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import streamlit as st


# Authentication, RBAC, and system management support.
# Author: Xinyuan Yu
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "shared_data"
USERS_PATH = DATA_DIR / "users.json"
ROLE_PERMISSIONS_PATH = DATA_DIR / "role_permissions.json"

PERMISSIONS = {
    "portal_access": "Consumer portal access",
    "data_ingest": "Upload and persist datasets",
    "catalog_manage": "Tag metadata and save catalog",
    "gateway_execute": "Run gateway test queries",
    "policy_view": "View active data access policy",
    "audit_view": "View compliance audit logs",
    "audit_clear": "Clear compliance audit logs",
    "system_manage": "Manage users, roles, and permission groups",
    "role_impersonate": "Test gateway execution as another role",
}

DEFAULT_PERMISSION_GROUPS = {
    "System_Administrators": [
        "portal_access",
        "data_ingest",
        "catalog_manage",
        "gateway_execute",
        "policy_view",
        "audit_view",
        "audit_clear",
        "system_manage",
        "role_impersonate",
    ],
    "Data_Stewards": [
        "portal_access",
        "data_ingest",
        "catalog_manage",
        "gateway_execute",
        "policy_view",
        "audit_view",
    ],
    "Data_Consumers": [
        "portal_access",
    ],
    "Compliance_Auditors": [
        "portal_access",
        "policy_view",
        "audit_view",
    ],
}

DEFAULT_ROLE_PERMISSIONS = {
    "metadata": {
        "author": "Xinyuan Yu",
        "module": "Authentication, role permissions, and permission groups",
    },
    "roles": {
        "Administrator": {
            "description": "Full platform administrator and policy owner.",
            "permission_group": "System_Administrators",
        },
        "Professional_Staff": {
            "description": "Internal staff with protected operational access.",
            "permission_group": "Data_Consumers",
        },
        "General_Analyst": {
            "description": "Analyst role for privacy-preserving analytics.",
            "permission_group": "Data_Consumers",
        },
        "External_Auditor": {
            "description": "External reviewer with audit-oriented access.",
            "permission_group": "Compliance_Auditors",
        },
    },
    "permission_groups": DEFAULT_PERMISSION_GROUPS,
}

DEFAULT_USERS = [
    {
        "username": "admin",
        "display_name": "System Administrator",
        "role": "Administrator",
        "password": "admin123",
    },
    {
        "username": "analyst",
        "display_name": "General Analyst",
        "role": "General_Analyst",
        "password": "analyst123",
    },
    {
        "username": "staff",
        "display_name": "Professional Staff",
        "role": "Professional_Staff",
        "password": "staff123",
    },
    {
        "username": "auditor",
        "display_name": "External Auditor",
        "role": "External_Auditor",
        "password": "auditor123",
    },
]


def _hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    salt = salt or os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000,
    ).hex()
    return {"salt": salt, "password_hash": digest}


def _verify_password(password: str, salt: str, password_hash: str) -> bool:
    candidate = _hash_password(password, salt)["password_hash"]
    return hmac.compare_digest(candidate, password_hash)


def _read_json(path: Path, default):
    if not path.exists() or path.stat().st_size == 0:
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _write_json(path: Path, payload) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)


def ensure_auth_store() -> None:
    DATA_DIR.mkdir(exist_ok=True)

    if not ROLE_PERMISSIONS_PATH.exists():
        _write_json(ROLE_PERMISSIONS_PATH, DEFAULT_ROLE_PERMISSIONS)

    if not USERS_PATH.exists():
        now = datetime.utcnow().isoformat() + "Z"
        users = {"users": []}
        for user in DEFAULT_USERS:
            password_fields = _hash_password(user["password"])
            users["users"].append({
                "username": user["username"],
                "display_name": user["display_name"],
                "role": user["role"],
                "active": True,
                "created_at": now,
                **password_fields,
            })
        _write_json(USERS_PATH, users)


def load_role_permissions() -> Dict:
    ensure_auth_store()
    config = _read_json(ROLE_PERMISSIONS_PATH, DEFAULT_ROLE_PERMISSIONS)
    config.setdefault("roles", DEFAULT_ROLE_PERMISSIONS["roles"])
    config.setdefault("permission_groups", DEFAULT_PERMISSION_GROUPS)
    return config


def save_role_permissions(config: Dict) -> None:
    _write_json(ROLE_PERMISSIONS_PATH, config)


def load_users() -> List[Dict]:
    ensure_auth_store()
    payload = _read_json(USERS_PATH, {"users": []})
    return payload.get("users", [])


def save_users(users: List[Dict]) -> None:
    _write_json(USERS_PATH, {"users": users})


def available_roles() -> List[str]:
    return list(load_role_permissions().get("roles", {}).keys())


def role_permissions(role: str) -> List[str]:
    config = load_role_permissions()
    role_config = config.get("roles", {}).get(role, {})
    group = role_config.get("permission_group")
    return config.get("permission_groups", {}).get(group, [])


def has_permission(permission: str, user: Optional[Dict] = None) -> bool:
    user = user or st.session_state.get("auth_user")
    if not user:
        return False
    return permission in role_permissions(user.get("role", ""))


def authenticate(username: str, password: str) -> Optional[Dict]:
    username = username.strip()
    for user in load_users():
        if user.get("username") != username or not user.get("active", True):
            continue
        if _verify_password(password, user.get("salt", ""), user.get("password_hash", "")):
            return public_user(user)
    return None


def public_user(user: Dict) -> Dict:
    return {
        "username": user.get("username", ""),
        "display_name": user.get("display_name", ""),
        "role": user.get("role", ""),
        "active": user.get("active", True),
    }


def create_or_update_user(
    username: str,
    display_name: str,
    role: str,
    active: bool,
    password: str = "",
) -> None:
    username = username.strip()
    display_name = display_name.strip() or username
    users = load_users()
    existing = next((u for u in users if u.get("username") == username), None)

    if existing:
        existing["display_name"] = display_name
        existing["role"] = role
        existing["active"] = active
        if password:
            existing.update(_hash_password(password))
    else:
        if not password:
            raise ValueError("New users require a password.")
        users.append({
            "username": username,
            "display_name": display_name,
            "role": role,
            "active": active,
            "created_at": datetime.utcnow().isoformat() + "Z",
            **_hash_password(password),
        })

    save_users(users)


def delete_user(username: str) -> None:
    users = [u for u in load_users() if u.get("username") != username]
    save_users(users)


def login_panel(app_name: str) -> Dict:
    ensure_auth_store()
    if st.session_state.get("auth_user"):
        return st.session_state.auth_user

    st.title(app_name)
    st.subheader("User Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", type="primary")

    if submitted:
        user = authenticate(username, password)
        if user:
            st.session_state.auth_user = user
            st.rerun()
        st.error("Invalid username, password, or disabled account.")

    st.info("Default accounts: admin/admin123, analyst/analyst123, staff/staff123, auditor/auditor123.")
    st.stop()


def require_permission(permission: str, message: str = "Access denied.") -> None:
    if not has_permission(permission):
        st.error(message)
        st.stop()


def render_user_badge() -> Dict:
    user = st.session_state.get("auth_user")
    if not user:
        return {}
    with st.sidebar:
        st.caption(f"Signed in as {user['display_name']} ({user['role']})")
        if st.button("Logout", use_container_width=True):
            del st.session_state["auth_user"]
            st.rerun()
    return user
