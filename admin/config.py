"""Настройки админки: env службы (секреты) и /etc/bvpn/config.json (кто эта установка, без секретов)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


DEFAULTS = {"server_id": "nl", "title": "Нидерланды", "label": "Нидерланды", "flag": "🇳🇱", "ip": "203.0.113.10",
            "brand": "VPN", "sub_url": "https://203.0.113.10/", "template": "owner", "monitor_account": "monitoring"}


def installation() -> dict:
    try:
        return {**DEFAULTS, **json.loads(Path(_env("BVPN_CONFIG", "/etc/bvpn/config.json")).read_text(encoding="utf-8"))}
    except (OSError, ValueError):
        return dict(DEFAULTS)


CONF = installation()


@dataclass
class Settings:
    bot_token: str = field(default_factory=lambda: _env("TELEGRAM_BOT_TOKEN"))
    chat_id: int = field(default_factory=lambda: int(_env("TELEGRAM_CHAT_ID", "0") or 0))
    owner_email: str = field(default_factory=lambda: _env("OWNER_EMAIL", "admin").lower())
    public_url: str = field(default_factory=lambda: _env("PUBLIC_URL", "https://203.0.113.10:8444").rstrip("/"))
    listen_port: int = field(default_factory=lambda: int(_env("LISTEN_PORT", "8092")))
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "/var/lib/bvpn-admin")))
    vpn_dir: Path = field(default_factory=lambda: Path(_env("VPN_DIR", "/var/lib/bvpn")))
    vpn_outbox: Path = field(default_factory=lambda: Path(_env("VPN_OUTBOX_DIR", "/var/lib/bvpn-outbox")))
    vpn_proposals: Path = field(default_factory=lambda: Path(_env("VPN_PROPOSALS_DIR", "/var/lib/bvpn-proposals")))
    vpn_kits: Path = field(default_factory=lambda: Path(_env("VPN_KITS_DIR", "/var/lib/bvpn-kits")))
    monitor_file: Path = field(default_factory=lambda: Path(_env("MONITOR_FILE", "/var/lib/bvpn-monitor/latest.json")))
    dry_run: bool = field(default_factory=lambda: _env("DRY_RUN") == "1")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "admin.db"
