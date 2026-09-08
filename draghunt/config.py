"""Validated local configuration. Relative paths resolve against the config file."""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class ConfigError(ValueError):
    pass


def default_path() -> Path:
    return Path(os.environ.get("DRAGHUNT_CONFIG") or
                str(Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "draghunt/range.toml")).expanduser()


def default_data_dir() -> str:
    return str(Path(os.environ.get("DRAGHUNT_DATA_DIR") or
                    str(Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "draghunt")).expanduser())


def _section(doc: dict, key: str) -> dict:
    value = doc.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a TOML table")
    return value


def _str(doc: dict, key: str, default: str = "") -> str:
    value = doc.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be text")
    return value.strip()


@dataclass
class AttackerCfg:
    host: str = ""
    user: str = ""
    ssh_key: str = ""


@dataclass
class TargetCfg:
    host: str = ""
    user: str = ""
    agent_id: str = ""


@dataclass
class RunnerCfg:
    dir: str = "~/casefiles-lab/lab"
    entry: str = "fire.sh"
    ready_timeout: int = 120


@dataclass
class SiemCfg:
    adapter: str = "wazuh"
    options: dict[str, Any] = field(default_factory=dict)
    ingest_wait: int = 120


@dataclass
class ResetCfg:
    mode: str = "none"
    proxmox: dict[str, Any] = field(default_factory=dict)


@dataclass
class RangeConfig:
    data_dir: str = field(default_factory=default_data_dir)
    catalog_dir: str = ""
    attacker: AttackerCfg = field(default_factory=AttackerCfg)
    target: TargetCfg = field(default_factory=TargetCfg)
    runner: RunnerCfg = field(default_factory=RunnerCfg)
    siem: SiemCfg = field(default_factory=SiemCfg)
    reset: ResetCfg = field(default_factory=ResetCfg)

    @staticmethod
    def from_dict(doc: dict[str, Any]) -> "RangeConfig":
        if not isinstance(doc, dict):
            raise ConfigError("configuration must be a TOML document")
        control = _section(doc, "control")
        a, t, r, s, rs = (_section(doc, k) for k in ("attacker", "target", "runner", "siem", "reset"))
        adapter = _str(s, "adapter", "wazuh")
        opts = dict(_section(s, adapter))
        opts["password"] = os.environ.get("DRAGHUNT_SIEM_PASSWORD") or _str(opts, "password")
        px = dict(_section(rs, "proxmox"))
        px["token_secret"] = os.environ.get("DRAGHUNT_PROXMOX_SECRET") or _str(px, "token_secret")
        mode = _str(rs, "mode", "none").lower()
        if mode not in {"snapshot", "cleanup", "both", "none"}:
            raise ConfigError("reset.mode must be snapshot, cleanup, both, or none")
        for section in (opts, px):
            for key in ("verify_tls", "start_after"):
                if key in section and type(section[key]) is not bool:
                    raise ConfigError(f"{key} must be a TOML boolean")
            if section.get("verify_tls") is False:
                raise ConfigError("verify_tls = false is not supported; set ca_file to your lab CA certificate instead")
            for key in ("api_url", "indexer_url", "dashboard_url"):
                if key in section:
                    value = _str(section, key)
                    url = urlparse(value)
                    # Credentialed endpoints must be HTTPS. The dashboard link carries no secret.
                    schemes = ("https", "http") if key == "dashboard_url" else ("https",)
                    if value and (url.scheme not in schemes or not url.hostname or url.username or url.password):
                        raise ConfigError(f"{key} must be an {'HTTP(S)' if key == 'dashboard_url' else 'HTTPS'} URL without embedded credentials")
        for section, key, default in ((r, "ready_timeout", 120), (s, "ingest_wait", 120)):
            value = section.get(key, default)
            if type(value) is not int or not 0 <= value <= 1800:
                raise ConfigError(f"{key} must be an integer between 0 and 1800")
        cfg = RangeConfig(
            data_dir=os.environ.get("DRAGHUNT_DATA_DIR") or _str(control, "data_dir", default_data_dir()),
            catalog_dir=_str(control, "catalog_dir"),
            attacker=AttackerCfg(_str(a, "host"), _str(a, "user"), _str(a, "ssh_key")),
            target=TargetCfg(_str(t, "host"), _str(t, "user"), _str(t, "agent_id")),
            runner=RunnerCfg(_str(r, "dir", "~/casefiles-lab/lab"), _str(r, "entry", "fire.sh"), r.get("ready_timeout", 120)),
            siem=SiemCfg(adapter, opts, s.get("ingest_wait", 120)), reset=ResetCfg(mode, px))
        for key, value in (("attacker.host", cfg.attacker.host), ("target.host", cfg.target.host)):
            if value and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:%_-]*", value):
                raise ConfigError(f"invalid {key}")
        if cfg.attacker.user and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", cfg.attacker.user):
            raise ConfigError("invalid attacker.user")
        if not cfg.runner.entry or "/" in cfg.runner.entry or cfg.runner.entry.startswith("-"):
            raise ConfigError("runner.entry must be a filename")
        if not (cfg.runner.dir.startswith("/") or cfg.runner.dir.startswith("~/")):
            raise ConfigError("runner.dir must be absolute or start with ~/")
        if err := cfg.rollback_binding_error():
            raise ConfigError(err)
        return cfg

    def missing_for_fire(self) -> list[str]:
        required = {"attacker.host": self.attacker.host, "attacker.user": self.attacker.user,
                    "target.host": self.target.host, "target.agent_id": self.target.agent_id,
                    "siem.indexer_url": self.siem.options.get("indexer_url")}
        return [key for key, value in required.items() if not value]

    def rollback_binding_error(self) -> str:
        """Why a snapshot rollback must not run, or "" when the VM is bound to the attack target.

        The attack goes to target.host while the rollback goes to reset.proxmox.vmid, which
        are configured independently. Requiring target_host next to the vmid catches a stale
        vmid after the target is re-pointed, before anything irreversible happens.
        """
        px = self.reset.proxmox
        if self.reset.mode not in ("snapshot", "both") or not px.get("vmid"):
            return ""
        bound = str(px.get("target_host", "")).strip()
        if bound and bound == self.target.host:
            return ""
        return (f"reset.proxmox.target_host ({bound or 'unset'}) must equal target.host "
                f"({self.target.host or 'unset'}) so VM {px['vmid']} is provably the attack target")


DEFAULT_PATH = default_path()


def _holds_inline_secret(doc: dict) -> bool:
    siem = _section(doc, "siem")
    adapter = _section(siem, _str(siem, "adapter", "wazuh"))
    proxmox = _section(_section(doc, "reset"), "proxmox")
    return bool(adapter.get("password") or proxmox.get("token_secret"))


def load(path: str | Path | None = None, missing_ok: bool = False) -> RangeConfig:
    p = Path(path).expanduser() if path is not None else default_path()
    if not p.exists():
        # missing_ok lets the dashboard start in synthetic mode and create the profile
        # from the Settings panel, so first-run setup does not require a file to exist yet.
        if not missing_ok and (path is not None or os.environ.get("DRAGHUNT_CONFIG")):
            raise ConfigError(f"configuration not found: {p}")
        return RangeConfig()
    try:
        doc = tomllib.loads(p.read_text())
        if _holds_inline_secret(doc) and p.stat().st_mode & 0o077:
            raise ConfigError(f"{p} holds a secret but is readable by other users; chmod 600 it "
                              "or supply DRAGHUNT_SIEM_PASSWORD / DRAGHUNT_PROXMOX_SECRET instead")
        cfg = RangeConfig.from_dict(doc)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise ConfigError(f"cannot read configuration {p}: {exc}") from exc
    for name in ("data_dir", "catalog_dir"):
        value = getattr(cfg, name)
        if value:
            resolved = Path(value).expanduser()
            setattr(cfg, name, str((resolved if resolved.is_absolute() else p.resolve().parent / resolved).resolve()))
    if cfg.attacker.ssh_key:
        key = Path(cfg.attacker.ssh_key).expanduser()
        cfg.attacker.ssh_key = str((key if key.is_absolute() else p.resolve().parent / key).resolve())
    return cfg


EXAMPLE_TOML = '''# Local range profile. Supply secrets through environment variables if preferred.
# DRAGHUNT_SIEM_PASSWORD and DRAGHUNT_PROXMOX_SECRET work with no secret keys below.
# If you put a secret in this file, keep it mode 0600; Draghunt refuses a readable one.
[control]
# Defaults to ~/.local/share/draghunt (or XDG_DATA_HOME/DRAGHUNT_DATA_DIR).
# data_dir = "/absolute/path/to/draghunt-data"
# Optional PRIVATE catalog containing metadata for protocol-v1 runners:
# catalog_dir = "/absolute/path/to/private/catalog"

[attacker]
host = "192.168.45.75"
user = "kali"
ssh_key = "~/.ssh/lab_id_ed25519"

[target]
host = "192.168.45.74"
user = "labadmin"
agent_id = "001"                 # Wazuh agent ID; verify against your target

[runner]
dir = "~/casefiles-lab/lab"
entry = "fire.sh"                 # must implement docs/RUNNER-PROTOCOL.md
ready_timeout = 120

[siem]
adapter = "wazuh"
ingest_wait = 120                 # wait after the investigation window before judging absence

[siem.wazuh]
indexer_url = "https://192.168.45.10:9200"
index = "wazuh-alerts-*"
# events_index = "wazuh-archives-*" # requires archive indexing in Wazuh
# dashboard_url = "https://wazuh.example.test"
username = "draghunt-reader"
# ca_file = "/absolute/path/to/lab-ca.pem"   # for a self-signed lab CA; TLS is always verified

[reset]
mode = "both"                     # snapshot | cleanup | both | none

[reset.proxmox]
api_url = "https://192.168.45.2:8006"
token_id = "draghunt@pve!range"
node = "pve"
vmid = 101
snapshot = "clean"
target_host = "192.168.45.74"     # must equal [target].host; binds the rollback to the attack target
# ca_file = "/absolute/path/to/lab-ca.pem"
'''


# --- Settings panel support: read a redacted profile, write one back ----------
# The dashboard needs to show and edit the profile without ever handing secrets
# back to the browser. public_profile() redacts them; form_to_tables() merges a
# submitted form with any secret already on disk, and to_toml() serializes the
# result (stdlib has no TOML writer, so this is a small deliberate one).

_SECRET_KEYS = {"password", "token_secret"}


def public_profile(cfg: "RangeConfig", path: str | Path) -> dict:
    """The profile as the browser may see it: secrets replaced by has_* booleans."""
    opts, px = cfg.siem.options, cfg.reset.proxmox
    return {
        "path": str(path),
        "control": {"catalog_dir": cfg.catalog_dir, "data_dir": cfg.data_dir},
        "attacker": {"host": cfg.attacker.host, "user": cfg.attacker.user, "ssh_key": cfg.attacker.ssh_key},
        "target": {"host": cfg.target.host, "user": cfg.target.user, "agent_id": cfg.target.agent_id},
        "runner": {"dir": cfg.runner.dir, "entry": cfg.runner.entry, "ready_timeout": cfg.runner.ready_timeout},
        "siem": {"adapter": cfg.siem.adapter, "indexer_url": opts.get("indexer_url", ""),
                 "index": opts.get("index", ""), "events_index": opts.get("events_index", ""),
                 "username": opts.get("username", ""), "dashboard_url": opts.get("dashboard_url", ""),
                 "ca_file": opts.get("ca_file", ""), "ingest_wait": cfg.siem.ingest_wait,
                 "has_password": bool(opts.get("password"))},
        "reset": {"mode": cfg.reset.mode,
                  "proxmox": {"api_url": px.get("api_url", ""), "token_id": px.get("token_id", ""),
                              "node": px.get("node", ""), "vmid": px.get("vmid", ""),
                              "snapshot": px.get("snapshot", ""), "target_host": px.get("target_host", ""),
                              "ca_file": px.get("ca_file", ""), "has_token_secret": bool(px.get("token_secret"))}},
        "gaps": cfg.missing_for_fire(),
        "binding_error": cfg.rollback_binding_error(),
    }


def _maybe_int(value: Any) -> Any:
    # Form inputs arrive as strings; hand integers to from_dict so it can validate them.
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return value


def form_to_tables(form: dict, existing: dict | None = None) -> dict:
    """Turn a settings-form payload into a TOML-shaped dict, preserving on-disk secrets.

    A secret absent or blank in the form keeps whatever the current profile holds, so the
    browser never has to receive a secret in order to leave it unchanged.
    """
    existing = existing or {}
    if not isinstance(form, dict):
        raise ConfigError("settings payload must be an object")
    get = lambda d, k: d.get(k, {}) if isinstance(d.get(k), dict) else {}
    fa, ft, fr = get(form, "attacker"), get(form, "target"), get(form, "runner")
    fs, fc = get(form, "siem"), get(form, "control")
    frs = get(form, "reset")
    fpx = get(frs, "proxmox")
    adapter = _str(fs, "adapter", "wazuh") or "wazuh"

    old_siem = get(get(existing, "siem"), adapter)
    old_px = get(get(existing, "reset"), "proxmox")
    password = _str(fs, "password") or old_siem.get("password", "")
    token_secret = _str(fpx, "token_secret") or old_px.get("token_secret", "")

    tables: dict[str, Any] = {
        "control": {"catalog_dir": _str(fc, "catalog_dir"),
                    "data_dir": get(existing, "control").get("data_dir", "")},
        "attacker": {"host": _str(fa, "host"), "user": _str(fa, "user"), "ssh_key": _str(fa, "ssh_key")},
        "target": {"host": _str(ft, "host"), "user": _str(ft, "user"), "agent_id": _str(ft, "agent_id")},
        "runner": {"dir": _str(fr, "dir", "~/casefiles-lab/lab") or "~/casefiles-lab/lab",
                   "entry": _str(fr, "entry", "fire.sh") or "fire.sh",
                   "ready_timeout": _maybe_int(fr.get("ready_timeout", 120))},
        "siem": {"adapter": adapter, "ingest_wait": _maybe_int(fs.get("ingest_wait", 120)),
                 adapter: {"indexer_url": _str(fs, "indexer_url"), "index": _str(fs, "index"),
                           "events_index": _str(fs, "events_index"), "username": _str(fs, "username"),
                           "dashboard_url": _str(fs, "dashboard_url"), "ca_file": _str(fs, "ca_file"),
                           "password": password}},
        "reset": {"mode": _str(frs, "mode", "none").lower() or "none",
                  "proxmox": {"api_url": _str(fpx, "api_url"), "token_id": _str(fpx, "token_id"),
                              "node": _str(fpx, "node"), "vmid": _maybe_int(fpx.get("vmid", "")),
                              "snapshot": _str(fpx, "snapshot"), "target_host": _str(fpx, "target_host"),
                              "ca_file": _str(fpx, "ca_file"), "token_secret": token_secret}},
    }
    return tables


def _toml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return f'"{escaped}"'


def to_toml(doc: dict, _prefix: str = "") -> str:
    """Serialize a nested table dict to TOML. Empty scalars are dropped; tables are emitted
    parent-before-child with scalar keys ahead of subtables, as TOML requires."""
    scalars = {k: v for k, v in doc.items() if not isinstance(v, dict) and v not in ("", None)}
    tables = {k: v for k, v in doc.items() if isinstance(v, dict)}
    lines: list[str] = []
    if not _prefix:
        lines += ["# Draghunt range profile. Managed by the dashboard Settings panel.",
                  "# Secrets stay in this file at mode 0600, or supply them via the environment.", ""]
    else:
        lines.append(f"[{_prefix}]")
    for key, value in scalars.items():
        lines.append(f"{key} = {_toml_scalar(value)}")
    if _prefix:
        lines.append("")
    for key, value in tables.items():
        lines.append(to_toml(value, f"{_prefix}.{key}" if _prefix else key))
    return "\n".join(lines)
