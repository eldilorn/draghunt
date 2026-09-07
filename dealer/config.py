"""Range configuration for live mode.

One TOML file on the laptop describes how to reach the moving parts: the Kali
attacker, the target VM, the SIEM to pull alerts from, and the hypervisor to
reset between reps. Read with the standard-library `tomllib`; no dependency.

Secrets (SIEM password, Proxmox token) may be given inline OR via environment
variable, so the file itself can stay free of credentials. Env wins if set.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


def _env_or(value: str | None, env_key: str) -> str | None:
    return os.environ.get(env_key) or (value or None)


@dataclass
class AttackerCfg:
    host: str = ""
    user: str = ""
    ssh_key: str = ""


@dataclass
class TargetCfg:
    host: str = ""
    user: str = ""


@dataclass
class RunnerCfg:
    # where the user's PRIVATE runners live, on the attacker box
    dir: str = "~/casefiles-lab/lab"
    entry: str = "fire.sh"  # dispatcher the app invokes with injected params


@dataclass
class SiemCfg:
    adapter: str = "wazuh"
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResetCfg:
    mode: str = "both"  # snapshot | cleanup | both | none
    proxmox: dict[str, Any] = field(default_factory=dict)


@dataclass
class RangeConfig:
    data_dir: str = ".dealer"
    attacker: AttackerCfg = field(default_factory=AttackerCfg)
    target: TargetCfg = field(default_factory=TargetCfg)
    runner: RunnerCfg = field(default_factory=RunnerCfg)
    siem: SiemCfg = field(default_factory=SiemCfg)
    reset: ResetCfg = field(default_factory=ResetCfg)

    @staticmethod
    def from_dict(doc: dict[str, Any]) -> "RangeConfig":
        a = doc.get("attacker", {})
        t = doc.get("target", {})
        r = doc.get("runner", {})
        s = doc.get("siem", {})
        rs = doc.get("reset", {})
        siem_adapter = str(s.get("adapter", "wazuh"))
        siem_opts = dict(s.get(siem_adapter, {}))
        # resolve secrets from env if present
        if "password" in siem_opts:
            siem_opts["password"] = _env_or(siem_opts.get("password"), "DEALER_SIEM_PASSWORD")
        proxmox = dict(rs.get("proxmox", {}))
        if "token_secret" in proxmox:
            proxmox["token_secret"] = _env_or(proxmox.get("token_secret"), "DEALER_PROXMOX_SECRET")
        return RangeConfig(
            data_dir=str(doc.get("control", {}).get("data_dir", ".dealer")),
            attacker=AttackerCfg(str(a.get("host", "")), str(a.get("user", "")), str(a.get("ssh_key", ""))),
            target=TargetCfg(str(t.get("host", "")), str(t.get("user", ""))),
            runner=RunnerCfg(str(r.get("dir", "~/casefiles-lab/lab")), str(r.get("entry", "fire.sh"))),
            siem=SiemCfg(siem_adapter, siem_opts),
            reset=ResetCfg(str(rs.get("mode", "both")), proxmox),
        )

    def missing_for_fire(self) -> list[str]:
        """What's not yet configured for a live fire. Empty == ready."""
        gaps = []
        if not self.attacker.host:
            gaps.append("attacker.host")
        if not self.attacker.user:
            gaps.append("attacker.user")
        if not self.target.host:
            gaps.append("target.host")
        return gaps


DEFAULT_PATH = Path("range.toml")


def load(path: str | Path | None = None) -> RangeConfig:
    p = Path(path or DEFAULT_PATH)
    if not p.exists():
        return RangeConfig()  # empty config: dry-run still works, fire is blocked
    try:
        return RangeConfig.from_dict(tomllib.loads(p.read_text()))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {p}: {exc}") from exc


EXAMPLE_TOML = """\
# range.toml — how the Dealer reaches your lab. Keep this file private (chmod 600).
# Secrets can be left blank here and supplied via env instead:
#   DEALER_SIEM_PASSWORD, DEALER_PROXMOX_SECRET

[control]
data_dir = ".dealer"

[attacker]                       # your Kali box — the app SSHes here to fire
host    = "192.168.45.75"
user    = "kali"
ssh_key = "~/.ssh/lab_id_ed25519"

[target]                         # the victim VM the attack lands on
host = "192.168.45.74"
user = "labadmin"

[runner]                         # your PRIVATE runners, on the attacker box
dir   = "~/casefiles-lab/lab"
entry = "fire.sh"                # dispatcher the app calls with injected params

[siem]
adapter = "wazuh"                # the only shipped adapter today; others pluggable

[siem.wazuh]
indexer_url = "https://192.168.45.10:9200"
index       = "wazuh-alerts-*"
username    = "admin"
password    = ""                 # or set DEALER_SIEM_PASSWORD
verify_tls  = false

[reset]
mode = "both"                    # snapshot | cleanup | both | none

[reset.proxmox]
api_url      = "https://192.168.45.2:8006"
token_id     = "root@pam!dealer"
token_secret = ""                # or set DEALER_PROXMOX_SECRET
node         = "pve"
vmid         = 101
snapshot     = "clean"
"""
