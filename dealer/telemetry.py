"""Synthetic telemetry for a dealt case.

So a rep is playable with no live range: given a sealed truth, emit log lines an
analyst can actually investigate. The signal that matches the truth is buried in
benign noise, so reading it is real work, not a lookup.

These are generic, synthetic log lines. They carry no private lab content and
use only RFC 5737 / RFC 2606 documentation ranges and example.com.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from .catalog import DealtCase

_BENIGN_IPS = ["10.0.0.14", "10.0.0.31", "10.0.0.52", "192.168.1.20"]
_BENIGN_USERS = ["alice", "bob", "root", "backup"]
_INTERNAL_HOSTS = ["10.0.0.14", "10.0.0.31", "10.0.0.52"]


def _base_time(gt_utc: str | None, rng: random.Random) -> datetime:
    try:
        return datetime.strptime(gt_utc or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _stamp(t: datetime) -> str:
    return t.strftime("%b %d %H:%M:%S")


def _auth_bruteforce(case: DealtCase, rng: random.Random, n: int) -> list[str]:
    gt = case.ground_truth
    host = "moria"
    t = _base_time(gt.dealt_utc, rng)
    lines: list[str] = []
    for _ in range(n):
        t += timedelta(seconds=rng.randint(1, 6))
        if rng.random() < 0.7:  # the attack: failures from the source IP
            port = rng.randint(30000, 60000)
            lines.append(
                f"{_stamp(t)} {host} sshd[{rng.randint(1000,9999)}]: "
                f"Failed password for {gt.account} from {gt.source_ip} port {port} ssh2"
            )
        else:  # benign noise
            u = rng.choice(_BENIGN_USERS)
            ip = rng.choice(_BENIGN_IPS)
            port = rng.randint(30000, 60000)
            verb = "Accepted" if rng.random() < 0.5 else "Failed"
            lines.append(
                f"{_stamp(t)} {host} sshd[{rng.randint(1000,9999)}]: "
                f"{verb} password for {u} from {ip} port {port} ssh2"
            )
    if gt.succeeded:
        t += timedelta(seconds=rng.randint(1, 4))
        port = rng.randint(30000, 60000)
        lines.append(
            f"{_stamp(t)} {host} sshd[{rng.randint(1000,9999)}]: "
            f"Accepted password for {gt.account} from {gt.source_ip} port {port} ssh2"
        )
    return lines


def _web_shell(case: DealtCase, rng: random.Random, n: int) -> list[str]:
    gt = case.ground_truth
    paths = ["/", "/index.php", "/about", "/login.php", "/assets/app.js", "/favicon.ico"]
    lines: list[str] = []
    t = _base_time(gt.dealt_utc, rng)
    shell = f"/uploads/{rng.choice(['img','tmp','data'])}{rng.randint(100,999)}.php"
    for _ in range(n):
        t += timedelta(seconds=rng.randint(1, 8))
        ip = rng.choice(_BENIGN_IPS)
        p = rng.choice(paths)
        lines.append(
            f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {p} HTTP/1.1" 200 {rng.randint(200,4000)}'
        )
    # the plant: a POST upload from the source IP, then interaction with the shell
    t += timedelta(seconds=rng.randint(2, 10))
    lines.append(
        f'{gt.source_ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"POST /upload.php HTTP/1.1" 200 {rng.randint(30,120)}'
    )
    if gt.succeeded:
        for _ in range(rng.randint(2, 5)):
            t += timedelta(seconds=rng.randint(1, 20))
            lines.append(
                f'{gt.source_ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET {shell}?cmd=id HTTP/1.1" 200 {rng.randint(20,90)}'
            )
    rng.shuffle(lines)
    return lines


def _dns_exfil(case: DealtCase, rng: random.Random, n: int) -> list[str]:
    gt = case.ground_truth
    domains = ["updates.example.com", "cdn.example.net", "time.example.org"]
    c2 = "sync.example.com"
    lines: list[str] = []
    t = _base_time(gt.dealt_utc, rng)
    for _ in range(n):
        t += timedelta(seconds=rng.randint(1, 5))
        if rng.random() < 0.55:  # exfil: long encoded labels to one domain from the victim
            label = "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(28, 48)))
            lines.append(
                f'{_stamp(t)} dnsmasq[{rng.randint(100,999)}]: query[A] '
                f'{label}.{c2} from {gt.source_ip}'
            )
        else:  # benign resolutions from assorted internal hosts
            ih = rng.choice(_INTERNAL_HOSTS)
            lines.append(
                f'{_stamp(t)} dnsmasq[{rng.randint(100,999)}]: query[A] '
                f'{rng.choice(domains)} from {ih}'
            )
    return lines


_GENERATORS = {
    "auth_bruteforce": _auth_bruteforce,
    "web_shell": _web_shell,
    "dns_exfil": _dns_exfil,
}


def generate(case: DealtCase, seed: int | None = None) -> list[str]:
    """Produce synthetic telemetry lines for a dealt case."""
    spec = case.scenario.telemetry
    gen = _GENERATORS.get(spec.get("generator", ""))
    if gen is None:
        return [f"# no telemetry generator for scenario {case.scenario.id}"]
    rng = random.Random((seed if seed is not None else case.seed) ^ 0x5EED)
    lo, hi = (spec.get("volume") or [40, 100])[:2]
    n = rng.randint(int(lo), int(hi))
    return gen(case, rng, n)
