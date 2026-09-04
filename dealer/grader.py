"""Score an analyst verdict against sealed ground truth.

The rubric is data-driven: each dimension has a weight and a comparison, and
the total is normalised to 100. Change WEIGHTS to reweight the loop without
touching the scoring logic.

Design choices worth knowing:

* Disposition is the spine. Calling a malicious case "benign" is the one miss
  that should sting, so a disposition of the wrong *polarity* (malicious vs
  benign) zeroes the rest of the score via a hard cap. Get the call right first;
  the observables are how you prove it.
* MITRE technique matches at two levels. An exact sub-technique (T1110.001)
  earns full marks; the right parent technique (T1110) earns partial. That
  rewards "close" the way a real reviewer would.
* Unanswered fields score zero but never negative. A partial verdict is honest,
  not punished beyond the points it forgoes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schema import GroundTruth, Verdict


# Dimension weights. Relative; the engine normalises to 100.
WEIGHTS: dict[str, int] = {
    "disposition": 30,
    "technique": 25,
    "source_ip": 15,
    "account": 15,
    "succeeded": 15,
}

# If the analyst inverts the call (malicious <-> benign), cap the whole score
# here regardless of how many observables they got right.
WRONG_POLARITY_CAP = 40

_POLARITY = {"malicious": 1, "benign": -1, "inconclusive": 0}


@dataclass
class LineItem:
    dimension: str
    weight: int
    earned: float
    expected: str
    got: str
    note: str = ""

    @property
    def pct(self) -> float:
        return 0.0 if self.weight == 0 else round(100 * self.earned / self.weight, 1)


@dataclass
class Report:
    scenario_id: str
    total: float          # 0..100
    band: str
    items: list[LineItem]
    capped: bool = False

    def as_text(self) -> str:
        lines = [
            f"Dealer verdict report — scenario {self.scenario_id}",
            f"Score: {self.total:.0f}/100   Grade: {self.band}",
            "",
        ]
        w = max(len(i.dimension) for i in self.items)
        for i in self.items:
            mark = "OK " if i.earned >= i.weight else ("~  " if i.earned > 0 else "X  ")
            lines.append(
                f"  {mark}{i.dimension.ljust(w)}  {i.earned:>4.1f}/{i.weight:<2}  "
                f"expected={i.expected!r} got={i.got!r}"
                + (f"  ({i.note})" if i.note else "")
            )
        if self.capped:
            lines.append("")
            lines.append(
                f"  ! Disposition polarity wrong — total capped at {WRONG_POLARITY_CAP}."
            )
        return "\n".join(lines)


def _band(total: float) -> str:
    if total >= 90:
        return "A — clean read"
    if total >= 75:
        return "B — solid, minor gaps"
    if total >= 60:
        return "C — right call, thin evidence"
    if total >= 40:
        return "D — shaky"
    return "F — missed it"


def _norm_ip(s: str | None) -> str | None:
    return s.strip() if s else None


def _norm_acct(s: str | None) -> str | None:
    return s.strip().lower() if s else None


def _technique_score(expected: str, got: str | None, weight: int) -> tuple[float, str]:
    """Full marks on exact match, partial on shared parent technique."""
    if not got:
        return 0.0, "no technique given"
    if got == expected:
        return float(weight), "exact"
    exp_parent = expected.split(".")[0]
    got_parent = got.split(".")[0]
    if got_parent == exp_parent:
        return round(weight * 0.6, 2), "right technique, wrong sub-technique"
    return 0.0, "wrong technique"


def grade(gt: GroundTruth, v: Verdict, weights: dict[str, int] | None = None) -> Report:
    w = weights or WEIGHTS
    items: list[LineItem] = []

    # disposition
    d_earned = float(w["disposition"]) if v.disposition == gt.disposition else 0.0
    items.append(LineItem("disposition", w["disposition"], d_earned,
                          gt.disposition, v.disposition))

    # technique
    t_earned, t_note = _technique_score(gt.technique, v.technique, w["technique"])
    items.append(LineItem("technique", w["technique"], t_earned,
                          gt.technique, v.technique or "-", t_note))

    # source_ip
    ip_ok = _norm_ip(v.source_ip) == _norm_ip(gt.source_ip)
    items.append(LineItem("source_ip", w["source_ip"],
                          float(w["source_ip"]) if ip_ok else 0.0,
                          gt.source_ip, v.source_ip or "-"))

    # account (may be absent from ground truth; then it's a free dimension)
    if gt.account is None:
        items.append(LineItem("account", w["account"], float(w["account"]),
                              "n/a", v.account or "-", "no account in scenario"))
    else:
        acct_ok = _norm_acct(v.account) == _norm_acct(gt.account)
        items.append(LineItem("account", w["account"],
                              float(w["account"]) if acct_ok else 0.0,
                              gt.account, v.account or "-"))

    # succeeded
    if v.succeeded is None:
        s_earned = 0.0
        s_got = "-"
    else:
        s_earned = float(w["succeeded"]) if v.succeeded == gt.succeeded else 0.0
        s_got = str(v.succeeded).lower()
    items.append(LineItem("succeeded", w["succeeded"], s_earned,
                          str(gt.succeeded).lower(), s_got))

    total_weight = sum(w.values())
    earned = sum(i.earned for i in items)
    total = round(100 * earned / total_weight, 1) if total_weight else 0.0

    # Hard cap for inverted polarity (malicious called benign or vice versa).
    capped = False
    gt_pol = _POLARITY[gt.disposition]
    v_pol = _POLARITY[v.disposition]
    if gt_pol != 0 and v_pol != 0 and gt_pol != v_pol and total > WRONG_POLARITY_CAP:
        total = float(WRONG_POLARITY_CAP)
        capped = True

    return Report(gt.scenario_id, total, _band(total), items, capped)
