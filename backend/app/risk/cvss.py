"""CVSS v3.1 base score calculator (specification-accurate).

Implements the base metric equations from the FIRST CVSS v3.1 spec, including
the integer-based roundup. Given a vector string it returns score + severity.
"""
import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
       "C": {"N": 0.85, "L": 0.68, "H": 0.50}}  # PR differs when scope changes


def _roundup(value: float) -> float:
    i = round(value * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse(vector: str) -> dict:
    body = vector.replace("CVSS:3.1/", "")
    return dict(p.split(":") for p in body.split("/") if ":" in p)


def base_score(vector: str) -> float:
    m = parse(vector)
    scope = m["S"]
    av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
    pr = _PR[scope][m["PR"]]
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def rate(vector: str) -> dict:
    full = vector if vector.startswith("CVSS:3.1/") else "CVSS:3.1/" + vector
    s = base_score(vector)
    return {"vector": full, "score": s, "severity": severity(s)}


if __name__ == "__main__":
    # sanity: known reference vectors
    checks = [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # classic critical RCE-style
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),   # authn info disclosure
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # scope-changed full compromise
    ]
    for vec, expected in checks:
        got = base_score(vec)
        print(f"{'OK ' if got == expected else 'XX '}{vec} -> {got} (expected {expected})")
