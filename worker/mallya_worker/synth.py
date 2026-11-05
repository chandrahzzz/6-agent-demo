"""Deterministic synthetic data for the fictional Meridian Bank. Nothing here is real.

* Names are built from invented syllables, so they cannot belong to a real person.
* PAN-shaped values follow the public format but are random; Aadhaar-shaped values are
  random digits with a Verhoeff check digit. Neither was ever issued to anyone.
* Emails use the reserved .test TLD.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from mallya_common.verhoeff import check_digit, checksum_ok

L = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_ON = ["ar", "be", "ka", "lo", "mi", "na", "pra", "ri", "sa", "ta", "ve", "yo", "dha", "ish", "ku", "zen"]
_MID = ["va", "ni", "ra", "le", "mo", "shi", "ta", "du", "ke", "ya"]
_END = ["n", "a", "esh", "ika", "ar", "it", "on", "el", "ya", "um"]
SEGMENTS = ["retail", "retail", "retail", "premium", "sme", "nri"]


def _name(r: random.Random) -> str:
    def part() -> str:
        return (r.choice(_ON) + r.choice(_MID) + r.choice(_END)).capitalize()
    return f"{part()} {part()}"


def synthetic_pan(r: random.Random, surname_initial: str) -> str:
    return (
        "".join(r.choice(L) for _ in range(3)) + "P" + surname_initial.upper()
        + "".join(r.choice("0123456789") for _ in range(4)) + r.choice(L)
    )


def synthetic_aadhaar(r: random.Random) -> str:
    payload = r.choice("23456789") + "".join(r.choice("0123456789") for _ in range(10))
    return payload + check_digit(payload)


def decoy_invoice_number(r: random.Random) -> str:
    """12 digits that deliberately FAIL Verhoeff (decoy)."""
    while True:
        n = r.choice("23456789") + "".join(r.choice("0123456789") for _ in range(11))
        if not checksum_ok(n):
            return n


def decoy_sku(r: random.Random) -> str:
    """Product SKU that is PAN-shaped (ABCDE1234F style) - must not be flagged as a customer PAN."""
    return "".join(r.choice(L) for _ in range(5)) + "".join(r.choice("0123456789") for _ in range(4)) + r.choice(L)


@dataclass
class Customer:
    customer_id: str
    account_id: str
    full_name: str
    pan: str
    aadhaar: str
    phone: str
    email: str
    segment: str
    created_at: date
    marketing_consent: str  # granted | withdrawn
    marketing_consent_changed_at: datetime
    analytics_consent: str
    third_party_consent: str
    retention_class: str
    retain_until: date
    retention_last_reviewed: date | None


def customers(seed: int, n: int = 5000) -> list[Customer]:
    r = random.Random(f"meridian-customers-{seed}")
    out: list[Customer] = []
    seen_pan: set[str] = set()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(1, n + 1):
        name = _name(r)
        surname = name.split()[-1]
        pan = synthetic_pan(r, surname[0])
        while pan in seen_pan:
            pan = synthetic_pan(r, surname[0])
        seen_pan.add(pan)
        first, last = (p.lower() for p in name.split())
        withdrawn = r.random() < 0.062
        created = date(2015, 1, 1) + timedelta(days=r.randrange(0, 4000))
        out.append(Customer(
            customer_id=f"MRD-{i:06d}",
            account_id="ACC" + "".join(r.choice("0123456789") for _ in range(10)),
            full_name=name,
            pan=pan,
            aadhaar=synthetic_aadhaar(r),
            phone="+91 " + r.choice("6789") + "".join(r.choice("0123456789") for _ in range(9)),
            email=f"{first}.{last}{r.randrange(10, 99)}@meridian-customer.test",
            segment=r.choice(SEGMENTS),
            created_at=created,
            marketing_consent="withdrawn" if withdrawn else "granted",
            marketing_consent_changed_at=base + timedelta(days=r.randrange(0, 300), minutes=r.randrange(0, 1440)),
            analytics_consent="granted" if r.random() < 0.8 else "withdrawn",
            third_party_consent="granted" if r.random() < 0.35 else "not_given",
            retention_class=r.choice(["standard-8y", "standard-8y", "kyc-10y"]),
            retain_until=created + timedelta(days=365 * 8),
            retention_last_reviewed=date(2026, 1, 1) + timedelta(days=r.randrange(0, 200)),
        ))
    return out


CSV_COLUMNS = ["customer_id", "account_id", "full_name", "pan", "aadhaar", "phone", "email", "segment"]


def customers_csv(rows: list[Customer], columns: list[str] = CSV_COLUMNS) -> bytes:
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(columns)
    for c in rows:
        w.writerow([getattr(c, col) for col in columns])
    return buf.getvalue().encode("utf-8")


def products_csv(seed: int, n: int = 400) -> bytes:
    r = random.Random(f"products-{seed}")
    lines = ["sku,product_name,category,unit_price_inr"]
    cats = ["cards", "lockers", "forex", "insurance", "deposits"]
    for i in range(n):
        lines.append(f"{decoy_sku(r)},Product {i + 1:03d},{r.choice(cats)},{r.randrange(100, 9999)}")
    return ("\n".join(lines) + "\n").encode()


def invoices_csv(seed: int, n: int = 300) -> bytes:
    r = random.Random(f"invoices-{seed}")
    lines = ["invoice_number,vendor,amount_inr,issued_on"]
    for i in range(n):
        lines.append(f"{decoy_invoice_number(r)},Supplier {r.randrange(1, 40):02d},{r.randrange(1000, 900000)},2026-0{r.randrange(1, 10)}-1{r.randrange(0, 9)}")
    return ("\n".join(lines) + "\n").encode()


def harmless_doc(r: random.Random, title: str) -> bytes:
    paras = [
        "This note describes the quarterly operating rhythm for the platform team.",
        "Owners should review dashboards every Monday and record decisions in the tracker.",
        "Escalations follow the standard on-call rota; see the runbook index for details.",
        "Capacity planning assumes 20 percent headroom on all shared clusters.",
        "No customer data is included in this document.",
    ]
    r.shuffle(paras)
    return (f"# {title}\n\n" + "\n\n".join(paras) + "\n").encode()
