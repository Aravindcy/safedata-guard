"""
Generate realistic-but-synthetic datasets for examples and benchmarks.

No real personal data is used. Names/emails/accounts are fabricated from simple
templates and random values. Run:

    python scripts/make_datasets.py

Writes CSVs into datasets/ (banking, insurance, energy, healthcare, sales
renewals, complaints). These are deliberately small (a few thousand rows) so the
repo stays light and examples run fast.
"""

import os
import numpy as np
import pandas as pd

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "datasets")
RNG = np.random.default_rng(2025)

FIRST = ["James", "Mary", "Mohammed", "Priya", "Wei", "Sofia", "Liam", "Aisha",
         "Carlos", "Yuki", "Olu", "Hannah", "Ivan", "Fatima", "Noah", "Mei"]
LAST = ["Smith", "Patel", "Khan", "Garcia", "Chen", "Okafor", "Nguyen", "Rossi",
        "Kowalski", "Ahmed", "Brown", "Andersson", "Silva", "Tanaka", "Ali"]
CITIES = ["London", "Manchester", "Birmingham", "Leeds", "Bristol", "Glasgow",
          "Liverpool", "Cardiff"]


def _people(n):
    first = RNG.choice(FIRST, n)
    last = RNG.choice(LAST, n)
    full = [f"{a} {b}" for a, b in zip(first, last)]
    email = [f"{a.lower()}.{b.lower()}{i}@example.com"
             for i, (a, b) in enumerate(zip(first, last))]
    return full, email


def banking(n=2000):
    full, email = _people(n)
    return pd.DataFrame({
        "customer_id": [f"CUS{i:06d}" for i in range(n)],
        "full_name": full,
        "email": email,
        "sort_code": [f"{RNG.integers(10,99)}-{RNG.integers(10,99)}-{RNG.integers(10,99)}" for _ in range(n)],
        "account_number": [f"{RNG.integers(10**7, 10**8)}" for _ in range(n)],
        "city": RNG.choice(CITIES, n),
        "product": RNG.choice(["Current", "Savings", "Credit Card", "Loan", "Mortgage"], n),
        "balance": np.round(RNG.normal(5000, 8000, n), 2),
        "monthly_txns": RNG.integers(0, 120, n),
    })


def insurance(n=1500):
    full, email = _people(n)
    return pd.DataFrame({
        "policy_id": [f"POL{i:06d}" for i in range(n)],
        "claimant_name": full,
        "email": email,
        "postcode": [f"{RNG.choice(list('ABEGLMNS'))}{RNG.integers(1,99)} {RNG.integers(1,9)}{RNG.choice(list('ABDEFGH'))}{RNG.choice(list('JKLNPQ'))}" for _ in range(n)],
        "claim_type": RNG.choice(["Auto", "Home", "Travel", "Health", "Liability"], n),
        "region": RNG.choice(CITIES, n),
        "claim_amount": np.round(RNG.gamma(2.0, 1500, n), 2),
        "settled": RNG.choice([True, False], n, p=[0.7, 0.3]),
        "days_to_settle": RNG.integers(1, 180, n),
    })


def energy(n=2000):
    full, email = _people(n)
    return pd.DataFrame({
        "meter_id": [f"MTR{i:07d}" for i in range(n)],
        "customer_name": full,
        "email": email,
        "postcode_area": RNG.choice(["E1", "M2", "B3", "LS1", "BS4", "G5"], n),
        "tariff": RNG.choice(["Standard", "Economy7", "Green", "Fixed12"], n),
        "kwh_monthly": np.round(RNG.normal(310, 120, n).clip(10), 1),
        "peak_kw": np.round(RNG.uniform(1.0, 12.0, n), 2),
        "has_solar": RNG.choice([True, False], n, p=[0.15, 0.85]),
    })


def healthcare(n=1200):
    full, _ = _people(n)
    return pd.DataFrame({
        "patient_id": [f"PT{i:06d}" for i in range(n)],
        "patient_name": full,
        "nhs_number": [f"{RNG.integers(100,999)} {RNG.integers(100,999)} {RNG.integers(1000,9999)}" for _ in range(n)],
        "department": RNG.choice(["Cardiology", "Oncology", "Neurology",
                                  "Pediatrics", "Orthopedics", "ER"], n),
        "age": RNG.integers(0, 98, n),
        "los_days": RNG.integers(0, 40, n),
        "treatment_cost": np.round(RNG.gamma(2.0, 3000, n), 2),
    })


def sales_renewals(n=1800):
    full, email = _people(n)
    return pd.DataFrame({
        "account_id": [f"ACC{i:06d}" for i in range(n)],
        "contact_name": full,
        "contact_email": email,
        "segment": RNG.choice(["SMB", "Mid-Market", "Enterprise"], n),
        "region": RNG.choice(CITIES, n),
        "arr": np.round(RNG.gamma(2.0, 12000, n), 2),
        "renewed": RNG.choice([True, False], n, p=[0.78, 0.22]),
        "months_to_renewal": RNG.integers(0, 12, n),
    })


def complaints(n=1600):
    full, email = _people(n)
    return pd.DataFrame({
        "case_id": [f"CASE{i:06d}" for i in range(n)],
        "customer_name": full,
        "email": email,
        "channel": RNG.choice(["Phone", "Email", "Chat", "Branch"], n),
        "category": RNG.choice(["Billing", "Fraud", "Service", "Technical", "Other"], n),
        "region": RNG.choice(CITIES, n),
        "resolved": RNG.choice([True, False], n, p=[0.65, 0.35]),
        "resolution_hours": np.round(RNG.gamma(2.0, 8, n), 1),
    })


GENERATORS = {
    "banking_transactions": banking,
    "insurance_claims": insurance,
    "energy_consumption": energy,
    "healthcare_admissions": healthcare,
    "sales_renewals": sales_renewals,
    "customer_complaints": complaints,
}


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, gen in GENERATORS.items():
        df = gen()
        path = os.path.join(OUT, f"{name}.csv")
        df.to_csv(path, index=False)
        print(f"wrote {path}  ({len(df)} rows, {len(df.columns)} cols)")


if __name__ == "__main__":
    main()
