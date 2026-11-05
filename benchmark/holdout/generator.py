"""Held-out scenario generator: a SEPARATE generator with a different seed and different
parameter ranges than benchmark/scenarios/generator.py. It is run against detectors frozen at
git tag detectors-v1 (see FROZEN_DETECTORS.json); the runner refuses to call results
"held-out" if the detector code no longer matches the frozen hashes.

Ranges deliberately include edges the main set avoids: replica private + cold cache, the
largest sensitive-doc count, an export that runs past the end of the archive (so only part of it
matches), larger campaigns and uploads.
"""
from __future__ import annotations

import random

HOLDOUT_SEED = 7919


def variants() -> list[tuple[str, dict]]:
    r = random.Random(f"holdout-{HOLDOUT_SEED}")
    return [
        ("HERO-01", {"access_variant": "A", "replica_public": False, "cdn_cached": False}),
        ("HERO-01", {"access_variant": "B", "replica_public": True, "cdn_cached": False}),
        ("D-02", {"access_variant": "A", "n_sensitive": 4, "rows_per_doc": r.randint(45, 60), "variant_seed": r.randint(20_000, 30_000)}),
        ("D-03", {"access_variant": "A", "rows": r.randint(500, 700), "start": 4500}),
        ("D-04", {"members": r.randint(2500, 3000), "variant_seed": r.randint(20_000, 30_000)}),
        ("D-05", {"rows": r.randint(350, 450), "variant_seed": r.randint(20_000, 30_000)}),
        ("PAN-DISCOVERY", {"variant_seed": r.randint(20_000, 30_000), "rows": 300}),
        ("UNAPPROVED-API", {"variant_seed": r.randint(20_000, 30_000)}),
        ("AI-TRAINING-DATA-LEAK", {"variant_seed": r.randint(20_000, 30_000)}),
    ]
