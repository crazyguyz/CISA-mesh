"""v5.0.8 - Single source of truth for asset "display IDs" (ma tai san).

Why this module exists
----------------------
Before v5.0.8 the human-readable asset code was generated in SIX places with
FOUR different formats, so the Assets page showed a mix of 8-, 11-, 13- and
32-character values:

  db_postgres.insert_machine_config  computer  "PC-"  + uuid4[:8]      -> 11
  db_postgres.insert_machine_config  monitor   never assigned (bug)    -> 32 (raw md5)
  db_manager.insert_machine_config   computer  "PC-"  + uuid4[:8]      -> 11
  db_manager.insert_machine_config   monitor   "MN-"  + uuid4[:8]      -> 11
  upsert_inventory_asset/_new_display_id       "TS-<XX>-" + uuid4[:6]  -> 12/13
  asset_discovery / sync_user_assets           md5[:8], no prefix      -> 8

The 32-character values are the worst: when display_id was empty the API/UI
fell back to the raw md5 `asset_id`, which is unreadable in the asset list and
the Excel export.

Canonical format (one scheme for every asset type)
--------------------------------------------------
    {PREFIX}-{8 uppercase hex}          e.g. PC-0887498B, MN-1A2B3C4D

Always 11 characters, always has a prefix that tells the reader what the asset
is. Codes are stored in the database, so existing codes are never rewritten:
this module only decides the format of NEW codes and provides a deterministic
derivation used by the backfill tool and the API fallback.

Deterministic mode: pass `seed` (normally the asset_id) and the same seed always
yields the same code. That keeps the value shown by the dashboard identical to
the value the backfill tool stores.
"""

import hashlib
import re

# category -> prefix. Categories come from assets_inventory.category, from
# asset_discovery's classification and from the computer/monitor tables.
DISPLAY_PREFIXES = {
    "computer": "PC",
    "monitor": "MN",
    "printer": "PR",
    "phone": "DT",
    "network_device": "NM",
    "peripheral": "NV",
    "component": "LK",
    "user": "US",
    "other": "TS",
}

DEFAULT_PREFIX = "TS"

# Canonical form: 2-letter prefix, dash, 8 uppercase hex characters.
DISPLAY_ID_RE = re.compile(r"^[A-Z]{2}-[0-9A-F]{8}$")

DISPLAY_ID_LEN = 11


def display_prefix(category):
    """Prefix for a category ('computer' -> 'PC'); unknown/empty -> 'TS'."""
    return DISPLAY_PREFIXES.get((category or "").strip().lower(), DEFAULT_PREFIX)


def make_display_id(category, seed=None, prefix=None):
    """Build a canonical display id: 'PC-0887498B' (11 chars).

    seed=None   -> random code (used when a brand new asset row is created).
    seed=<str>  -> deterministic code derived from the seed (idempotent, so a
                   re-run of the backfill or a second API read yields the same
                   value).
    prefix      -> override the category prefix (rarely needed).
    """
    pfx = (prefix or display_prefix(category)).upper()
    if seed is None:
        import uuid
        digest = uuid.uuid4().hex[:8].upper()
    else:
        digest = hashlib.md5(str(seed).encode("utf-8")).hexdigest()[:8].upper()
    return "%s-%s" % (pfx, digest)


def is_canonical(display_id):
    """True when display_id already follows the v5.0.8 scheme."""
    return bool(DISPLAY_ID_RE.match((display_id or "").strip().upper()))


def derive_for_asset(category, asset_id):
    """Canonical code for an asset whose display_id is missing/blank.

    Used by tools/backfill_display_ids.py and by the API/UI fallback so that a
    row without a stored code is still shown as 'PC-XXXXXXXX' instead of a
    32-character md5 hash.
    """
    if not (asset_id or "").strip():
        return ""
    return make_display_id(category, seed=asset_id)
