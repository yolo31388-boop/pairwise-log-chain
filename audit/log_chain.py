"""Tamper-evident audit-log chaining helpers.

The chain is a list of records.  Every record stores a ``seq`` number, an
optional ``time``, the event fields, and a ``hash`` covering **all** of the
other fields plus the previous record's hash::

    hash_n = H(domain || prev_hash || canonical(event_without_hash))

Because the hash covers every field, changing the message, timestamp, actor,
or any other attribute breaks verification.  ``canonical_event`` produces a
byte-for-byte stable representation (sorted keys, no insignificant
whitespace), so every node computes the same digest for the same event.

The first record of a chain uses :data:`GENESIS_HASH` as its predecessor.
For a retained/archived slice, pass the externally anchored hash of the last
pruned record as ``genesis`` and the original sequence number as
``start_seq``; the anchor must be stored somewhere the retention job cannot
rewrite (object-lock bucket, WORM store, external timestamping service).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping

__all__ = [
    "GENESIS_HASH",
    "canonical_event",
    "event_hash",
    "verify_chain",
    "redact",
    "anchor",
]

#: Predecessor value used by the first record of a fresh chain.
GENESIS_HASH = "0"

#: Domain separator so an audit-chain digest can never be confused with a
#: digest produced by another protocol over the same payload.
_HASH_DOMAIN = b"audit-log-chain:v1\x00"

_ID_RE = re.compile(r"(?<!\d)(\d{6})(\d{8})(\d{3}[\dXx])(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)(1[3-9]\d)(\d{4})(\d{4})(?!\d)")


# ---------------------------------------------------------------------------
# Stable canonicalisation
# ---------------------------------------------------------------------------

def _normalise(value: Any) -> Any:
    """Convert ``value`` to a JSON-compatible, deterministic structure.

    Mapping keys are stringified so ``sort_keys`` can never compare mixed key
    types, and unordered containers (sets) are sorted so their serialisation
    does not depend on hash randomisation.
    """
    if isinstance(value, Mapping):
        return {str(key): _normalise(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_normalise(item) for item in value]
        return sorted(items, key=lambda item: canonical_event(item))
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    return value


def canonical_event(event: Any) -> str:
    """Return a stable JSON representation of ``event``.

    ``sort_keys`` removes dependence on insertion order and the compact
    separators remove dependence on whitespace.  ``ensure_ascii=False`` keeps
    non-ASCII text in its UTF-8 form, which is itself deterministic.
    """
    return json.dumps(
        _normalise(event),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def event_hash(prev_hash: Any, event: Any) -> str:
    """Hash an event together with its predecessor's hash.

    The predecessor is length-prefixed so that ``prev="ab", event="c"`` and
    ``prev="a", event="bc"`` cannot collide.
    """
    if isinstance(prev_hash, str):
        prev_bytes = prev_hash.encode("utf-8")
    else:
        prev_bytes = canonical_event(prev_hash).encode("utf-8")
    body = canonical_event(event).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(_HASH_DOMAIN)
    digest.update(len(prev_bytes).to_bytes(8, "big"))
    digest.update(prev_bytes)
    digest.update(body)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

def _time_key(value: Any) -> float | None:
    """Normalise a timestamp for ordering checks.

    ``None`` means "no timestamp supplied".  Numbers are treated as epoch
    seconds; ISO-8601 strings are parsed (a missing offset is assumed UTC).
    A value that is present but unusable raises ``ValueError`` so verification
    fails closed instead of silently skipping the clock-order check.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("boolean is not a timestamp")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    raise ValueError("unsupported timestamp type")


def verify_chain(
    chain: Iterable[Mapping[str, Any]],
    *,
    genesis: str = GENESIS_HASH,
    start_seq: int = 1,
    check_time: bool = True,
    expected_head: str | None = None,
) -> bool:
    """Verify sequence continuity, clock order, and every record hash.

    Parameters
    ----------
    chain:
        Records in chain order.  Records must be mappings containing at least
        ``seq`` and ``hash``; the hash is computed over all remaining fields.
    genesis:
        Hash of the record immediately before ``chain``.  Use the anchored
        head of a pruned archive when verifying a retained slice.
    start_seq:
        Expected ``seq`` of the first record (``1`` for a fresh chain).
    check_time:
        Reject records whose ``time`` decreases relative to the previous
        record, catching clock skew and reordered events.
    expected_head:
        When supplied, also require the final record's hash to equal this
        externally anchored value, detecting truncation of the tail.

    Returns
    -------
    bool
        ``True`` only if the whole chain is intact.
    """
    prev_hash = str(genesis)
    expected_seq = start_seq
    last_time: float | None = None

    try:
        records = iter(chain)
    except TypeError:
        return False

    for record in records:
        if not isinstance(record, Mapping):
            return False

        seq = record.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int):
            return False
        if seq != expected_seq:
            # Gaps, duplicates, and out-of-order records all land here.
            return False
        expected_seq += 1

        stored_hash = record.get("hash")
        if not isinstance(stored_hash, str) or not stored_hash:
            return False

        payload = {key: value for key, value in record.items() if key != "hash"}
        computed = event_hash(prev_hash, payload)
        if not hmac.compare_digest(
            stored_hash.encode("utf-8"), computed.encode("ascii")
        ):
            return False

        if check_time:
            try:
                stamp = _time_key(record.get("time"))
            except (TypeError, ValueError):
                return False
            if stamp is not None:
                if last_time is not None and stamp < last_time:
                    return False
                last_time = stamp

        prev_hash = stored_hash

    if expected_head is not None:
        return hmac.compare_digest(
            prev_hash.encode("utf-8"), str(expected_head).encode("utf-8")
        )
    return True


# ---------------------------------------------------------------------------
# PII redaction
# ---------------------------------------------------------------------------

def _redact_text(text: str) -> str:
    # 18-digit PRC resident identity number: keep region (6) and tail (4).
    text = _ID_RE.sub(
        lambda match: match.group(1) + "*" * 8 + match.group(3), text
    )
    # 11-digit mainland mobile number: keep prefix (3) and tail (4).
    text = _PHONE_RE.sub(
        lambda match: match.group(1) + "*" * 4 + match.group(3), text
    )
    return text


def redact(value: Any) -> Any:
    """Mask phone numbers and identity numbers in strings (recursively).

    Non-string leaves are returned unchanged so this can be applied directly
    to an event before it is written and hashed.
    """
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


# ---------------------------------------------------------------------------
# External head anchoring
# ---------------------------------------------------------------------------

def anchor(head: str, proof: Any) -> bool:
    """Check an external attestation for ``head``.

    ``proof`` is the record returned by the anchoring mechanism (WORM bucket
    metadata, RFC 3161 receipt wrapper, ...).  A boolean ``head`` field is an
    explicit attestation result.  A string is the anchored digest and must
    match ``head`` exactly.

    Anchors must live outside the retention window; they are what makes
    deletion of old records or truncation of the tail detectable.
    """
    if not head:
        return False

    if isinstance(proof, str):
        return hmac.compare_digest(str(head).encode("utf-8"), proof.encode("utf-8"))
    if not isinstance(proof, Mapping):
        return False

    attested = proof.get("head")
    if isinstance(attested, bool):
        return attested
    if isinstance(attested, str):
        return hmac.compare_digest(
            str(head).encode("utf-8"), attested.encode("utf-8")
        )
    return False
