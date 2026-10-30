# SOV-018: demo digest/matching profile (OD-15)

**Version:** 0.1.
**Date:** 2026-10-30.
**Task:** [SOV-018](https://github.com/apil-khadka/Sovra/issues/22)
(local extraction, protected digests, provenance).
**Profile name:** `mip-digest-v1`.

This record freezes OD-15 for the synthetic demo: the digest
functions, canonicalization, normalization, and matching semantics
used by local extraction. SOV-018 Java work must implement exactly
this profile; any deviation needs a new recorded revision and
re-review. The profile pins the demo decision only — production
selection criteria stay open and are listed in section 6.

## 1. Digest functions

| Purpose | Function | Output |
| --- | --- | --- |
| Source bytes | SHA-256 over the exact decrypted vault bytes | 32 bytes |
| Field values, canonical | SHA-256 over the canonical field bytes (section 3) | 32 bytes |
| Field values, exact | SHA-256 over the UTF-8 observed string, unmodified | 32 bytes |

All three digests are integrity references inside authorized
reads. None is a lookup key: no index, no query, and no endpoint
resolves rows by digest (DR-15, SR-24).

## 2. Field normalization (`normalizer-v1`)

Each observed string maps to one normalized string:

1. Unicode NFC.
2. Trim leading and trailing whitespace (Unicode-aware).
3. Collapse each interior whitespace run to one ASCII space.
4. Case-fold to lowercase for `name` and `country` only;
   `document_number`, `date_of_birth`, and `expiry_date` keep case.

Unknown fields normalize with steps 1–3 and no case rule. The
normalizer identifier is stored per run so a later profile change
cannot silently re-encode old values. The engine identifier
versions the whole pipeline: a normalizer or canonicalization
change ships a new `engine_id`, and the per-source unique key
then treats re-extraction as a new run rather than an update.

## 3. Canonical field bytes (`canon-v1`)

The canonical bytes of one normalized string are its UTF-8
encoding with no length prefix, no separator, and no framing;
digests are computed per field, never over concatenated records.
Multi-byte input is valid UTF-8 by construction (the source text
decodes as UTF-8 or extraction terminates before matching).

## 4. Matching rules

- `exact`: `exact_digest` equality over observed strings.
- `canonical`: `canonical_digest` equality, so NFC/whitespace/case
  variants of the same value match under `normalizer-v1`.
- A match on either digest is a candidate hit, never a live-data
  decision: the synthetic demo terminates before any live-data
  path, and each match carries its full provenance chain
  (section 5). Refreshing digests after a profile change is a
  re-extraction, not an update — revisions are append-only.

## 5. Provenance recorded per run

Every extraction run records: source vault object and version,
`source_digest`, `engine_id`, `schema_id`, `normalizer_id`,
`canon_id`, the revision chain with per-revision
`canonical_digest`/`exact_digest` and confidence, the approver,
and the approval revision. AC-10/11/12 are verified against
these fields: wrong-source input terminates, matching uses
current approved digests, and stale approvals cannot authorize.

## 6. What stays open for production

This freeze covers the demo only. Before any live-data use,
SOV-018 must additionally resolve: the production engine and
schema registry, live OCR/parse accuracy gates, the live-only
profile identifier (distinct from `mip-digest-v1`), key custody
for digest-anchored artifacts, and independent review (SOV-037).
