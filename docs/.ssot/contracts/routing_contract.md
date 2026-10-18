# Routing Contract

Last updated: 2026-09-19
Version: v2

## Authority
This contract defines the required inputs and error shape for IDA tool routing requests.

## Rules
- Every IDA tool call must include `instance_id`.
- If missing or invalid, the response must contain the following fields:
  - `error`
  - `hint`
  - `available_instances` (when applicable)

## Loaded Input Identity
- Before forwarding, compare the registration's `input_fingerprint` and normalized module name with `ida://idb/identity`.
- `input_fingerprint` is an IDB-stored original-input digest: `{algorithm: "sha256" | "md5", digest: <hex>}`. Prefer SHA-256; MD5 is a compatibility fallback, not a collision-resistant security guarantee.
- Missing, malformed, unavailable, or mismatched identity blocks forwarding with `error` and a recovery `hint`. Legacy registrations must be recreated after updating/restarting the plugin; managed sessions must be reopened.
- Successful identity reads may be cached for five seconds, bound to the endpoint and registration identity. Changes within that interval and changes after verification but before execution remain outside this guard's guarantee.
- Identity describes the input recorded by IDA, not subsequent IDB edits or replacement of the original file on disk. Do not hash the current disk file as a substitute for the loaded input.
- Similarity indexes require an IDB-provided input digest; path plus function count is not an acceptable fallback key.

## Traceability
- Implementation: `src/ida_multi_mcp/router.py`
- Error envelope shaping: `src/ida_multi_mcp/server.py`
- Digest normalization and IDB reads: `src/ida_multi_mcp/identity.py`
- Identity resource: `src/ida_multi_mcp/ida_mcp/api_resources.py`
- Identity transport: `src/ida_multi_mcp/health.py`
- Similarity index keys: `src/ida_multi_mcp/tools/similarity.py`
