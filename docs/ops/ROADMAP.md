# Roadmap

Last updated: 2026-09-19
Status: Active

## Scope Synchronization
This roadmap does not redefine `docs/.ssot/PRD.md` or `docs/.ssot/contracts/*`; it only manages execution priorities.

## Near-term (Now)
1. Close P0/P1 stability issues together with contracts and tests.
2. Regularly review the governance gates (SSOT precedence, consistency, absolute-date, traceability).
3. Automate the doc-code consistency verification routine (pre-release).

## Implemented
- Issue #24: loaded-input identity verification and removal of path/function-count similarity keys. See [Routing Contract v2](../.ssot/contracts/routing_contract.md#loaded-input-identity); implementation: `src/ida_multi_mcp/router.py`, `src/ida_multi_mcp/identity.py`, and `src/ida_multi_mcp/tools/similarity.py`.

## Mid-term
1. Formalize contract versioning (compatible/incompatible) operational procedures.
2. Split decision records (ADRs) into finer units and strengthen history linkage.
3. Consider turning operational diagnostics (pre/post-install auto-diagnosis) into actual automated scripts.

## N/A
- Runbook: N/A (no on-call/service operation model at this time)
