# 21. Architecture Problems Specification

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Scope
- Subject: current `ida-multi-mcp` architecture (2026-02-17)
- Evidence sources: existing SSOT documents + actual code (`src/ida_multi_mcp/**`) + tests (`tests/**`)
- Goal: identify problems in the current structure/features and finalize impact and remediation spec

## Severity Criteria
- `P0`: immediate, critical impact on functionality/reliability/safety
- `P1`: operational outage / data inconsistency / serious quality degradation risk
- `P2`: medium-term maintainability/consistency/extensibility degradation
- `P3`: minor defects or documentation/diagnostic quality issues

## Problem Specifications

### P0

#### AP-P0-01 Expiry-reason field key mismatch causes cause-tracking failure
- Evidence:
  - `src/ida_multi_mcp/registry.py:244` stores `expired.reason`
  - `src/ida_multi_mcp/router.py:189`, `src/ida_multi_mcp/router.py:199` look up `expire_reason`
- Problem:
  - Expiry reason is always reported as `unknown`, polluting recovery guidance.
- Impact:
  - Root-cause tracking fails during incident response; auto-recovery hint quality degrades.
- Spec (fix required):
  - Router should read `reason` first and allow `expire_reason` as a fallback for backward compatibility.

#### AP-P0-02 User-specified registry path diverges from plugin registration path
- Evidence:
  - Server/CLI support `--registry`: `src/ida_multi_mcp/__main__.py:909`, `src/ida_multi_mcp/__main__.py:925`
  - Plugin registration uses a fixed path only: `src/ida_multi_mcp/plugin/registration.py:28`, `src/ida_multi_mcp/plugin/registration.py:50`, `src/ida_multi_mcp/plugin/registration.py:73`
- Problem:
  - Launching the server with a custom registry causes the IDA plugin to register in a different file, making instances invisible.
- Impact:
  - False "no instances" reports and real operational failure.
- Spec (fix required):
  - Unify the plugin registration path so it can be injected via environment variable/config.

### P1

#### AP-P1-01 Corrupt registry JSON halts all functionality
- Evidence: `src/ida_multi_mcp/registry.py:65-66`
- Problem:
  - `json.load` exceptions are not recovered, so a single file corruption can fail all commands.
- Impact:
  - Server startup failure; list/route fully blocked.
- Spec (fix required):
  - On corruption detection, quarantine as backup (`instances.json.bak`) and auto-recover to the default structure.

#### AP-P1-02 decompile_to_file single-mode filename collisions drop results
- Evidence: `src/ida_multi_mcp/server.py:433-437`
- Problem:
  - With same-name functions (namespace/overload/demangle collisions), earlier files are overwritten.
- Impact:
  - Missing or distorted results; reduced reproducibility of analysis.
- Spec (fix required):
  - Include the address in the filename (`{safe_name}_{addr}.c`), or increment a suffix on collision.

#### AP-P1-03 Binary-change verification is filename-based, allowing false positives/negatives
- Evidence:
  - Name comparison: `src/ida_multi_mcp/router.py:122-123`
  - Uses name rather than path: `src/ida_multi_mcp/router.py:88-89`
- Problem:
  - Same-filename samples under different paths can be incorrectly judged as matching.
- Impact:
  - Risk of cross-binary contamination in analysis.
- Spec (fix required):
  - Strengthen via composite verification of `module` + `input_file` + `idb_path`.

#### AP-P1-04 Fail-open policy on binary verification permits stale routing
- Evidence: `src/ida_multi_mcp/router.py:118-120`
- Problem:
  - Requests still pass when metadata lookup fails, risking misrouting to a stale instance.
- Impact:
  - Tools may execute against the wrong target.
- Spec (fix required):
  - At minimum, return a `warning` meta; or provide a configurable strict mode (default strict recommended).

#### AP-P1-05 Install flow continues to succeed after prerequisite ImportError
- Evidence: install continues after `src/ida_multi_mcp/__main__.py:811-814` (`:815+`)
- Problem:
  - Even with missing dependencies, plugin deployment and success messages proceed.
- Impact:
  - Users are misled to think installation succeeded while load actually fails.
- Spec (fix required):
  - On prerequisite failure, exit non-zero and abort installation.

#### AP-P1-06 Uninstall recursively removes the entire `~/.ida-mcp` directory
- Evidence: `src/ida_multi_mcp/__main__.py:866-869`
- Problem:
  - Risk of over-deletion if future state files / operational metadata are stored there.
- Impact:
  - Loss of operational state / forensic history.
- Spec (fix required):
  - Delete only owned files (allowlist), or back up before deletion.

### P2

#### AP-P2-01 Pre-validating `active_instance` before IDA tool execution conflicts with the routing contract
- Evidence: `src/ida_multi_mcp/server.py:223-230`
- Problem:
  - Actual routing is based on explicit `instance_id`, yet a failed pre-check for `active` can reject the entire call.
- Impact:
  - False-negative errors in edge states.
- Spec (fix required):
  - Remove the pre-check and delegate to the router.

#### AP-P2-02 Static tool schema is narrower than the actual feature surface, introducing contract drift
- Evidence:
  - Static schema: 34 tools (`ida_tool_schemas.json`)
  - Actual APIs include more tools/resources (`api_debug`, `api_resources`)
- Problem:
  - Tool listings differ significantly between IDA-disconnected and IDA-connected states.
- Impact:
  - Unstable client-side tool planning.
- Spec (fix required):
  - Introduce a build-time pipeline that auto-generates/syncs the full schema.

#### AP-P2-03 decompile_to_file lacks safeguards for large-scale execution
- Evidence:
  - `all=true` path: `src/ida_multi_mcp/server.py:340-379`
  - IDA single-thread constraint: `src/ida_multi_mcp/ida_mcp/sync.py:129-136`
- Problem:
  - For binaries with many functions, long blocking effectively halts the service.
- Impact:
  - Other requests stall during long jobs.
- Spec (fix required):
  - Enforce function-count caps, confirmation prompts, and progress + cancellation support.

#### AP-P2-04 Router error responses lose the actual instance_id
- Evidence: `src/ida_multi_mcp/router.py:163` (`instance_info.get("id", "unknown")`)
- Problem:
  - `instance_info` has no `id` field, so `unknown` is recorded in most cases.
- Impact:
  - Harder incident diagnosis.
- Spec (fix required):
  - Explicitly pass/include the caller-context `instance_id`.

#### AP-P2-05 health cleanup function's timeout parameter is effectively unused
- Evidence:
  - Signature: `src/ida_multi_mcp/health.py:96`
  - Logic uses only process-alive: `src/ida_multi_mcp/health.py:116-121`
- Problem:
  - API contract does not match behavior.
- Impact:
  - Maintainer confusion and incorrect operational tuning.
- Spec (fix required):
  - Remove the parameter, or actually implement heartbeat-based cleanup.

#### AP-P2-06 Install messaging/commands do not match actual CLI flags
- Evidence:
  - Loader text: `src/ida_multi_mcp/plugin/ida_multi_mcp_loader.py:13` (`ida-multi-mcp install`)
  - Actual CLI is `--install`: `src/ida_multi_mcp/__main__.py:889`
- Problem:
  - Mis-operation possible during on-site install.
- Impact:
  - Higher onboarding failure rate.
- Spec (fix required):
  - Correct the wording to match the actual command.

### P3

#### AP-P3-01 Registry/cache access-permission hardening is unspecified
- Evidence:
  - No permission policy at registry creation: `src/ida_multi_mcp/registry.py:37`
  - Cache is plaintext in-memory; protection boundaries poorly documented: `src/ida_multi_mcp/cache.py`
- Problem:
  - Unclear least-privilege policy in local multi-user environments.
- Impact:
  - Potential findings in security audits.
- Spec (fix required):
  - Specify/enforce file-creation permissions (e.g., 600); add operational guidance.

#### AP-P3-02 Test coverage is limited relative to core architecture paths
- Evidence:
  - Currently 4 tests: `tests/test_router_requires_instance_id.py`, `tests/test_install_factory_droid.py`, `tests/test_install_windows_settings_fallback.py`, `tests/test_list_instances_schema.py`
- Problem:
  - Registry recovery / rediscovery / decompile_to_file / plugin lifecycle paths are unverified.
- Impact:
  - Persistent regression risk.
- Spec (fix required):
  - Add a prioritized test set covering high-risk paths.

## Priority Execution Plan
1. Immediate P0 fixes: `AP-P0-01`, `AP-P0-02`
2. P1 stabilization: `AP-P1-01`~`AP-P1-06`
3. P2 contract-consistency improvements: `AP-P2-*`
4. P3 operational/quality hardening

## Task-force Conclusion
- The current architecture achieves its core goal of "multi-instance MCP routing", but:
  - Immediate improvements are needed in expiry-reason handling, registry-path unification, and recovery durability,
  - Without large-job execution control and a strengthened test regime, operational scale-up carries a high probability of incidents.
