# 15. Testing Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Current Test Coverage
- router: `instance_id` required validation (`tests/test_router_requires_instance_id.py`)
- install: Windows settings overwrite fallback (`tests/test_install_windows_settings_fallback.py`)
- install: Factory Droid config create/delete (`tests/test_install_factory_droid.py`)
- management schema: `list_instances` returns an object (`tests/test_list_instances_schema.py`)

## Strengths
- Guards regression-prone install-path concerns (permissions/file formats)
- Pins the core routing-safety contract (`instance_id`)

## Gaps
- Insufficient unit tests for registry expire/cleanup paths
- Limited mocked tests for rediscovery in realistic environments
- Limited tests for decompile_to_file large-scale paths and error handling
- Missing plugin hook lifecycle tests

## Recommended Additional Tests
- Registry file-lock contention scenarios
- Router expired-replacement guidance logic
- Cache TTL/eviction boundary conditions

