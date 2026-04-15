# ida-multi-mcp Architecture SSOT Index

Last updated: 2026-02-17
Status: Active
Change class: B (scope/architecture)

## Governance Alignment
- Authority order:
1. `docs/.ssot/contracts/*`
2. `docs/.ssot/PRD.md`
3. `docs/.ssot/decisions/*`
4. `docs/.ssot/architectures/*`
5. `docs/plans/_completed/*`
6. `docs/ops/*`
- This directory contains architecture description documents and does not redefine Contracts semantics.

## Required Cross-links
- Governance: `docs/README.md`
- PRD: `docs/.ssot/PRD.md`
- Contracts: `docs/.ssot/contracts/INDEX.md`
- Decisions: `docs/.ssot/decisions/INDEX.md`
- SSOT TODO: `docs/.ssot/TODO.md`
- SSOT History: `docs/.ssot/HISTORY.md`
- Roadmap: `docs/ops/ROADMAP.md`

## Architecture Set
1. `01_system_context.md` - System context
2. `02_component_decomposition.md` - Component decomposition
3. `03_runtime_sequences.md` - Runtime sequences
4. `04_instance_lifecycle.md` - Instance lifecycle
5. `05_data_model_persistence.md` - Data model/persistence
6. `06_tool_discovery_schema_federation.md` - Tool discovery/schema federation
7. `07_transport_protocol.md` - Transport/protocol
8. `08_concurrency_sync.md` - Concurrency/synchronization
9. `09_security_architecture.md` - Security
10. `10_reliability_failure.md` - Reliability/failure handling
11. `11_performance_scalability.md` - Performance/scalability
12. `12_cli_installation_architecture.md` - CLI/installation architecture
13. `13_plugin_bootstrap.md` - Plugin bootstrap
14. `14_observability_diagnostics.md` - Observability/diagnostics
15. `15_testing_architecture.md` - Testing architecture
16. `16_compatibility_matrix.md` - Compatibility matrix
17. `17_extensibility_evolution.md` - Extensibility/evolution
18. `18_module_ownership.md` - Module ownership separation
19. `19_operational_runbook.md` - Operational runbook (includes current N/A context documents)
20. `20_adr_summary.md` - ADR summary
21. `21_architecture_problems_spec.md` - Architecture problems research/spec
