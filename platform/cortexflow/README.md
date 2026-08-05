# CortexFlow

CortexFlow is the enterprise agent runtime for NexusOps AI.

It owns reasoning, planning, memory coordination, tool routing and agent lifecycle.

Current implementation is mapped to existing backend modules:

- `app.redqueen`
- `app.ares`
- `app.intelligence`

Runtime migration must stay incremental until imports, tests and deployment entrypoints are moved safely.

