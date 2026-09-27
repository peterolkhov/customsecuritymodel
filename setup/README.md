# setup/ — sponsor integration seams

## QM memory provider (`qm.memory-provider.json`)

Routes QM's `org` scope to the company's findings brain (GBrain via MCP) so
agents inside QM recall scan findings like any other org knowledge.

Wire it (see qm/docs/memory-providers.md):

```bash
export MEMORY_PROVIDER_CONFIG="$(cat setup/qm.memory-provider.json)"
```

The read/write tools and client-id env names are placeholders for the gbrain
MCP surface; set `GBRAIN_RO_*` / `GBRAIN_RW_*` when exposing
`gbrain mcp expose` (Tailscale tailnet) for remote/team brains.
