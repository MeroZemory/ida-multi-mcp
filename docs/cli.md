# CLI Reference

[← back to README](../README.md)

## CLI Commands

### `ida-multi-mcp`
Start the MCP server (stdio). Used by MCP clients. This is the default command.

```bash
ida-multi-mcp
ida-multi-mcp --idalib-python /path/to/python3  # custom Python for headless sessions
```

### `ida-multi-mcp --list`
List all registered IDA instances.

```bash
ida-multi-mcp --list
```

### `ida-multi-mcp --install [--ida-dir DIR]`
Install the IDA plugin and auto-configure all detected MCP clients (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Zed, and 20+ more).

```bash
ida-multi-mcp --install
ida-multi-mcp --install --ida-dir "C:\Program Files\IDA Pro 9.0"  # Windows custom path
```

### `ida-multi-mcp --uninstall [--ida-dir DIR]`
Remove the IDA plugin, clean up registry, and remove MCP client configurations.

```bash
ida-multi-mcp --uninstall
```

### `ida-multi-mcp --config`
Print the MCP client configuration JSON for easy reference.

```bash
ida-multi-mcp --config
```
