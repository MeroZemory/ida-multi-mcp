"""CLI entry point for ida-multi-mcp.

Provides commands for running the server, listing instances, and managing installation.
"""

import sys
import argparse
import json
from pathlib import Path
import shutil

from .server import serve
from .registry import InstanceRegistry


def cmd_serve(args):
    """Start the MCP server."""
    serve(registry_path=args.registry)


def cmd_list(args):
    """List all registered IDA instances."""
    registry = InstanceRegistry(args.registry)
    instances = registry.list_instances()
    active = registry.get_active()

    if not instances:
        print("No IDA instances registered.")
        print("Open IDA Pro with the ida-multi-mcp plugin to register an instance.")
        return

    print(f"Registered IDA instances ({len(instances)}):\n")
    for instance_id, info in instances.items():
        active_marker = " [ACTIVE]" if instance_id == active else ""
        print(f"  {instance_id}{active_marker}")
        print(f"    Binary: {info.get('binary_name', 'unknown')}")
        print(f"    Path: {info.get('binary_path', 'unknown')}")
        print(f"    Arch: {info.get('arch', 'unknown')}")
        print(f"    Port: {info.get('port', 0)}")
        print(f"    PID: {info.get('pid', 0)}")
        print()


def cmd_install(args):
    """Install the IDA plugin and configure MCP clients."""
    print("Installing ida-multi-mcp...")

    # 1. Install IDA plugin
    plugin_source = Path(__file__).parent / "plugin"
    ida_plugins_dir = Path.home() / "idapro" / "plugins"

    if args.ida_dir:
        ida_plugins_dir = Path(args.ida_dir) / "plugins"

    if not ida_plugins_dir.exists():
        print(f"Creating IDA plugins directory: {ida_plugins_dir}")
        ida_plugins_dir.mkdir(parents=True, exist_ok=True)

    # Copy plugin files
    plugin_dest = ida_plugins_dir / "ida_multi_mcp"
    if plugin_dest.exists():
        print(f"Removing existing plugin at {plugin_dest}")
        shutil.rmtree(plugin_dest)

    print(f"Copying plugin to {plugin_dest}")
    shutil.copytree(plugin_source, plugin_dest)

    print("\n✓ IDA plugin installed successfully!")

    # 2. Show MCP client configuration
    print("\n" + "="*60)
    print("MCP Client Configuration")
    print("="*60)
    print("\nAdd this to your MCP client configuration:")
    print("\nClaude Desktop (claude_desktop_config.json):")
    print(json.dumps({
        "mcpServers": {
            "ida-multi-mcp": {
                "command": "ida-multi-mcp",
                "args": ["serve"]
            }
        }
    }, indent=2))

    print("\nCursor (.cursor/config.json):")
    print(json.dumps({
        "mcp": {
            "servers": {
                "ida-multi-mcp": {
                    "command": "ida-multi-mcp",
                    "args": ["serve"]
                }
            }
        }
    }, indent=2))

    print("\n" + "="*60)
    print("\nNext steps:")
    print("1. Restart your MCP client (Claude Desktop / Cursor)")
    print("2. Open IDA Pro - the plugin will auto-register")
    print("3. Use 'ida-multi-mcp list' to verify instances")
    print("="*60)


def cmd_uninstall(args):
    """Uninstall the IDA plugin."""
    print("Uninstalling ida-multi-mcp...")

    ida_plugins_dir = Path.home() / "idapro" / "plugins"
    if args.ida_dir:
        ida_plugins_dir = Path(args.ida_dir) / "plugins"

    plugin_dest = ida_plugins_dir / "ida_multi_mcp"

    if not plugin_dest.exists():
        print(f"Plugin not found at {plugin_dest}")
        return

    print(f"Removing plugin from {plugin_dest}")
    shutil.rmtree(plugin_dest)

    print("\n✓ IDA plugin uninstalled successfully!")
    print("\nRemember to remove ida-multi-mcp from your MCP client configuration.")


def cmd_config(args):
    """Print MCP client configuration JSON."""
    config = {
        "mcpServers": {
            "ida-multi-mcp": {
                "command": "ida-multi-mcp",
                "args": ["serve"]
            }
        }
    }

    print("MCP Client Configuration")
    print("=" * 60)
    print("\nAdd this to your MCP client configuration file:")
    print("\nClaude Desktop (claude_desktop_config.json):")
    print(json.dumps(config, indent=2))
    print("\nCursor (.cursor/mcp.json):")
    print(json.dumps(config, indent=2))
    print("\nWindsurf (.codeium/windsurf/mcp_config.json):")
    print(json.dumps(config, indent=2))


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ida-multi-mcp: Multi-instance MCP server for IDA Pro"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Start the MCP server")
    serve_parser.add_argument(
        "--registry",
        help="Path to registry JSON file (default: ~/.ida-mcp/instances.json)"
    )
    serve_parser.set_defaults(func=cmd_serve)

    # list command
    list_parser = subparsers.add_parser("list", help="List registered IDA instances")
    list_parser.add_argument(
        "--registry",
        help="Path to registry JSON file (default: ~/.ida-mcp/instances.json)"
    )
    list_parser.set_defaults(func=cmd_list)

    # install command
    install_parser = subparsers.add_parser("install", help="Install IDA plugin and configure MCP clients")
    install_parser.add_argument(
        "--ida-dir",
        help="Custom IDA Pro installation directory"
    )
    install_parser.set_defaults(func=cmd_install)

    # uninstall command
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall IDA plugin")
    uninstall_parser.add_argument(
        "--ida-dir",
        help="Custom IDA Pro installation directory"
    )
    uninstall_parser.set_defaults(func=cmd_uninstall)

    # config command
    config_parser = subparsers.add_parser("config", help="Print MCP client configuration JSON")
    config_parser.set_defaults(func=cmd_config)

    # Parse and execute
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
