"""CLI entry point for ida-multi-mcp.

Provides flags for running the server, listing instances, and managing installation.
"""

import os
import sys
import argparse
import json
from pathlib import Path
import shutil

from .server import serve
from .registry import InstanceRegistry


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


def _get_ida_plugins_dir(custom_dir: str | None = None) -> Path:
    """Detect the IDA Pro plugins directory.

    Args:
        custom_dir: Custom IDA directory override

    Returns:
        Path to IDA plugins directory
    """
    if custom_dir:
        return Path(custom_dir) / "plugins"

    # Platform-specific defaults
    if sys.platform == "win32":
        # Windows: %APPDATA%/Hex-Rays/IDA Pro/plugins/
        appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return appdata / "Hex-Rays" / "IDA Pro" / "plugins"
    elif sys.platform == "darwin":
        # macOS: ~/.idapro/plugins/
        return Path.home() / ".idapro" / "plugins"
    else:
        # Linux: ~/.idapro/plugins/
        return Path.home() / ".idapro" / "plugins"


def cmd_install(args):
    """Install the IDA plugin and configure MCP clients."""
    print("Installing ida-multi-mcp...\n")

    # 1. Check prerequisites
    try:
        import ida_multi_mcp
        print(f"  [ok] ida-multi-mcp package found (v{ida_multi_mcp.__version__})")
    except ImportError:
        print("  [!!] ida-multi-mcp package not found in Python path")
        print("       Install with: pip install ida-multi-mcp")

    # 2. Install IDA plugin loader
    ida_plugins_dir = _get_ida_plugins_dir(args.ida_dir)

    if not ida_plugins_dir.exists():
        print(f"\n  Creating IDA plugins directory: {ida_plugins_dir}")
        ida_plugins_dir.mkdir(parents=True, exist_ok=True)

    # Copy the loader file as ida_multi_mcp.py into IDA's plugins directory
    loader_source = Path(__file__).parent / "plugin" / "ida_multi_mcp_loader.py"
    loader_dest = ida_plugins_dir / "ida_multi_mcp.py"

    # Try symlink first (development-friendly), fall back to copy
    if loader_dest.exists() or loader_dest.is_symlink():
        loader_dest.unlink()

    try:
        loader_dest.symlink_to(loader_source)
        print(f"\n  Symlinked plugin: {loader_dest} -> {loader_source}")
    except (OSError, NotImplementedError):
        shutil.copy2(loader_source, loader_dest)
        print(f"\n  Copied plugin to: {loader_dest}")

    print("\n  [ok] IDA plugin installed!")

    # 3. Show MCP client configuration
    mcp_config = {
        "mcpServers": {
            "ida-multi-mcp": {
                "command": "ida-multi-mcp"
            }
        }
    }

    print("\n" + "=" * 60)
    print("MCP Client Configuration")
    print("=" * 60)
    print("\nAdd this to your MCP client config file:\n")
    print(json.dumps(mcp_config, indent=2))

    print("\nConfig file locations:")
    print("  Claude Desktop: claude_desktop_config.json")
    print("  Claude Code:    claude mcp add ida-multi-mcp -s user -- ida-multi-mcp")
    print("  Cursor:         .cursor/mcp.json")
    print("  Windsurf:       .codeium/windsurf/mcp_config.json")

    print("\n" + "=" * 60)
    print("\nNext steps:")
    print("  1. Add the MCP config above to your client")
    print("  2. Open IDA Pro - the plugin auto-loads (PLUGIN_FIX)")
    print("  3. Run 'ida-multi-mcp --list' to verify instances")
    print("=" * 60)


def cmd_uninstall(args):
    """Uninstall the IDA plugin."""
    print("Uninstalling ida-multi-mcp...")

    ida_plugins_dir = _get_ida_plugins_dir(args.ida_dir)
    loader_dest = ida_plugins_dir / "ida_multi_mcp.py"

    if loader_dest.exists() or loader_dest.is_symlink():
        loader_dest.unlink()
        print(f"  Removed plugin: {loader_dest}")
    else:
        print(f"  Plugin not found at {loader_dest}")

    # Clean up registry
    registry_dir = Path.home() / ".ida-mcp"
    if registry_dir.exists():
        shutil.rmtree(registry_dir)
        print(f"  Removed registry: {registry_dir}")

    print("\n  [ok] ida-multi-mcp uninstalled!")
    print("\n  Remember to remove ida-multi-mcp from your MCP client config.")


def cmd_config(args):
    """Print MCP client configuration JSON."""
    config = {
        "mcpServers": {
            "ida-multi-mcp": {
                "command": "ida-multi-mcp"
            }
        }
    }

    print("MCP Client Configuration")
    print("=" * 60)
    print("\nAdd this to your MCP client configuration file:")
    print("\nClaude Desktop (claude_desktop_config.json):")
    print(json.dumps(config, indent=2))
    print("\nClaude Code:")
    print("  claude mcp add ida-multi-mcp -s user -- ida-multi-mcp")
    print("\nCursor (.cursor/mcp.json):")
    print(json.dumps(config, indent=2))
    print("\nWindsurf (.codeium/windsurf/mcp_config.json):")
    print(json.dumps(config, indent=2))


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ida-multi-mcp: Multi-instance MCP server for IDA Pro"
    )
    parser.add_argument(
        "--install", action="store_true",
        help="Install the IDA plugin and show MCP client configuration"
    )
    parser.add_argument(
        "--uninstall", action="store_true",
        help="Uninstall the IDA plugin and clean up registry"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all registered IDA instances"
    )
    parser.add_argument(
        "--config", action="store_true",
        help="Print MCP client configuration JSON"
    )
    parser.add_argument(
        "--ida-dir", type=str, default=None,
        help="Custom IDA Pro directory (for --install/--uninstall)"
    )
    parser.add_argument(
        "--registry", type=str, default=None,
        help="Path to registry JSON file (default: ~/.ida-mcp/instances.json)"
    )

    args = parser.parse_args()

    if args.install:
        cmd_install(args)
    elif args.uninstall:
        cmd_uninstall(args)
    elif args.list:
        cmd_list(args)
    elif args.config:
        cmd_config(args)
    else:
        # Default: start MCP server
        serve(registry_path=args.registry)


if __name__ == "__main__":
    main()
