"""CLI entry point for ida-multi-mcp.

Provides flags for running the server, listing instances, and managing installation.
"""

import os
import sys
import argparse
import json
import tempfile
from pathlib import Path
import shutil

from .server import serve
from .registry import InstanceRegistry

SERVER_NAME = "ida-multi-mcp"


def get_python_executable():
    """Get the path to the Python executable (venv-aware)."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env):
    """Copy Python environment variables needed by MCP clients.

    MCP servers are run without inheriting the environment, so we need to forward
    the environment variables that affect Python's dependency resolution by hand.
    Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    """
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config():
    """Generate MCP server configuration for ida-multi-mcp."""
    mcp_config = {
        "command": get_python_executable(),
        "args": ["-m", "ida_multi_mcp"],
    }
    env = {}
    if copy_python_env(env):
        mcp_config["env"] = env
    return mcp_config


def print_mcp_config():
    """Print MCP client configuration JSON."""
    print(
        json.dumps(
            {"mcpServers": {SERVER_NAME: generate_mcp_config()}}, indent=2
        )
    )


def install_mcp_servers(uninstall=False, quiet=False):
    """Auto-configure all known MCP clients for ida-multi-mcp."""
    # Map client names to their JSON key paths for clients that don't use "mcpServers"
    # Format: client_name -> (top_level_key, nested_key)
    # None means use default "mcpServers" at top level
    special_json_structures = {
        "VS Code": ("mcp", "servers"),
        "Visual Studio 2022": (None, "servers"),  # servers at top level
    }

    if sys.platform == "win32":
        configs = {
            "Cline": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (
                os.path.join(os.getenv("APPDATA", ""), "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Claude"
                ),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Zed"
                ),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "BoltAI": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "BoltAI",
                ),
                "config.json",
            ),
            "Perplexity": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Perplexity",
                ),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(os.path.expanduser("~"), ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    # Optional TOML support (Python 3.11+ has tomllib built-in)
    try:
        import tomllib
    except ImportError:
        tomllib = None

    try:
        import tomli_w
    except ImportError:
        tomli_w = None

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        if is_toml and tomllib is None:
            if not quiet:
                print(
                    f"Skipping {name} (TOML support not available, need Python 3.11+)"
                )
            continue

        # Read existing config
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(
                config_path,
                "rb" if is_toml else "r",
                encoding=None if is_toml else "utf-8",
            ) as f:
                if is_toml:
                    data = f.read()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except Exception:
                            if not quiet:
                                print(
                                    f"Skipping {name}\n  Config: {config_path} (invalid TOML)"
                                )
                            continue
                else:
                    data = f.read().strip()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = json.loads(data)
                        except json.decoder.JSONDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name}\n  Config: {config_path} (invalid JSON)"
                                )
                            continue

        # Handle TOML vs JSON structure
        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            # Check if this client uses a special JSON structure
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    # servers at top level (e.g., Visual Studio 2022)
                    if nested_key not in config:
                        config[nested_key] = {}
                    mcp_servers = config[nested_key]
                else:
                    # nested structure (e.g., VS Code uses mcp.servers)
                    if top_key not in config:
                        config[top_key] = {}
                    if nested_key not in config[top_key]:
                        config[top_key][nested_key] = {}
                    mcp_servers = config[top_key][nested_key]
            else:
                # Default: mcpServers at top level
                if "mcpServers" not in config:
                    config["mcpServers"] = {}
                mcp_servers = config["mcpServers"]

        # Migrate old "ida-pro-mcp" entry to "ida-multi-mcp"
        old_name = "ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[SERVER_NAME] = mcp_servers[old_name]
            del mcp_servers[old_name]

        # Also migrate the fully-qualified old name
        old_name_full = "github.com/mrexodia/ida-pro-mcp"
        if old_name_full in mcp_servers:
            mcp_servers[SERVER_NAME] = mcp_servers[old_name_full]
            del mcp_servers[old_name_full]

        if uninstall:
            if SERVER_NAME not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[SERVER_NAME]
        else:
            mcp_servers[SERVER_NAME] = generate_mcp_config()

        # Atomic write: temp file + rename
        suffix = ".toml" if is_toml else ".json"
        fd, temp_path = tempfile.mkstemp(
            dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
        )
        try:
            with os.fdopen(
                fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8"
            ) as f:
                if is_toml:
                    if tomli_w is not None:
                        f.write(tomli_w.dumps(config).encode("utf-8"))
                    else:
                        # Fallback: write minimal TOML manually
                        import io

                        buf = io.StringIO()
                        _write_toml_fallback(buf, config)
                        f.write(buf.getvalue().encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1

    if not uninstall and installed == 0:
        print(
            "No MCP clients found. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def _write_toml_fallback(f, config, prefix=""):
    """Minimal TOML writer fallback when tomli_w is not available."""
    for key, value in config.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            f.write(f"[{full_key}]\n")
            for k, v in value.items():
                if isinstance(v, dict):
                    _write_toml_fallback(f, {k: v}, full_key)
                elif isinstance(v, str):
                    f.write(f'{k} = "{v}"\n')
                elif isinstance(v, list):
                    items = ", ".join(f'"{i}"' if isinstance(i, str) else str(i) for i in v)
                    f.write(f"{k} = [{items}]\n")
                elif isinstance(v, bool):
                    f.write(f"{k} = {'true' if v else 'false'}\n")
                else:
                    f.write(f"{k} = {v}\n")
        elif isinstance(value, str):
            f.write(f'{key} = "{value}"\n')
        elif isinstance(value, bool):
            f.write(f"{key} = {'true' if value else 'false'}\n")
        else:
            f.write(f"{key} = {value}\n")


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


def _get_ida_plugins_dir(custom_dir=None):
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

    # 3. Auto-configure MCP clients
    print()
    install_mcp_servers()

    print("\n" + "=" * 60)
    print("Next steps:")
    print("  1. Restart your MCP client(s) for the config to take effect")
    print("  2. Open IDA Pro - the plugin auto-loads (PLUGIN_FIX)")
    print("  3. Run 'ida-multi-mcp --list' to verify instances")
    print("=" * 60)


def cmd_uninstall(args):
    """Uninstall the IDA plugin and remove MCP client configuration."""
    print("Uninstalling ida-multi-mcp...\n")

    # 1. Remove IDA plugin
    ida_plugins_dir = _get_ida_plugins_dir(args.ida_dir)
    loader_dest = ida_plugins_dir / "ida_multi_mcp.py"

    if loader_dest.exists() or loader_dest.is_symlink():
        loader_dest.unlink()
        print(f"  Removed plugin: {loader_dest}")
    else:
        print(f"  Plugin not found at {loader_dest}")

    # 2. Clean up registry
    registry_dir = Path.home() / ".ida-mcp"
    if registry_dir.exists():
        shutil.rmtree(registry_dir)
        print(f"  Removed registry: {registry_dir}")

    # 3. Remove MCP client configuration
    print()
    install_mcp_servers(uninstall=True)

    print("\n  [ok] ida-multi-mcp uninstalled!")


def cmd_config(args):
    """Print MCP client configuration JSON."""
    print_mcp_config()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ida-multi-mcp: Multi-instance MCP server for IDA Pro"
    )
    parser.add_argument(
        "--install", action="store_true",
        help="Install the IDA plugin and configure MCP clients"
    )
    parser.add_argument(
        "--uninstall", action="store_true",
        help="Uninstall the IDA plugin, clean up registry, and remove MCP client config"
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
