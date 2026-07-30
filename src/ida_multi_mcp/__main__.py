"""CLI entry point for ida-multi-mcp.

Provides flags for running the server, listing instances, and managing installation.
"""

import os
import re
import sys
import argparse
import hashlib
import json
import tempfile
import time
from pathlib import Path
import shutil

from .server import serve
from .registry import InstanceRegistry

SERVER_NAME = "ida-multi-mcp"

# ---------------------------------------------------------------------------
# IDA installation auto-detection (used by --install)
# ---------------------------------------------------------------------------

_IDA_VERSION_RE = re.compile(r"(\d+\.\d+)")
_TOML_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _detect_ida_dir() -> str | None:
    """Auto-detect the IDA Pro installation directory.

    Resolution order:
    1. ``IDADIR`` environment variable (if set and valid).
    2. ``ida-config.json`` ``ida-install-dir`` field (if non-empty).
    3. Filesystem scan of well-known locations (newest version wins).
    """
    # 1. Env var
    env_dir = os.environ.get("IDADIR", "").strip()
    if env_dir and os.path.isdir(env_dir):
        return env_dir

    # 2. ida-config.json (written by idapro package)
    if sys.platform == "win32":
        config_path = Path(os.environ.get("APPDATA", "")) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    else:
        config_path = Path.home() / ".idapro" / "ida-config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        cfg_dir = cfg.get("Paths", {}).get("ida-install-dir", "").strip()
        if cfg_dir and os.path.isdir(cfg_dir):
            return cfg_dir
    except Exception:
        pass

    # 3. Filesystem scan
    candidates: list[tuple[tuple[int, ...], str]] = []

    scan_roots: list[Path] = []
    if sys.platform == "win32":
        for drive in ("C:\\", "D:\\"):
            if os.path.isdir(drive):
                scan_roots.append(Path(drive))
        pf = os.environ.get("ProgramFiles", "C:\\Program Files")
        if os.path.isdir(pf):
            scan_roots.append(Path(pf))
        pf86 = os.environ.get("ProgramFiles(x86)", "")
        if pf86 and os.path.isdir(pf86):
            scan_roots.append(Path(pf86))
    elif sys.platform == "darwin":
        scan_roots.extend([Path("/Applications"), Path.home() / "Applications"])
    else:
        scan_roots.extend([Path("/opt"), Path.home()])

    seen: set[str] = set()
    for root in scan_roots:
        try:
            entries = list(root.iterdir())
        except OSError:
            # Unreadable root (permissions, missing, etc.) — skip it.
            continue
        for entry in entries:
            try:
                if not entry.is_dir():
                    continue
                if "ida" not in entry.name.lower():
                    continue
                resolved = str(entry.resolve())
                if resolved in seen:
                    continue
                seen.add(resolved)
                has_marker = any(
                    (entry / n).exists()
                    for n in (
                        "ida64.exe", "ida.exe",
                        "ida64", "ida",
                        "idalib.dll", "ida.dll",
                        "libidalib.dylib", "libida.dylib",
                        "libidalib.so", "libida.so",
                    )
                )
                if not has_marker:
                    continue
                m = _IDA_VERSION_RE.search(entry.name)
                ver = tuple(int(x) for x in m.group(1).split(".")) if m else (0, 0)
                candidates.append((ver, resolved))
            except OSError:
                # A single problematic entry (junction loop, device, ACL)
                # must not abort the scan of the remaining entries.
                continue

    if not candidates:
        return None

    candidates.sort(key=lambda t: t[0], reverse=True)
    return candidates[0][1]


def _replace_or_overwrite_file(src: str, dst: str, *, attempts: int = 6) -> bool:
    """Best-effort atomic replace with Windows-friendly fallback.

    On Windows, os.replace() can fail with WinError 5 if the destination is open
    without FILE_SHARE_DELETE (common for editor-held settings files). In that case,
    we retry briefly, then fall back to overwriting the destination in-place.
    """

    # Try atomic replace first (with retries for transient Windows locks)
    for i in range(max(1, attempts)):
        try:
            os.replace(src, dst)
            return True
        except PermissionError:
            if sys.platform != "win32":
                raise
            if i < attempts - 1:
                time.sleep(0.05 * (i + 1))
                continue
            break

    # Fallback: overwrite in-place (non-atomic) for Windows "access denied" renames
    try:
        if os.path.exists(dst):
            # Security: check for symlinks before writing (prevent symlink attacks)
            if os.path.islink(dst):
                print(f"  Warning: skipping symlink target: {dst}", file=sys.stderr)
                os.unlink(src)
                return False
            try:
                os.chmod(dst, 0o644)  # Security: use restrictive permissions (not 0o666)
            except Exception:
                pass
        shutil.copyfile(src, dst)
        os.unlink(src)
        return True
    except Exception:
        try:
            os.unlink(src)
        except Exception:
            pass
        return False


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


def generate_mcp_config(*, include_type: bool = False):
    """Generate MCP server configuration for ida-multi-mcp."""
    mcp_config = {
        "command": get_python_executable(),
        "args": ["-m", "ida_multi_mcp"],
    }

    # Factory Droid's ~/.factory/mcp.json schema requires an explicit transport type.
    if include_type:
        mcp_config["type"] = "stdio"

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
    # top_key None means the servers map lives at the top level under nested_key.
    special_json_structures = {
        "VS Code": ("mcp", "servers"),
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
            "Factory Droid": (
                os.path.join(os.path.expanduser("~"), ".factory"),
                "mcp.json",
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
            "Factory Droid": (
                os.path.join(os.path.expanduser("~"), ".factory"),
                "mcp.json",
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
            "Factory Droid": (
                os.path.join(os.path.expanduser("~"), ".factory"),
                "mcp.json",
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

        if name == "Factory Droid" and not uninstall:
            try:
                os.makedirs(config_dir, exist_ok=True)
            except OSError as exc:
                if not quiet:
                    print(
                        f"Skipping {name}\n  Config: {config_path} (cannot create dir: {exc.__class__.__name__})"
                    )
                continue

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
            # The path may be unreadable (permissions), a directory, or held
            # open by another process — skip this client rather than aborting
            # the whole install.
            try:
                with open(
                    config_path,
                    "rb" if is_toml else "r",
                    encoding=None if is_toml else "utf-8",
                ) as f:
                    raw = f.read()
            except OSError as exc:
                if not quiet:
                    print(
                        f"Skipping {name}\n  Config: {config_path} (cannot read: {exc.__class__.__name__})"
                    )
                continue

            if is_toml:
                if len(raw) == 0:
                    config = {}
                else:
                    try:
                        config = tomllib.loads(raw.decode("utf-8"))
                    except Exception:
                        if not quiet:
                            print(
                                f"Skipping {name}\n  Config: {config_path} (invalid TOML)"
                            )
                        continue
            else:
                data = raw.strip()
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

        # A config that parses to a non-dict (e.g. a top-level JSON array)
        # cannot hold a server map — skip rather than crashing on indexing.
        if not isinstance(config, dict):
            if not quiet:
                print(
                    f"Skipping {name}\n  Config: {config_path} (unexpected structure: root is {type(config).__name__})"
                )
            continue

        # Handle TOML vs JSON structure. setdefault creates the map when
        # missing; the isinstance check below catches a key that exists but
        # holds an unexpected (non-dict) value, so we never index into it.
        if is_toml:
            mcp_servers = config.setdefault("mcp_servers", {})
        else:
            # Check if this client uses a special JSON structure
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    # servers map at the top level under nested_key
                    mcp_servers = config.setdefault(nested_key, {})
                else:
                    # nested structure (e.g., VS Code uses mcp.servers)
                    parent = config.setdefault(top_key, {})
                    if not isinstance(parent, dict):
                        if not quiet:
                            print(
                                f"Skipping {name}\n  Config: {config_path} "
                                f"(unexpected structure: '{top_key}' is {type(parent).__name__})"
                            )
                        continue
                    mcp_servers = parent.setdefault(nested_key, {})
            else:
                # Default: mcpServers at top level
                mcp_servers = config.setdefault("mcpServers", {})

        # The server map must be a dict to hold our entry.
        if not isinstance(mcp_servers, dict):
            if not quiet:
                print(
                    f"Skipping {name}\n  Config: {config_path} "
                    f"(unexpected structure: server map is {type(mcp_servers).__name__})"
                )
            continue

        # Migrate old "ida-pro-mcp" entry to "ida-multi-mcp"
        migrated = False
        old_name = "ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[SERVER_NAME] = mcp_servers[old_name]
            del mcp_servers[old_name]
            migrated = True

        # Also migrate the fully-qualified old name
        old_name_full = "github.com/mrexodia/ida-pro-mcp"
        if old_name_full in mcp_servers:
            mcp_servers[SERVER_NAME] = mcp_servers[old_name_full]
            del mcp_servers[old_name_full]
            migrated = True

        if uninstall:
            if SERVER_NAME not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[SERVER_NAME]
        else:
            new_entry = generate_mcp_config(include_type=(name == "Factory Droid"))
            existing = mcp_servers.get(SERVER_NAME)
            # Skip an untouched, already-correct entry to avoid rewriting the
            # user's config file. A migration above always forces a write.
            if not migrated and existing == new_entry:
                if not quiet:
                    print(f"Skipping {name}\n  Config: {config_path} (already up to date)")
                continue
            # Don't silently clobber a customized entry — say what is happening.
            if existing is not None and existing != new_entry and not quiet:
                print(f"Replacing existing '{SERVER_NAME}' entry in {name}\n  Config: {config_path}")
            mcp_servers[SERVER_NAME] = new_entry

        # Atomic write: temp file + replace (with Windows-friendly fallback)
        suffix = ".toml" if is_toml else ".json"
        try:
            fd, temp_path = tempfile.mkstemp(
                dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
            )
        except OSError as exc:
            if not quiet:
                print(
                    f"Skipping {name}\n  Config: {config_path} (cannot create temp file: {exc.__class__.__name__})"
                )
            continue

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

            if not _replace_or_overwrite_file(temp_path, config_path):
                try:
                    os.unlink(temp_path)  # don't leave a .tmp_ orphan behind
                except OSError:
                    pass
                if not quiet:
                    action = "uninstall" if uninstall else "installation"
                    print(
                        f"Skipping {name} {action}\n"
                        f"  Config: {config_path} (permission denied; close the app using it and retry)"
                    )
                continue
        except Exception as exc:
            # Don't let one client's write failure abort the rest of the run.
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            if not quiet:
                print(
                    f"Skipping {name}\n  Config: {config_path} (write failed: {exc.__class__.__name__})"
                )
            continue

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


def _toml_quote_key(key: str) -> str:
    """Quote TOML keys when they are not valid bare keys."""
    if _TOML_BARE_KEY_RE.fullmatch(key):
        return key
    return json.dumps(key, ensure_ascii=False)


def _toml_format_value(value):
    """Serialize a Python value as TOML."""
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(_toml_format_value(item) for item in value) + "]"
    if isinstance(value, (int, float)):
        return str(value)
    raise TypeError(f"Unsupported TOML value type: {type(value).__name__}")


def _write_toml_fallback(f, config, prefix=()):
    """Minimal TOML writer fallback when tomli_w is not available."""
    scalar_items = []
    table_items = []
    for key, value in config.items():
        if isinstance(value, dict):
            table_items.append((key, value))
        else:
            scalar_items.append((key, value))

    if prefix:
        table_name = ".".join(_toml_quote_key(part) for part in prefix)
        f.write(f"[{table_name}]\n")

    for key, value in scalar_items:
        f.write(f"{_toml_quote_key(key)} = {_toml_format_value(value)}\n")

    if prefix and scalar_items and table_items:
        f.write("\n")

    for index, (key, value) in enumerate(table_items):
        if prefix or index > 0 or scalar_items:
            f.write("\n")
        _write_toml_fallback(f, value, (*prefix, key))


def cmd_list(args):
    """List all registered IDA instances."""
    registry = InstanceRegistry(args.registry)
    instances = registry.list_instances()

    if not instances:
        print("No IDA instances registered.")
        print("Open IDA Pro with the ida-multi-mcp plugin to register an instance.")
        return

    print(f"Registered IDA instances ({len(instances)}):\n")
    for instance_id, info in instances.items():
        print(f"  {instance_id}")
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


def _configure_idalib_path():
    """Auto-detect IDA installation and write to ida-config.json.

    The ``idapro`` package reads ``ida-config.json`` at import time to
    locate IDA libraries. If the ``ida-install-dir`` field is already
    populated or ``IDADIR`` is set, this is a no-op. Otherwise we scan
    well-known paths, pick the newest version, and write it.
    """
    # Check if already configured
    env_dir = os.environ.get("IDADIR", "").strip()
    if env_dir and os.path.isdir(env_dir):
        print(f"\n  [ok] IDADIR already set: {env_dir}")
        return

    # Check ida-config.json
    if sys.platform == "win32":
        config_path = Path(os.environ.get("APPDATA", "")) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    else:
        config_path = Path.home() / ".idapro" / "ida-config.json"

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        existing = cfg.get("Paths", {}).get("ida-install-dir", "").strip()
        if existing and os.path.isdir(existing):
            print(f"\n  [ok] ida-config.json already has ida-install-dir: {existing}")
            return
    except Exception:
        cfg = {}

    # Auto-detect
    detected = _detect_ida_dir()
    if not detected:
        print("\n  [--] Could not auto-detect IDA installation directory.")
        print("       Set IDADIR environment variable manually for headless (idalib) support.")
        return

    # Write to ida-config.json
    cfg.setdefault("Paths", {})
    cfg["Paths"]["ida-install-dir"] = detected

    config_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4)
        print(f"\n  [ok] Auto-detected IDA at: {detected}")
        print(f"       Written to: {config_path}")
    except Exception as e:
        print(f"\n  [!!] Failed to write ida-config.json: {e}")
        print(f"       Set IDADIR={detected} manually.")


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
        return 1

    # 2. Install IDA plugin loader
    ida_plugins_dir = _get_ida_plugins_dir(args.ida_dir)

    if not ida_plugins_dir.exists():
        print(f"\n  Creating IDA plugins directory: {ida_plugins_dir}")
        ida_plugins_dir.mkdir(parents=True, exist_ok=True)

    # Copy the loader file as ida_multi_mcp.py into IDA's plugins directory
    loader_source = Path(__file__).parent / "plugin" / "ida_multi_mcp_loader.py"
    loader_dest = ida_plugins_dir / "ida_multi_mcp.py"

    # Try symlink first (development-friendly), fall back to copy
    # Use a temporary name + rename to avoid TOCTOU race between unlink/symlink
    import tempfile
    loader_tmp = None
    try:
        # Create symlink/copy at a temp path in the same directory, then atomically rename
        tmp_fd, loader_tmp = tempfile.mkstemp(
            prefix=".ida_multi_mcp_", suffix=".tmp",
            dir=str(ida_plugins_dir),
        )
        os.close(tmp_fd)
        os.unlink(loader_tmp)  # Remove the temp file so we can create symlink at this path

        try:
            Path(loader_tmp).symlink_to(loader_source)
            os.replace(loader_tmp, str(loader_dest))
            loader_tmp = None  # Successfully replaced, no cleanup needed
            print(f"\n  Symlinked plugin: {loader_dest} -> {loader_source}")
        except (OSError, NotImplementedError):
            # Symlink failed, fall back to copy + rename
            shutil.copy2(loader_source, loader_tmp)
            os.replace(loader_tmp, str(loader_dest))
            loader_tmp = None
            print(f"\n  Copied plugin to: {loader_dest}")
    finally:
        if loader_tmp is not None:
            try:
                os.unlink(loader_tmp)
            except OSError:
                pass

    print("\n  [ok] IDA plugin installed!")

    # 3. Auto-detect IDA installation and write to ida-config.json for idalib
    _configure_idalib_path()

    # 4. Auto-configure MCP clients
    print()
    install_mcp_servers()

    print("\n" + "=" * 60)
    print("Next steps:")
    print("  1. Restart your MCP client(s) for the config to take effect")
    print("  2. Open IDA Pro - the plugin auto-loads (PLUGIN_FIX)")
    print("  3. Run 'ida-multi-mcp --list' to verify instances")
    print("=" * 60)
    return 0


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
        # Security: don't follow symlinks during uninstall (prevent arbitrary deletion)
        if registry_dir.is_symlink():
            registry_dir.unlink()
            print(f"  Removed registry symlink: {registry_dir}")
        else:
            # Only remove known files, not arbitrary directory trees
            for known_file in ["instances.json", "instances.json.lock"]:
                fpath = registry_dir / known_file
                if fpath.exists() and not fpath.is_symlink():
                    fpath.unlink()
            # Remove directory only if empty (safe)
            try:
                registry_dir.rmdir()
            except OSError:
                # Directory not empty (has unexpected files), leave it
                pass
            print(f"  Removed registry: {registry_dir}")

    # 3. Remove MCP client configuration
    print()
    install_mcp_servers(uninstall=True)

    print("\n  [ok] ida-multi-mcp uninstalled!")
    return 0


def cmd_config(args):
    """Print MCP client configuration JSON."""
    print_mcp_config()
    return 0


def _sha256_file(path: Path) -> str | None:
    """Content hash, reading through a symlink. None when unreadable."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _loader_install_state(custom_dir=None) -> dict:
    """Describe the installed loader: where, how, and whether it matches ours.

    File size is not a usable check here: Windows reports a symlink's own length
    as 0 bytes, so a correctly symlinked loader looks empty to `Get-Item` and to
    anything else reading the link rather than its target. Compare content hashes
    through the link instead, which is mode-agnostic.
    """
    packaged = Path(__file__).parent / "plugin" / "ida_multi_mcp_loader.py"
    installed = _get_ida_plugins_dir(custom_dir) / "ida_multi_mcp.py"

    is_symlink = installed.is_symlink()
    exists = installed.exists()  # follows the link, so a dangling one is False

    if is_symlink:
        mode = "symlink"
    elif exists:
        mode = "copy"
    else:
        mode = "missing"

    link_target = None
    if is_symlink:
        try:
            link_target = str(installed.resolve())
        except OSError:
            pass

    packaged_sha = _sha256_file(packaged)
    installed_sha = _sha256_file(installed) if exists else None

    return {
        "packaged_loader": str(packaged),
        "installed_loader": str(installed),
        "mode": mode,
        "exists": exists,
        "link_target": link_target,
        "packaged_sha256": packaged_sha,
        "installed_sha256": installed_sha,
        "match": bool(installed_sha and installed_sha == packaged_sha),
    }


def cmd_verify(args):
    """Report installed-loader state as JSON. Exit 0 only when it matches."""
    state = _loader_install_state(args.ida_dir)
    print(json.dumps(state, indent=2))

    if state["match"]:
        return 0
    if state["mode"] == "missing":
        print("\n  Loader is not installed. Run: ida-multi-mcp --install",
              file=sys.stderr)
    elif state["installed_sha256"] is None:
        print("\n  Loader path exists but could not be read (dangling symlink?). "
              "Run: ida-multi-mcp --install", file=sys.stderr)
    else:
        print("\n  Installed loader differs from the packaged one, so it is stale. "
              "Run: ida-multi-mcp --install", file=sys.stderr)
    return 1


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
        "--verify", action="store_true",
        help="Verify the installed IDA plugin loader (JSON; exit 1 if stale or missing)"
    )
    parser.add_argument(
        "--ida-dir", type=str, default=None,
        help="Custom IDA Pro directory (for --install/--uninstall/--verify)"
    )
    parser.add_argument(
        "--registry", type=str, default=None,
        help="Path to registry JSON file (default: ~/.ida-mcp/instances.json)"
    )
    parser.add_argument(
        "--idalib-python", type=str, default=None,
        help="Python executable with idapro installed (for headless idalib sessions). "
             "Defaults to the same Python running this server."
    )

    args = parser.parse_args()

    if args.install:
        sys.exit(cmd_install(args))
    elif args.uninstall:
        sys.exit(cmd_uninstall(args))
    elif args.verify:
        sys.exit(cmd_verify(args))
    elif args.list:
        cmd_list(args)
        return
    elif args.config:
        sys.exit(cmd_config(args))
    else:
        # Default: start MCP server
        serve(registry_path=args.registry, idalib_python=args.idalib_python)


if __name__ == "__main__":
    main()
