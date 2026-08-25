# Troubleshooting

[← back to README](../README.md)

## Troubleshooting

<details>
<summary>"No IDA instances registered"</summary>

Make sure:
1. IDA Pro is running with a binary loaded
2. Check IDA's plugin list (Edit → Plugins → Scan) to confirm `ida-multi-mcp` plugin loaded
3. Check IDA console for error messages
4. Run `ida-multi-mcp --list` again

</details>

<details>
<summary>"Instance 'k7m2' not found"</summary>

The instance has crashed or expired. Run:
```bash
ida-multi-mcp --list
```
to see available instances, then use a valid ID.

</details>

<details>
<summary>"Instance 'k7m2' expired. Replaced by 'px3a'"</summary>

You opened a different binary in that IDA instance. This is expected. Use the new instance ID (`px3a`).

</details>

<details>
<summary>Plugin doesn't load in IDA / "No module named 'ida_multi_mcp'"</summary>

This usually means IDA's Python cannot find the package due to a **Python version mismatch**.

1. Check IDA's Python version — in the IDA console, run:
   ```
   import sys; print(sys.version)
   ```
2. Install the package for that specific Python version:

   **macOS:**
   ```bash
   # Replace 3.11 with IDA's actual Python version
   python3.11 -m pip install --user git+https://github.com/MeroZemory/ida-multi-mcp.git
   ```

   **Windows:**
   ```bash
   # Replace 3.12 with IDA's actual Python version
   py -3.12 -m pip install git+https://github.com/MeroZemory/ida-multi-mcp.git
   ```

3. Ensure the IDA plugins directory contains `ida_multi_mcp.py`:
   - macOS/Linux: `~/.idapro/plugins/`
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
4. Restart IDA Pro

</details>

<details>
<summary>MCP handshake fails on Windows: "connection closed: initialize response"</summary>

This happens when the MCP client starts Python in UTF-8 mode (`PYTHONUTF8=1`, Grok and some Codex/Claude setups) on a non-English Windows console.

`ida-multi-mcp` scans for live IDA GUI processes with `tasklist` / `netstat` **before** answering MCP `initialize`. Those utilities emit OEM/GBK. With `text=True` and UTF-8 decoding, CPython's stdout reader raises `UnicodeDecodeError`, `check_output` returns `None`, and `out.strip()` crashes the process.

Current `ida-multi-mcp` decodes those commands as OEM with replacement and treats discovery failures as "no GUI instances" so headless `idalib_*` tools still start.

If you are on an older install:

```bash
pip install -U git+https://github.com/MeroZemory/ida-multi-mcp.git
```

Then restart the MCP client. You do **not** need IDA GUI running for the stdio server to handshake.

</details>

<details>
<summary>MCP server fails to connect (macOS)</summary>

If your MCP client shows `Status: failed` for ida-multi-mcp, the registered command may point to the wrong Python version.

1. Check what command is configured (e.g., in `.claude.json`, `.cursor/mcp.json`)
2. If it shows `python3 -m ida_multi_mcp`, replace it with the pipx-managed CLI:

   **Claude Code:**
   ```bash
   claude mcp remove ida-multi-mcp -s user
   claude mcp add ida-multi-mcp -s user -- ida-multi-mcp
   ```

   **Other clients:** Edit the MCP config JSON and change:
   ```json
   {
     "command": "ida-multi-mcp",
     "args": []
   }
   ```

3. Restart the MCP client

</details>

<details>
<summary>Codex fails to start on Windows with TOML parse error</summary>

If Codex prints an error like `invalid unquoted key` for `%USERPROFILE%\.codex\config.toml`, the config contains Windows paths that are not valid TOML syntax.

Use literal quoted keys/strings for Windows paths:

```toml
[projects.'\\?\C:\Git\MeroZemory\tidy-up']
trust_level = "trusted"

[mcp_servers.ida-multi-mcp]
command = 'C:\Users\MeroZemory\AppData\Local\Programs\Python\Python311\python.exe'
args = ["-m", "ida_multi_mcp"]
```

Do not use unquoted `\\?\...` project table keys, and do not use double-quoted Windows paths unless backslashes are escaped.

</details>

## Uninstallation

<details>
<summary><b>macOS</b></summary>

```bash
# 1. Remove IDA plugin + MCP client configurations
ida-multi-mcp --uninstall

# 2. Remove packages
pipx uninstall ida-multi-mcp
python3.11 -m pip uninstall -y ida-multi-mcp  # replace 3.11 with IDA's version
```

</details>

<details>
<summary><b>Windows</b></summary>

```bash
# 1. Remove IDA plugin + MCP client configurations
ida-multi-mcp --uninstall

# (optional) If IDA is installed in a custom location
ida-multi-mcp --uninstall --ida-dir "C:\Program Files\IDA Pro 9.0"

# 2. Remove the Python package
python -m pip uninstall -y ida-multi-mcp
```

</details>

After uninstalling, fully restart IDA Pro and your MCP client(s) so the removed configuration is picked up.
