# MCPluginForX96Dbg

A 32-bit x96dbg plugin that exposes a lightweight JSON-RPC "Model Context Protocol" (MCP) bridge over TCP. The server allows automations to inspect and control the active debuggee without relying on the debugger UI.

## Features

- Starts an MCP server automatically when the plugin loads (default `0.0.0.0:51337`).
- JSON-RPC endpoints:
  - Memory & modules:
    - `readMemory` – read up to 4096 bytes from the target.
    - `listModules` – enumerate loaded modules (base, size, path, sections).
    - `getExports` / `getImports` – inspect module export/import tables.
    - `getDisassembly` – disassemble instructions at any address.
  - Page & runtime diagnostics:
    - `getPageRights` / `setPageRights` – inspect or mutate page protection.
    - `memIsCodePage` – identify executable regions.
    - `getTraceRecord` – pull coverage metadata for a page.
    - `memBpSize` – report hardware breakpoint granularity at an address.
    - `getThreads` – enumerate debugger threads with CIP, TLS, timing, and wait state info.
  - Breakpoint management:
    - `setBreakpoint` / `enableBreakpoint` / `disableBreakpoint` – manage software breakpoints.
    - `deleteBreakpoint` – remove software or hardware breakpoints.
    - `listBreakpoints` – enumerate all debugger breakpoints including hit counts and conditions.
  - Execution & state:
    - `getRegisters` – snapshot general-purpose, segment, and debug registers plus flags.
    - `runTrace` – trigger `traceinto`/`traceover` executions with an optional step count.
    - `ping` – lightweight health check.
- Runtime commands inside x96dbg:
  - `mcp.status` – print the current server state.
  - `mcp.restart` – restart the server without reloading the plugin.
  - `mcp.port <port>` – persist a new TCP port (saved to the `MCP` setting bucket).
  - `mcp.host <IPv4|0.0.0.0|*>` – persist the bind address (default `127.0.0.1`). Use `0.0.0.0` to accept LAN clients.

## Build

Configure with CMake (remember to target Win32):

```powershell
cmake -S . -B build -A Win32
cmake --build build --config Release
```

After either build, take `build/bin/Release/MCPluginForX96Dbg.dp32` together with `MCPluginForX96Dbg.json` and copy them into the x96dbg `x32\plugins` folder (typically `%APPDATA%\x96dbg\x32\plugins`). Restart the 32-bit debugger to load the plugin.

## Visual Studio Code setup

1. Install the **CMake Tools** and **C/C++** extensions in Visual Studio Code.
2. Open this repository folder and allow CMake Tools to detect the project.
3. From the command palette pick **CMake: Select a Kit** and choose the 32-bit (Win32/x86) Visual Studio compiler toolchain.
4. Run **CMake: Configure**. This mirrors `cmake -S . -B build -A Win32` and generates the build directory.
5. Run **CMake: Build** (or press `Ctrl+Shift+B`) targeting the **Release** configuration. The plugin will land in `build/bin/Release/MCPluginForX96Dbg.dll`.
6. Copy `build/bin/<config>/MCPluginForX96Dbg.dp32` **and** `MCPluginForX96Dbg.json` to `x32\plugins`, then start the 32-bit debugger—loading the plugin will spawn the MCP server on `127.0.0.1:51337` by default.

> Note: The server speaks newline-delimited JSON-RPC. If you open the port in a web browser you’ll receive a plain-text help message rather than a JSON response.

### MCP client configuration for VS Code

Visual Studio Code can forward requests to the plugin's MCP server via the Model Context Protocol bridge. Create `.vscode/mcp.json` (or update your global `mcp.json`) with the following entry:

```json
{
  "mcpServers": {
    "x96dbg-mcp": {
      "command": "python",
      "args": [
        "${workspaceFolder}/tools/mcp_tcp_bridge.py",
        "--host",
        "127.0.0.1",
        "--port",
        "51337"
      ],
      "description": "Connects VS Code to the x96dbg MCP plugin running on the local machine."
    }
  }
}
```

> 💡 Ensure Python 3.9+ is on your PATH. The helper script simply forwards newline-delimited JSON between VS Code and the plugin. Load the plugin in x96dbg before VS Code connects. The plugin binds to `0.0.0.0` by default; adjust the `--host` argument as needed, or run `mcp.host 127.0.0.1` inside x96dbg to restrict access to loopback only.

## Protocol Overview

Connections are accepted on `127.0.0.1:<port>` using a single-line JSON-RPC framing (newline-delimited). Example interaction:

```
{"jsonrpc":"2.0","id":1,"method":"readMemory","params":{"address":"0x401000","size":16}}
```

Successful responses mirror the same `id` and contain a `result` object. Failures return an `error` block with a numeric `code` and printable `message`.

## Safety Notes

- By default the plugin listens on all interfaces (`0.0.0.0`). Change the port via `mcp.port <value>` if needed, and optionally return to loopback-only mode with `mcp.host 127.0.0.1` for tighter security.
- To serve LAN clients, run `mcp.host 0.0.0.0` (or a specific IPv4). Remember this exposes the JSON-RPC interface beyond the local machine—restrict usage to trusted networks.
- Requests require an attached debuggee. Operations will fail gracefully with `No debuggee attached` when the debugger is idle.
- Memory reads are capped at 4096 bytes per request to avoid large transfers.

## Next Steps
-Implement this for x96-64Dbg

## Donations
https://www.paypal.com/donate/?hosted_button_id=JX66BE5XAGVQE
