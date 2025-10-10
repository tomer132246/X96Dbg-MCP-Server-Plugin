# x96dbg Plugin & Script API Cheat Sheet

_Last updated: 2025-10-10_

This document summarizes the API surface exposed by x96dbg to native plugins and scripting helpers. It distills the headers shipped in `pluginsdk/` and highlights the calls that are most relevant to the MCP plugin project.

> **Naming note:** the SDK keeps the historical `x64dbg` naming even when targeting the 32-bit build (x96dbg). The symbols are identical for both bitnesses; conditional fields that only exist on 64-bit builds are called out where relevant.

## Plugin lifecycle and core glue

x96dbg loads plugins as native DLLs. Each plugin must export three entry points:

| Export | Signature | Purpose |
| --- | --- | --- |
| `pluginit` | `bool pluginit(PLUG_INITSTRUCT* init)` | Called first. Provide metadata (`sdkVersion`, `pluginVersion`, `pluginName`) and capture the debugger-assigned `pluginHandle`. Return `false` to abort loading. |
| `plugsetup` | `void plugsetup(PLUG_SETUPSTRUCT* setup)` | Called after the UI is ready. Use it to register menu items and commands. |
| `plugstop` | `bool plugstop()` | Called when the plugin is unloaded; return `true` to acknowledge. |

Key structs defined in `_plugins.h`:

- `PLUG_INITSTRUCT`: debugger -> plugin metadata plus fields the plugin fills during `pluginit`.
- `PLUG_SETUPSTRUCT`: contains HWND/menu handles for all major debugger panes (Disasm, Dump, Stack, Mem map, Graph, Symbol module).
- `PLUG_SCRIPTSTRUCT`: storage for script-hosted data.

### Registering commands & callbacks

`_plugins.h` also exposes helpers the debugger exports to plugins. Highlights:

- `_plugin_registercommand(int pluginHandle, const char* name, CBPLUGINCOMMAND cb, bool debugonly)` – bind textual commands (e.g., `mcp.status`).
- `_plugin_unregistercommand`, `_plugin_startscript`, `_plugin_waituntilpaused` – manage commands and script execution hooks.
- `_plugin_registercallback` / `_plugin_unregistercallback` – subscribe to `CBTYPE` events (see `_plugins.h` for the full enum), including debugger lifecycle (`CB_INITDEBUG`, `CB_STOPDEBUG`), breakpoint hits, menu actions, and UI messages.
- `_plugin_logprintf`, `_plugin_logputs`, `_plugin_logprint`, `_plugin_lograw_html` – emit log output to the GUI log pane.
- `_plugin_debugpause`, `_plugin_debugskipexceptions(bool)` – interact with the debug session.
- Menu helpers (`_plugin_menuadd`, `_plugin_menuaddentry`, `_plugin_menuentryseticon`, etc.) allow populating the various context menus exposed via `PLUG_SETUPSTRUCT` handles.
- Expression helpers and formatters (`_plugin_registerexprfunction`, `_plugin_registerformatfunction`) add custom evaluators to x96dbg’s expression engine.

## Bridge helpers (`bridgemain.h`)

These C exports form the low-level glue between the GUI and debugger cores. For plugins they’re mostly optional but extremely useful for shared utilities.

- `BridgeInit()` / `BridgeStart()` – initialize the bridge pair; typically handled by x96dbg itself before plugins load.
- `BridgeAlloc(size_t)` / `BridgeFree(void*)` – debugger-side heap allocation (distinct from the debuggee).
- Settings persistence: `BridgeSettingGet*`, `BridgeSettingSet*`, `BridgeSettingFlush()`, `BridgeSettingRead()`.
- Environment: `BridgeGetDbgVersion()`, `BridgeIsProcessElevated()`, `BridgeGetNtBuildNumber()`, `BridgeUserDirectory()`.
- Thread information: `DbgGetThreadList(THREADLIST*)` fills a heap-allocated array of `THREADALLINFO` records (free with `BridgeFree`). Each record exposes the thread ID, handle, CIP, timing counters, wait reason, and priority metadata.
- Breakpoint state: `DbgGetBpList(BPXTYPE, BPMAP*)` enumerates debugger-managed breakpoints by category, while `DbgIsBpDisabled(addr)` reports whether a software breakpoint is currently disabled.
- `ListOf(T)` macro (from `bridgelist.h`) – used by many Script APIs to return variable-length collections. Always free via `BridgeFree` when you own the memory.

## Debugger-wide utility pack (`_dbgfunctions.h`)

`DbgFunctions()` returns a giant struct of function pointers that expose additional debugger features not covered by the Script namespace. Notable entries:

- Assembly & patching: `AssembleAtEx`, `Assemble`, `MemPatch`, `PatchEnum`, `PatchRestore`, `PatchFile`.
- Module helpers: `ModBaseFromAddr`, `ModNameFromAddr`, `ModPathFrom*`, `ModRelocations*`, `ModSymbolStatus`, `RefreshModuleList`.
- Runtime state: `GetCallStack`, `GetCallStackEx`, `GetSEHChain`, `GetDbgEvents`, `GetProcessList`, `IsProcessElevated`.
- Memory information: `GetPageRights`, `SetPageRights`, `MemIsCodePage`, `GetTraceRecord*`, `MemBpSize`.
- Comment / symbol helpers: `GetUserComment`, `EnumConstants`, `EnumExceptions`, `EnumErrorCodes`.
- Handles introspection: `EnumHandles`, `GetHandleName`, `EnumTcpConnections`, `HandlesEnumWindows`, `HandlesEnumHeaps`.
- Misc: `AnimateCommand` (execute UI command strings), `DbgSetDebuggeeInitScript`, `SymAutoComplete`, hashing utilities (`DbGetHash`).

Each entry is documented briefly in the header; the list is append-only, meaning indices stay stable across releases.

## Script API namespaces

The Script API (`Script::<Area>::*`) is exported to both plugins and script engines. Namespaces fall under `_scriptapi_*.h`.

### Memory access (`Script::Memory`)

- Raw reads/writes: `Read`, `Write`, `ReadByte/Word/Dword/Qword`, `Write*` counterparts, `ReadPtr`, `WritePtr`.
- Allocation in the target: `RemoteAlloc(addrHint, size)`, `RemoteFree(addr)`.
- Information queries: `IsValidPtr`, `GetProtect`, `SetProtect`, `GetBase`, `GetSize`.

### Module metadata (`Script::Module`)

- Resolve by address or name: `InfoFromAddr`, `InfoFromName`, `BaseFrom*`, `SizeFrom*`, `EntryFrom*`.
- Names & paths: `NameFromAddr`, `PathFromAddr`, `PathFromName`.
- Sections: `SectionCountFrom*`, `SectionFrom*`, `SectionListFrom*` with `ModuleSectionInfo` describing `addr`, `size`, `name`.
- Enumerate: `GetList` (all modules), `GetMainModule*`, `GetExports`, `GetImports` with `ModuleExport/ModuleImport` records (include ordinal, RVA, forwarded flag, decorated/undecorated names).

### Registers & flags (`Script::Register`, `Script::Flag`, `Script::Stack`)

- Generic `Get`/`Set(RegisterEnum)` plus typed helpers for every architectural register. 64-bit-only registers are enclosed in `#ifdef _WIN64`.
- `Size()` returns the register width for the current architecture.
- Debug registers DR0–DR7 have specialized accessors.
- Flag operations via `Script::Flag::Get/Set` or individual helpers for ZF/OF/CF/etc.
- Stack helpers: `Stack::Push`, `Stack::Pop`, `Stack::Peek(offset)` using natural register width units.

### Debug control (`Script::Debug`)

- Execution control: `Wait()`, `Run()`, `Pause()`, `Stop()`, `StepIn()`, `StepOver()`, `StepOut()`.
- Breakpoints: `SetBreakpoint`, `DeleteBreakpoint`, `DisableBreakpoint` for software; `SetHardwareBreakpoint`, `DeleteHardwareBreakpoint` with optional `HardwareType` (Access/Write/Execute).

### Annotations and navigation (`Script::Comment`, `Script::Label`, `Script::Function`, `Script::Bookmark`, `Script::Symbol`)

Each namespace manages a different disassembly annotation type. They expose a consistent shape:

- `Set(...)`, `Get(...)`, `Delete(...)`, `DeleteRange(start, end)`, `Clear()` to manage entries.
- `GetInfo(...)` returns structs containing module name, RVA, and metadata such as `manual` and label/comment text.
- `GetList(ListOf(...))` enumerates everything; caller must free the returned list via `BridgeFree`.
- `Label::FromString` resolves textual labels to addresses; `Label::IsTemporary` checks auto-generated labels.
- `Function::Add/Delete` manage function boundaries (`FunctionInfo` includes instruction counts).
- `Symbol::GetList` enumerates exports/imports/manual symbols.

### Miscellaneous utilities (`Script::Misc`)

- `ParseExpression(expression, &value)` – evaluate x96dbg expression strings.
- `RemoteGetProcAddress(module, api)` – resolve API addresses inside the debuggee.
- `ResolveLabel(label)` – look up disassembly labels.
- `Alloc` / `Free` – debugger heap helpers (mirrors `BridgeAlloc/Free`).

### Patterns & assembler helpers

- `_scriptapi_pattern.h` exposes `Find`, `FindMem`, and mask-based pattern matching across memory.
- `_scriptapi_assembler.h` provides `Assemble`/`Disassemble` helpers (thin wrappers over Keystone/Zydis via the debugger).
- `_scriptapi_argument.h` offers access to function argument annotations (used by `Function` metadata).

## Event callbacks (CBTYPE)

Plugins can subscribe to dozens of debugger events via `_plugin_registercallback`:

- Debug lifecycle: `CB_INITDEBUG`, `CB_CREATEPROCESS`, `CB_STOPDEBUG`, `CB_ATTACH`, `CB_DETACH`, `CB_EXCEPTION`.
- Thread/Module events: `CB_CREATETHREAD`, `CB_LOADDLL`, `CB_UNLOADDLL`, `CB_EXITTHREAD`, `CB_EXITPROCESS`.
- Breakpoints & stepping: `CB_BREAKPOINT`, `CB_STEPPED`, `CB_RESUMEDEBUG`, `CB_PAUSEDEBUG`.
- UI & analysis: `CB_MENUENTRY`, `CB_ANALYZE`, `CB_ADDRINFO`, `CB_SELCHANGED`, `CB_WINEVENT`, `CB_WINEVENTGLOBAL`.
- Database persistence: `CB_LOADSAVEDB`, `CB_SAVEDB` with JSON payloads.
- Expression evaluation overrides: `CB_VALFROMSTRING`, `CB_VALTOSTRING`.
- Trace & instrumentation: `CB_TRACEEXECUTE` (per-instruction callback), `CB_SYSTEMBREAKPOINT`, `CB_STOPPINGDEBUG`.

Each callback passes a specific structure (e.g., `PLUG_CB_BREAKPOINT`, `PLUG_CB_EXCEPTION`) defined in `_plugins.h`.

## Data structures used by the SDK

- Scalars: `duint` (pointer-sized unsigned integer), `dsint` (signed counterpart).
- Fixed-size strings: module names (`MAX_MODULE_SIZE`), labels (`MAX_LABEL_SIZE`), comments (`MAX_COMMENT_SIZE`), generic strings (`MAX_STRING_SIZE`). Ensure target buffers are at least these sizes when calling APIs that write into plugin-managed memory.
- `ListOf(T)` container: allocate with `BridgeList<T>` helper (C++) or let the API produce it; always call `BridgeFree(list->data)` / `BridgeFree(list)` when done.

## Integration tips for the MCP plugin

- Prefer Script APIs for day-to-day debugger interaction (memory, modules, registers). They are architecture aware and enforce correct calling conventions.
- Use `BridgeSettingGetUint`/`BridgeSettingSet` to persist user-configurable options (e.g., MCP server host/port), as demonstrated in `plugin.cpp`.
- When exposing functionality via MCP, map each method to the closest Script or DbgFunction call to minimize manual parsing.
- Free every allocation the debugger returns (module lists, export arrays, etc.) using `BridgeFree` to avoid leaking debugger memory.
- For high-frequency operations (memory reads, register snapshots), favor the typed helpers (e.g., `ReadByte`, `GetRAX`) to avoid manual buffer management.

## Reference links

- Official plugin documentation: <https://help.x64dbg.com/en/latest/developers/index.html>
- Script API reference: <https://help.x64dbg.com/en/latest/developers/commands/Script.html>
- Example plugins: <https://github.com/x64dbg/x64dbg/tree/development/src/dbg/plugins>

---

If additional headers or undocumented fields are needed, inspect the remaining `_scriptapi_*.h` and `bridgemain.h` sections in `pluginsdk/`. They closely mirror the debugger’s own internal APIs and are considered stable unless noted otherwise.
