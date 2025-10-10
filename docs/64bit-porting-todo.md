# 64-bit Porting Plan

_Last updated: 2025-10-10_

> **Status:** Implementation complete. The notes below remain as documentation of the workstreams that were executed and serve as a checklist for future regressions.

The goal is to support building and shipping the MCP plugin for both debugger flavors:

- **x96dbg / 32-bit** – current implementation and packaging remain intact.
- **x64dbg / 64-bit** – new build artefact produced from the same code base with minimal duplication.

This document captures the research findings and enumerates every code, build, and documentation change required before implementation begins.

---

## 1. High-level tasks

1. **Adjust the build system to support dual architectures.**
   - Allow both Win32 and x64 configurations from a single CMake project.
   - Emit architecture-appropriate artefacts: `.dp32` for Win32, `.dp64` for x64.
   - Link against the correct SDK libraries (`x32dbg/x32bridge` vs `x64dbg/x64bridge`).
   - Provide configuration options (cache variables or presets) so the developer can explicitly choose the target.
2. **Audit the code for architecture-specific logic.**
   - Ensure address formatting, pointer casts, and JSON outputs remain correct on 64-bit.
   - Expand register reporting for x64 (RAX/RBX/… plus extended registers).
   - Review breakpoint handling, thread info, page rights, and script API usage for architecture-neutral behavior; add `#ifdef _WIN64` branches where data layouts diverge.
3. **Update packaging & metadata.**
   - Produce separate plugin binaries (`MCPluginForX96Dbg.dp32`, `MCPluginForX96Dbg.dp64`).
   - Refresh `MCPluginForX96Dbg.json` (or provide a dual-arch metadata strategy) to advertise 64-bit compatibility.
4. **Revise documentation & developer guidance.**
   - Expand the README build section with explicit Win32/x64 steps and deployment paths (`x32\plugins` vs `x64\plugins`).
   - Document the new CMake options and any prerequisites (e.g., 64-bit SDK libs).
   - Note runtime validation steps (attaching to 64-bit debuggee, verifying MCP tools).
5. **Verification workflow.**
   - Define a matrix of manual tests to run against both builds (memory read, registers, breakpoint management, etc.).
   - Consider adding CI or scripted build steps for both architectures if feasible.

---

## 2. Build system changes (CMake)

### 2.1 Remove hard-coded Win32 enforcement
- **File:** `CMakeLists.txt`, block starting at the `if(WIN32 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)` check.
- **Action:** Replace the block with logic that respects the user-selected generator platform.
  - Optionally introduce a cache variable (e.g., `MCP_TARGET_ARCH`) defaulting to `win32` but allowing `x64`.
  - Validate the supplied architecture and emit a clear error if incompatible.

### 2.2 Architecture-aware target properties
- **File:** `CMakeLists.txt`, `target_link_libraries` call.
  - Use generator expressions: `${PLUGIN_SDK_DIR}/x32dbg.lib` when building for Win32, `${PLUGIN_SDK_DIR}/x64dbg.lib` for x64 (and similarly for the bridge library).
  - Confirm the libs exist in the SDK (already present: `x32dbg.lib`, `x32bridge.lib`, `x64dbg.lib`, `x64bridge.lib`).
- **File:** `CMakeLists.txt`, `target_compile_definitions`.
  - Remove hard-coded `WIN32` define; rely on the compiler-provided macros. Add a custom definition (e.g., `MCP_TARGET_64BIT`) if needed by the code.
- **File:** `CMakeLists.txt`, `set_target_properties`.
  - Adjust `SUFFIX` based on pointer size: `.dp32` when `CMAKE_SIZEOF_VOID_P == 4`, `.dp64` otherwise.
  - Ensure the output name remains consistent (`MCPluginForX96Dbg`) so packaging scripts can reuse logic.
- **Enhancement:** Optionally create two logical targets (`MCPlugin32`, `MCPlugin64`) that both include the common source list but set different compile definitions and output directories. This simplifies “build both” scenarios while keeping the code shared.

### 2.3 Toolchain presets / documentation
- Provide `CMakePresets.json` entries or README guidance for:
  - Win32 Release (`-A Win32` or preset `win32-release`).
  - x64 Release (`-A x64` or preset `x64-release`).

---

## 3. Source code adjustments

### 3.1 Register reporting (`src/mcp_server.cpp`)
- **Sections:** `handleGetRegisters`, `handleListBreakpoints` (for address formatting) already uses `duint`.
- **Updates:**
  - Under `_WIN64`, populate the JSON with 64-bit register names (`rax`, `rbx`, …, `r15`, `rip`, `rflags`).
  - Include high 32-bit registers only when available; maintain existing 32-bit outputs for Win32.
  - Expand debug registers mapping if the 64-bit `REGDUMP` structure exposes additional fields.
  - Review segment register handling; consider exposing 64-bit specific values if meaningful.

### 3.2 Format helpers & numeric conversions (`src/mcp_server.cpp` at `parseAddress`, `formatAddress`, thread handling)
- Ensure conversions rely on `duint`/`uintptr_t` (already used). Validate that stoull-based parsing continues to work for >32-bit addresses.
- For thread handles and other pointer-sized values, confirm `reinterpret_cast<uintptr_t>` is used; add explicit `#ifdef _WIN64` if additional zero-extension is required.

### 3.3 Plugin entry point (`src/plugin.cpp`)
- Review any hard-coded strings referencing “x96dbg (32-bit)” for messaging; consider conditional messaging or generalize to “x64dbg” when `_WIN64` is defined.
- If plugin naming must differ for 64-bit (e.g., `kPluginName`), confirm with x64dbg conventions. Typically, the plugin name string can stay the same; only the binary extension changes.
- Ensure `BridgeSetting...` calls remain architecture agnostic. Settings stored on disk are shared—confirm this is desired or namespace them per arch if conflicts are possible.

### 3.4 Logging & diagnostic paths (`src/logging.*`)
- Quick audit to confirm no architecture-specific assumptions (e.g., buffer sizes). No changes expected but include in final verification.

### 3.5 Conditional compilation macros
- Introduce helper macros in a shared header (e.g., `src/mcp_server.h` or a new `src/arch_config.h`) to toggle behaviors:
  - `#ifdef _WIN64` for register naming, JSON labels, packaging hints.
  - Avoid duplicating entire functions; prefer small guarded sections.

---

## 4. Packaging & metadata

### 4.1 Plugin manifest (`MCPluginForX96Dbg.json`)
- Update description to mention dual-architecture support.
- Confirm whether x64dbg expects a separate manifest (it typically reads the same file). If necessary, create a second manifest or adjust fields dynamically during packaging.
- Consider bumping `version`/`minimum_x64dbg_version` once 64-bit support ships.

### 4.2 Output layout
- Establish distinct deployment folders:
  - Win32 build → `build/bin/Release/MCPluginForX96Dbg.dp32` → copy to `<x64dbg root>/x32/plugins/`.
  - x64 build → `build/bin/Release64/MCPluginForX96Dbg.dp64` (or similar) → copy to `<x64dbg root>/x64/plugins/`.
- Update any scripts or documentation referencing the output path.

### 4.3 README updates
- Expand the “Features” intro to reflect x64dbg support.
- In the build instructions:
  - Provide commands for both architectures (PowerShell snippet similar to `cmake -S . -B build -A Win32` and `cmake -S . -B build_x64 -A x64`).
  - Note separate deployment paths and file extensions.
- If we introduce `CMakePresets.json`, document how to use them (`cmake --preset win32-release`, `cmake --build --preset win32-release`).

---

## 5. Validation checklist

1. **Build verification**
   - Compile both configurations (Debug/Release optional) and ensure artefacts are generated with correct suffixes.
   - Confirm no link errors due to mismatched SDK libraries.
2. **Runtime smoke tests (Win32 & x64)**
   - Attach debugger to sample 32-bit and 64-bit processes respectively.
   - Validate MCP connection (Ping).
   - Exercise core tools: `readMemory`, `listModules`, `getRegisters`, `setBreakpoint`, `listBreakpoints`, `getThreads`.
   - For 64-bit, verify registers show 64-bit names/values.
3. **Regression checks**
   - Ensure 32-bit plugin behavior remains unchanged.
   - Confirm settings persistence doesn’t cross-contaminate architectures (decide if shared values are acceptable).
4. **Documentation accuracy**
   - Follow the README instructions verbatim on a clean machine to ensure no missing steps.

---

## 6. Open questions / follow-ups

- **Manifest strategy:** Does x64dbg require a separate JSON manifest, or can one file serve both? Investigate official plugin guidelines.
- **Automated packaging:** Decide whether to provide a combined zip containing both `.dp32` and `.dp64` plus shared assets.
- **CI support:** Explore adding GitHub Actions or Azure Pipelines to build both architectures automatically.

---

## 7. File touch list summary

| Area | File(s) | Notes |
| --- | --- | --- |
| Build config | `CMakeLists.txt`, optional `CMakePresets.json` | Architecture handling, library selection, output suffix. |
| Plugin manifest | `MCPluginForX96Dbg.json` | Update description/version fields for dual-arch support. |
| Plugin entry | `src/plugin.cpp` | Messaging tweaks; ensure architecture-neutral behavior. |
| MCP server | `src/mcp_server.cpp`, `src/mcp_server.h` | Register JSON, helper macros, any pointer-sized formatting adjustments. |
| Logging/utilities | `src/logging.*` (review) | Confirm no size assumptions. |
| Documentation | `README.md`, new/updated sections; possibly new deployment guides. |
| New doc | `docs/64bit-porting-todo.md` | (this plan). |

---

This plan should be reviewed and refined before coding begins. Once agreed, implementation can proceed by addressing the tasks in the order above, keeping the 32-bit build healthy throughout.
