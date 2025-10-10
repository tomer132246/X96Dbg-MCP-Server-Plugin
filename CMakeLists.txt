cmake_minimum_required(VERSION 3.20)

project(MCPluginForX96Dbg LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(MCP_TARGET_ARCH "auto" CACHE STRING "Target architecture (auto, win32, x64)")
set_property(CACHE MCP_TARGET_ARCH PROPERTY STRINGS "auto" "win32" "x64")

if(NOT CMAKE_SIZEOF_VOID_P)
    message(FATAL_ERROR "CMAKE_SIZEOF_VOID_P is not defined; ensure a compiler toolchain is available before configuring.")
endif()

if(MCP_TARGET_ARCH STREQUAL "auto")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(_mcp_effective_arch "x64")
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(_mcp_effective_arch "win32")
    else()
        message(FATAL_ERROR "Unsupported pointer size ${CMAKE_SIZEOF_VOID_P}; please set MCP_TARGET_ARCH explicitly.")
    endif()
else()
    string(TOLOWER "${MCP_TARGET_ARCH}" _mcp_effective_arch)
    if(NOT (_mcp_effective_arch STREQUAL "win32" OR _mcp_effective_arch STREQUAL "x64"))
        message(FATAL_ERROR "Invalid MCP_TARGET_ARCH value '${MCP_TARGET_ARCH}'. Expected auto, win32, or x64.")
    endif()
endif()

if(_mcp_effective_arch STREQUAL "x64" AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Generator pointer size (${CMAKE_SIZEOF_VOID_P} bytes) does not match MCP_TARGET_ARCH=x64. Regenerate with -A x64 or update the preset.")
elseif(_mcp_effective_arch STREQUAL "win32" AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "Generator pointer size (${CMAKE_SIZEOF_VOID_P} bytes) does not match MCP_TARGET_ARCH=win32. Regenerate with -A Win32 or update the preset.")
endif()

set(MCP_IS_64BIT FALSE)
if(_mcp_effective_arch STREQUAL "x64")
    set(MCP_IS_64BIT TRUE)
endif()

set(PLUGIN_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/pluginsdk")
set(NLOHMANN_DIR "${CMAKE_CURRENT_LIST_DIR}/third_party/nlohmann")

set(MCP_OUTPUT_SUFFIX ".dp32")
set(MCP_OUTPUT_ARCH_DIR "win32")
set(MCP_BRIDGE_LIB "${PLUGIN_SDK_DIR}/x32bridge.lib")
set(MCP_DEBUGGER_LIB "${PLUGIN_SDK_DIR}/x32dbg.lib")

if(MCP_IS_64BIT)
    set(MCP_OUTPUT_SUFFIX ".dp64")
    set(MCP_OUTPUT_ARCH_DIR "x64")
    set(MCP_BRIDGE_LIB "${PLUGIN_SDK_DIR}/x64bridge.lib")
    set(MCP_DEBUGGER_LIB "${PLUGIN_SDK_DIR}/x64dbg.lib")
endif()

add_library(MCPluginForX96Dbg SHARED
    src/logging.cpp
    src/mcp_server.cpp
    src/plugin.cpp
    src/mcp_server.h
    src/logging.h
)

target_include_directories(MCPluginForX96Dbg
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${PLUGIN_SDK_DIR}
        ${NLOHMANN_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/src
)

target_link_libraries(MCPluginForX96Dbg
    PRIVATE
        ${MCP_DEBUGGER_LIB}
        ${MCP_BRIDGE_LIB}
        ws2_32
)

target_compile_definitions(MCPluginForX96Dbg
    PRIVATE
        _WINDOWS
        _USRDLL
        MCPLUGINFORX96DBG_EXPORTS
        MCP_TARGET_ARCH_STRING="${_mcp_effective_arch}"
        $<$<BOOL:${MCP_IS_64BIT}>:MCP_TARGET_64BIT>
)

set(_mcp_runtime_dir "${CMAKE_BINARY_DIR}/bin/${MCP_OUTPUT_ARCH_DIR}")
set(_mcp_archive_dir "${CMAKE_BINARY_DIR}/lib/${MCP_OUTPUT_ARCH_DIR}")

set_target_properties(MCPluginForX96Dbg PROPERTIES
    OUTPUT_NAME "MCPluginForX96Dbg"
    RUNTIME_OUTPUT_DIRECTORY "${_mcp_runtime_dir}"
    ARCHIVE_OUTPUT_DIRECTORY "${_mcp_archive_dir}"
    LIBRARY_OUTPUT_DIRECTORY "${_mcp_runtime_dir}"
    SUFFIX "${MCP_OUTPUT_SUFFIX}"
)

foreach(_cfg IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${_cfg}" _cfg_upper)
    set_target_properties(MCPluginForX96Dbg PROPERTIES
        "RUNTIME_OUTPUT_DIRECTORY_${_cfg_upper}" "${_mcp_runtime_dir}/${_cfg}"
        "LIBRARY_OUTPUT_DIRECTORY_${_cfg_upper}" "${_mcp_runtime_dir}/${_cfg}"
        "ARCHIVE_OUTPUT_DIRECTORY_${_cfg_upper}" "${_mcp_archive_dir}/${_cfg}"
    )
endforeach()

message(STATUS "Configured MCPluginForX96Dbg for ${_mcp_effective_arch} (output suffix ${MCP_OUTPUT_SUFFIX})")
