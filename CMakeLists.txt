cmake_minimum_required(VERSION 3.20)

project(MCPluginForX96Dbg LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Force 32-bit builds unless the generator already specifies an architecture
if(WIN32 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(STATUS "Forcing 32-bit build (Win32)")
    set(CMAKE_GENERATOR_PLATFORM "Win32" CACHE STRING "" FORCE)
endif()

set(PLUGIN_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/pluginsdk")
set(NLOHMANN_DIR "${CMAKE_CURRENT_LIST_DIR}/third_party/nlohmann")

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
        ${PLUGIN_SDK_DIR}/x32dbg.lib
        ${PLUGIN_SDK_DIR}/x32bridge.lib
        ws2_32
)

target_compile_definitions(MCPluginForX96Dbg
    PRIVATE
        WIN32
        _WINDOWS
        _USRDLL
        MCPLUGINFORX96DBG_EXPORTS
)

set_target_properties(MCPluginForX96Dbg PROPERTIES
    OUTPUT_NAME "MCPluginForX96Dbg"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    SUFFIX ".dp32"
)
