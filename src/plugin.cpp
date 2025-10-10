#include <winsock2.h>
#include <windows.h>

#include <cstdlib>
#include <cstring>
#include <string>

#include <ws2tcpip.h>
#include <string>

#include "pluginsdk/_plugins.h"
#include "pluginsdk/bridgemain.h"

#include "logging.h"
#include "mcp_server.h"

static HMODULE g_pluginInstance = nullptr;
static int g_pluginHandle = -1;
static unsigned short g_serverPort = 51337;
static std::string g_serverHost = "0.0.0.0";
static McpServer g_mcpServer;

namespace
{
    constexpr auto kPluginName = "MCPluginForX96Dbg";
    constexpr auto kDebuggerFlavor = sizeof(void*) == 8 ? "x64dbg" : "x96dbg";
    constexpr auto kArchitectureLabel = sizeof(void*) == 8 ? "x64" : "x86";

    bool isValidBindAddress(const char* value)
    {
        if(!value || !*value)
            return false;

        if(std::strcmp(value, "*") == 0 || std::strcmp(value, "any") == 0)
            return true;

        in_addr addr{};
        return inet_pton(AF_INET, value, &addr) == 1;
    }

    bool restartServer()
    {
        if(g_mcpServer.isRunning())
        {
            LogInfo("Stopping MCP server for restart");
            g_mcpServer.stop();
        }
        bool started = g_mcpServer.start(g_serverHost, g_serverPort);
        if(started)
            LogInfoF("MCP server listening on %s:%u", g_mcpServer.host().c_str(), g_mcpServer.port());
        else
            LogErrorF("Failed to start MCP server on %s:%u", g_serverHost.c_str(), g_serverPort);
        return started;
    }

    unsigned short clampPort(unsigned long value)
    {
        if(value > 0xFFFF)
            value = 0xFFFF;
        if(value == 0)
            value = 1;
        return static_cast<unsigned short>(value);
    }

    bool cmdStatus(int, char**)
    {
        LogInfoF("Server status requested: %s (%s:%u) [%s/%s]",
                 g_mcpServer.isRunning() ? "running" : "stopped",
                 g_serverHost.c_str(),
                 g_serverPort,
                 kDebuggerFlavor,
                 kArchitectureLabel);
        return true;
    }

    bool cmdRestart(int, char**)
    {
        if(restartServer())
        {
            LogInfoF("Server restarted on %s:%u", g_serverHost.c_str(), g_serverPort);
            return true;
        }
        LogError("Server restart failed");
        return false;
    }

    bool cmdPort(int argc, char** argv)
    {
        if(argc < 2)
        {
            LogWarning("mcp.port usage: mcp.port <newPort>");
            return false;
        }

        char* end = nullptr;
        unsigned long parsed = std::strtoul(argv[1], &end, 0);
        if(!end || *end != '\0')
        {
            LogErrorF("Invalid port value: %s", argv[1]);
            return false;
        }

        unsigned short newPort = clampPort(parsed);
        if(newPort == g_serverPort)
        {
            LogInfoF("Port unchanged (%u)", g_serverPort);
            return true;
        }

        g_serverPort = newPort;
        BridgeSettingSetUint("MCP", "Port", g_serverPort);
        LogInfoF("Updated server port to %u (persisted)", g_serverPort);
        return cmdRestart(argc, argv);
    }

    bool cmdHost(int argc, char** argv)
    {
        if(argc < 2)
        {
            LogWarning("mcp.host usage: mcp.host <IPv4|0.0.0.0|*>");
            return false;
        }

        const char* requested = argv[1];
        if(!isValidBindAddress(requested))
        {
            LogErrorF("Invalid host value: %s", requested);
            return false;
        }

        std::string normalized = requested;
        if(normalized == "*" || normalized == "any")
            normalized = "0.0.0.0";

        if(normalized == g_serverHost)
        {
            LogInfoF("Host unchanged (%s)", g_serverHost.c_str());
            return true;
        }

        g_serverHost = normalized;
        BridgeSettingSet("MCP", "Host", g_serverHost.c_str());
        LogInfoF("Updated server host to %s (persisted)", g_serverHost.c_str());
        return cmdRestart(argc, argv);
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    if(!initStruct)
        return false;

    g_pluginHandle = initStruct->pluginHandle;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    initStruct->pluginVersion = 1;
    std::strncpy(initStruct->pluginName, kPluginName, sizeof(initStruct->pluginName) - 1);
    initStruct->pluginName[sizeof(initStruct->pluginName) - 1] = '\0';

    duint storedPort = 0;
    if(BridgeSettingGetUint("MCP", "Port", &storedPort))
        g_serverPort = clampPort(static_cast<unsigned long>(storedPort));

    char storedHost[256] = {};
    if(BridgeSettingGet("MCP", "Host", storedHost) && storedHost[0])
    {
        if(isValidBindAddress(storedHost))
        {
            std::string normalized = storedHost;
            if(normalized == "*" || normalized == "any")
                normalized = "0.0.0.0";
            g_serverHost = normalized;
        }
        else
        {
            LogWarningF("Ignoring invalid stored host '%s'", storedHost);
        }
    }

    if(!g_mcpServer.start(g_serverHost, g_serverPort))
    {
        LogErrorF("Failed to start MCP server on %s:%u", g_serverHost.c_str(), g_serverPort);
        return false;
    }

    LogInfoF("Plugin initialized (handle=%d, debugger=%s, arch=%s). Listening on %s:%u",
             g_pluginHandle,
             kDebuggerFlavor,
             kArchitectureLabel,
             g_serverHost.c_str(),
             g_serverPort);
    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    g_mcpServer.stop();
    LogInfo("Plugin stop invoked");
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
    _plugin_registercommand(g_pluginHandle, "mcp.status", cmdStatus, false);
    _plugin_registercommand(g_pluginHandle, "mcp.restart", cmdRestart, false);
    _plugin_registercommand(g_pluginHandle, "mcp.port", cmdPort, false);
    _plugin_registercommand(g_pluginHandle, "mcp.host", cmdHost, false);
    LogInfo("Plugin setup complete; commands registered");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    if(ul_reason_for_call == DLL_PROCESS_ATTACH)
        g_pluginInstance = hModule;
    return TRUE;
}
