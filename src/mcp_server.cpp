#include "mcp_server.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>
#include <limits>
#include <unordered_set>

#include <ws2tcpip.h>

#include "pluginsdk/bridgemain.h"
#include "pluginsdk/bridgelist.h"
#include "pluginsdk/_dbgfunctions.h"
#include "pluginsdk/_scriptapi_debug.h"
#include "pluginsdk/_scriptapi_module.h"

#include "logging.h"

#pragma comment(lib, "Ws2_32.lib")

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

using json = nlohmann::json;

namespace
{
    constexpr size_t kMaxMemoryRead = 0x1000;

    struct ResourceDefinition
    {
        const char* uri;
        const char* name;
        const char* description;
        const char* mimeType;
        const char* body;
        const char* category;
    };

    constexpr ResourceDefinition kStaticResources[] = {
        {
            "mcp://mcplugin/resources/overview",
            "MCPluginForX96Dbg overview",
            "What this MCP server exposes and how to connect Cursor or VS Code.",
            "text/markdown",
            R"(## MCPluginForX96Dbg Overview

This MCP server forwards a 32-bit x96dbg session to MCP-aware clients so they can call debugger tooling without leaving their editor.

### Capabilities
- Memory inspection (`readMemory`, `writeMemory`, `patternScan`)
- Module, import, export, thread, and breakpoint enumeration
- Page rights queries/updates and trace helpers
- Register snapshots (`getRegisters`) and disassembly (`getDisassembly`)

### Connecting from Cursor
1. Load the MCPluginForX96Dbg plugin inside x96dbg.
2. Start the MCP server (or use `tools/mcp_tcp_bridge.py`) on `host:port` that matches your `mcp.json`.
3. Add the entry from `MCPluginForX96Dbg.json` (or `mcp.json`) to Cursor's MCP configuration.
4. Launch Cursor's MCP panel and connect to `x96dbg-mcp`.

### Notes
- Only 32-bit sessions are supported today.
- Most tools expect the debuggee to be paused/broken in x96dbg.
- Any errors reported in Cursor are also logged in the x96dbg log window for troubleshooting.)",
            "documentation"
        },
        {
            "mcp://mcplugin/resources/tools",
            "Available tools",
            "Reference sheet for the debugger-oriented tools this server exposes.",
            "text/markdown",
            R"(## Tool Reference

| Tool | Summary |
| --- | --- |
| readMemory | Dump bytes from the target address space (max 4 KB per call). |
| writeMemory | Patch bytes with optional temporary page-rights escalation. |
| listModules | Enumerate loaded modules with base, size, entry, and sections. |
| getExports / getImports | Inspect module export and import tables. |
| getDisassembly | Disassemble up to 64 instructions from an address. |
| getRegisters | Snapshot general, debug, and flag registers. |
| getThreads | Inspect debugger threads, priorities, wait reasons, and CIP. |
| listBreakpoints / setBreakpoint / enableBreakpoint / disableBreakpoint / deleteBreakpoint | Manage all x96dbg breakpoint flavors. |
| getPageRights / setPageRights / memIsCodePage | Query/modify memory protections. |
| runTrace / getTraceRecord / memBpSize | Helpers for trace and memory-breakpoint diagnostics. |
| patternScan | Binary pattern search with wildcard support. |
| getPageRights | Inspect rights + guard bits for an address. |
| ping | Lightweight health check. |

Each tool maps directly to an x96dbg API call; detailed schemas are available through `tools/list`.)",
            "reference"
        }
    };

    const ResourceDefinition* findResourceDefinition(const std::string& uri)
    {
        for(const auto& resource : kStaticResources)
        {
            if(uri == resource.uri)
                return &resource;
        }
        return nullptr;
    }

    const std::unordered_set<std::string> kDirectToolMethods = {
        "readMemory",
        "writeMemory",
        "listModules",
        "getExports",
        "getImports",
        "getDisassembly",
        "getThreads",
        "getPageRights",
        "setPageRights",
        "memIsCodePage",
        "getTraceRecord",
        "memBpSize",
        "patternScan",
        "listBreakpoints",
        "deleteBreakpoint",
        "disableBreakpoint",
        "enableBreakpoint",
        "setBreakpoint",
        "getRegisters",
        "runTrace",
        "ping"
    };

    void ensureToolResponseFormat(const std::string& method, json& result)
    {
        if(!kDirectToolMethods.count(method))
            return;

        if(result.contains("content"))
            return;

        const json structuredCopy = result;

        std::string summary = "Tool '" + method + "' completed successfully.";
        json content = json::array();
        content.push_back({
            {"type", "text"},
            {"text", summary}
        });
        content.push_back({
            {"type", "text"},
            {"text", structuredCopy.dump(2)}
        });

        result["content"] = content;
        if(!result.contains("structured"))
            result["structured"] = structuredCopy;

        LogInfoF("Added MCP content envelope for method '%s'", method.c_str());
    }

    std::string sanitizeMessage(const std::string& message)
    {
        std::string result = message;
        std::replace(result.begin(), result.end(), '\r', ' ');
        std::replace(result.begin(), result.end(), '\n', ' ');
        return result;
        }

        bool isLikelyHttpRequestLine(const std::string& line)
        {
            if(line.find("HTTP/") != std::string::npos)
                return true;

            static const std::array<const char*, 6> prefixes = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "};
            for(const char* prefix : prefixes)
            {
                if(line.rfind(prefix, 0) == 0)
                    return true;
            }

            return false;
    }

    uint64_t fileTimeToUInt64(const FILETIME& fileTime)
    {
        ULARGE_INTEGER value{};
        value.LowPart = fileTime.dwLowDateTime;
        value.HighPart = fileTime.dwHighDateTime;
        return value.QuadPart;
    }

    std::string fileTimeToIsoString(const FILETIME& fileTime)
    {
        if(fileTime.dwLowDateTime == 0 && fileTime.dwHighDateTime == 0)
            return std::string();

        SYSTEMTIME systemTime{};
        if(!FileTimeToSystemTime(&fileTime, &systemTime))
            return std::string();

        char buffer[64] = {};
        const int written = std::snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                                           systemTime.wYear,
                                           systemTime.wMonth,
                                           systemTime.wDay,
                                           systemTime.wHour,
                                           systemTime.wMinute,
                                           systemTime.wSecond,
                                           systemTime.wMilliseconds);
        if(written <= 0)
            return std::string();

        size_t usable = static_cast<size_t>(written);
        if(usable >= sizeof(buffer))
            usable = sizeof(buffer) - 1;

        return std::string(buffer, buffer + usable);
    }

    std::string threadPriorityToString(THREADPRIORITY priority)
    {
        switch(priority)
        {
        case _PriorityIdle:
            return "Idle";
        case _PriorityAboveNormal:
            return "AboveNormal";
        case _PriorityBelowNormal:
            return "BelowNormal";
        case _PriorityHighest:
            return "Highest";
        case _PriorityLowest:
            return "Lowest";
        case _PriorityNormal:
            return "Normal";
        case _PriorityTimeCritical:
            return "TimeCritical";
        case _PriorityUnknown:
            return "Unknown";
        default:
            return std::string("Value(") + std::to_string(static_cast<int>(priority)) + ')';
        }
    }

    std::string threadWaitReasonToString(THREADWAITREASON reason)
    {
        switch(reason)
        {
        case _Executive:
            return "Executive";
        case _FreePage:
            return "FreePage";
        case _PageIn:
            return "PageIn";
        case _PoolAllocation:
            return "PoolAllocation";
        case _DelayExecution:
            return "DelayExecution";
        case _Suspended:
            return "Suspended";
        case _UserRequest:
            return "UserRequest";
        case _WrExecutive:
            return "WrExecutive";
        case _WrFreePage:
            return "WrFreePage";
        case _WrPageIn:
            return "WrPageIn";
        case _WrPoolAllocation:
            return "WrPoolAllocation";
        case _WrDelayExecution:
            return "WrDelayExecution";
        case _WrSuspended:
            return "WrSuspended";
        case _WrUserRequest:
            return "WrUserRequest";
        case _WrEventPair:
            return "WrEventPair";
        case _WrQueue:
            return "WrQueue";
        case _WrLpcReceive:
            return "WrLpcReceive";
        case _WrLpcReply:
            return "WrLpcReply";
        case _WrVirtualMemory:
            return "WrVirtualMemory";
        case _WrPageOut:
            return "WrPageOut";
        case _WrRendezvous:
            return "WrRendezvous";
        case _Spare2:
            return "Spare2";
        case _Spare3:
            return "Spare3";
        case _Spare4:
            return "Spare4";
        case _Spare5:
            return "Spare5";
        case _WrCalloutStack:
            return "WrCalloutStack";
        case _WrKernel:
            return "WrKernel";
        case _WrResource:
            return "WrResource";
        case _WrPushLock:
            return "WrPushLock";
        case _WrMutex:
            return "WrMutex";
        case _WrQuantumEnd:
            return "WrQuantumEnd";
        case _WrDispatchInt:
            return "WrDispatchInt";
        case _WrPreempted:
            return "WrPreempted";
        case _WrYieldExecution:
            return "WrYieldExecution";
        case _WrFastMutex:
            return "WrFastMutex";
        case _WrGuardedMutex:
            return "WrGuardedMutex";
        case _WrRundown:
            return "WrRundown";
        default:
            return std::string("Value(") + std::to_string(static_cast<int>(reason)) + ')';
        }
    }

    std::string toLowerCopy(const std::string& value)
    {
        std::string lower = value;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return lower;
    }

    std::string breakpointTypeToString(BPXTYPE type)
    {
        switch(type)
        {
        case bp_normal:
            return "software";
        case bp_hardware:
            return "hardware";
        case bp_memory:
            return "memory";
        case bp_dll:
            return "dll";
        case bp_exception:
            return "exception";
        case bp_none:
        default:
            return "none";
        }
    }

    bool parseBreakpointTypeString(const std::string& text, BPXTYPE& outType)
    {
        const std::string lower = toLowerCopy(text);
        if(lower == "software" || lower == "sw" || lower == "soft" || lower == "normal")
        {
            outType = bp_normal;
            return true;
        }
        if(lower == "hardware" || lower == "hw" || lower == "hard")
        {
            outType = bp_hardware;
            return true;
        }
        if(lower == "memory" || lower == "mem")
        {
            outType = bp_memory;
            return true;
        }
        if(lower == "dll" || lower == "library")
        {
            outType = bp_dll;
            return true;
        }
        if(lower == "exception" || lower == "ex")
        {
            outType = bp_exception;
            return true;
        }
        if(lower == "none")
        {
            outType = bp_none;
            return true;
        }
        return false;
    }

    std::string hardwareTypeToString(unsigned char value)
    {
        switch(static_cast<BPHWTYPE>(value))
        {
        case hw_access:
            return "access";
        case hw_write:
            return "write";
        case hw_execute:
            return "execute";
        default:
            return std::string("value(") + std::to_string(value) + ')';
        }
    }

    std::string hardwareSizeToString(unsigned char value)
    {
        switch(static_cast<BPHWSIZE>(value))
        {
        case hw_byte:
            return "byte";
        case hw_word:
            return "word";
        case hw_dword:
            return "dword";
        case hw_qword:
            return "qword";
        default:
            return std::string("value(") + std::to_string(value) + ')';
        }
    }

    std::string memoryTypeToString(unsigned char value)
    {
        switch(static_cast<BPMEMTYPE>(value))
        {
        case mem_access:
            return "access";
        case mem_read:
            return "read";
        case mem_write:
            return "write";
        case mem_execute:
            return "execute";
        default:
            return std::string("value(") + std::to_string(value) + ')';
        }
    }

    std::string dllTypeToString(unsigned char value)
    {
        switch(static_cast<BPDLLTYPE>(value))
        {
        case dll_load:
            return "load";
        case dll_unload:
            return "unload";
        case dll_all:
            return "all";
        default:
            return std::string("value(") + std::to_string(value) + ')';
        }
    }

    std::string exceptionTypeToString(unsigned char value)
    {
        switch(static_cast<BPEXTYPE>(value))
        {
        case ex_firstchance:
            return "firstChance";
        case ex_secondchance:
            return "secondChance";
        case ex_all:
            return "all";
        default:
            return std::string("value(") + std::to_string(value) + ')';
        }
    }

    std::vector<unsigned char> parseFormattedByteString(const std::string& dataText, const std::string& formatText)
    {
        const std::string format = toLowerCopy(formatText);

        if(format == "hex" || format == "bytes" || format == "byte" || format == "raw")
        {
            std::string filtered;
            filtered.reserve(dataText.size());
            for(size_t i = 0; i < dataText.size(); ++i)
            {
                char ch = dataText[i];
                if(std::isspace(static_cast<unsigned char>(ch)) || ch == ',' || ch == ';')
                    continue;
                if(ch == '0' && i + 1 < dataText.size() && (dataText[i + 1] == 'x' || dataText[i + 1] == 'X'))
                {
                    ++i;
                    continue;
                }
                filtered.push_back(ch);
            }

            if(filtered.size() % 2 != 0 || filtered.empty())
                throw std::runtime_error("Hex byte sequence must contain an even number of hexadecimal characters");

            std::vector<unsigned char> bytes;
            bytes.reserve(filtered.size() / 2);
            for(size_t i = 0; i < filtered.size(); i += 2)
            {
                const char hi = filtered[i];
                const char lo = filtered[i + 1];
                if(!std::isxdigit(static_cast<unsigned char>(hi)) || !std::isxdigit(static_cast<unsigned char>(lo)))
                    throw std::runtime_error("Hex byte sequence contains non-hexadecimal characters");
                unsigned int value = 0;
                value = static_cast<unsigned int>(std::stoul(filtered.substr(i, 2), nullptr, 16));
                bytes.push_back(static_cast<unsigned char>(value & 0xFFu));
            }

            return bytes;
        }

        if(format == "ascii" || format == "utf8" || format == "string" || format == "text")
        {
            std::vector<unsigned char> bytes(dataText.begin(), dataText.end());
            if(bytes.empty())
                throw std::runtime_error("ASCII/UTF-8 payload cannot be empty");
            return bytes;
        }

        throw std::runtime_error("Unsupported data format: " + formatText + " (use 'hex' or 'ascii')");
    }

    struct PatternParseResult
    {
        std::vector<int> pattern;
        std::string normalized;
    };

    PatternParseResult parsePatternExpression(const std::string& patternText)
    {
        std::istringstream stream(patternText);
        std::string token;
        PatternParseResult result;

        while(stream >> token)
        {
            if(token.empty())
                continue;

            if(token == "?" || token == "??")
            {
                result.pattern.push_back(-1);
                if(!result.normalized.empty())
                    result.normalized.push_back(' ');
                result.normalized += "??";
                continue;
            }

            if(token.size() == 1 && token[0] == '?')
            {
                result.pattern.push_back(-1);
                if(!result.normalized.empty())
                    result.normalized.push_back(' ');
                result.normalized += "??";
                continue;
            }

            if(token.rfind("0x", 0) == 0 || token.rfind("0X", 0) == 0)
                token = token.substr(2);

            if(token.size() != 2 || !std::isxdigit(static_cast<unsigned char>(token[0])) || !std::isxdigit(static_cast<unsigned char>(token[1])))
                throw std::runtime_error("Pattern tokens must be hex bytes or '?' wildcards");

            const unsigned int value = static_cast<unsigned int>(std::stoul(token, nullptr, 16));
            result.pattern.push_back(static_cast<int>(value & 0xFFu));

            if(!result.normalized.empty())
                result.normalized.push_back(' ');
            std::ostringstream oss;
            oss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (value & 0xFFu);
            result.normalized += oss.str();
        }

        if(result.pattern.empty())
            throw std::runtime_error("Pattern must contain at least one byte or wildcard token");

        return result;
    }
}

McpServer::McpServer()
    : running_(false), listenSocket_(INVALID_SOCKET), port_(0), activeClient_(INVALID_SOCKET), wsaInitialized_(false), host_("127.0.0.1")
{
}

McpServer::~McpServer()
{
    stop();
}

bool McpServer::start(const std::string& host, unsigned short port)
{
    std::lock_guard<std::mutex> guard(stateMutex_);
    if(running_)
        return true;

    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        LogError("Winsock initialisation failed");
        return false;
    }

    wsaInitialized_ = true;
    host_ = host.empty() ? std::string("127.0.0.1") : host;
    port_ = port;

    in_addr addr{};
    if(host_ != "0.0.0.0" && inet_pton(AF_INET, host_.c_str(), &addr) != 1)
    {
        LogErrorF("Invalid bind address %s", host_.c_str());
        WSACleanup();
        wsaInitialized_ = false;
        running_ = false;
        return false;
    }

    running_ = true;

    worker_ = std::thread(&McpServer::serverLoop, this);
    LogInfoF("Server thread starting on %s:%u", host_.c_str(), port_);
    return true;
}

void McpServer::stop()
{
    {
        std::lock_guard<std::mutex> guard(stateMutex_);
        if(!running_)
            return;
        running_ = false;
    }

    SOCKET clientToClose = INVALID_SOCKET;
    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        clientToClose = activeClient_;
    }

    if(clientToClose != INVALID_SOCKET)
        shutdown(clientToClose, SD_BOTH);

    if(listenSocket_ != INVALID_SOCKET)
    {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }

    if(worker_.joinable())
        worker_.join();

    if(wsaInitialized_)
    {
        WSACleanup();
        wsaInitialized_ = false;
    }

    LogInfo("Server stopped");
}

bool McpServer::isRunning() const
{
    return running_.load();
}

unsigned short McpServer::port() const
{
    return port_;
}

const std::string& McpServer::host() const
{
    return host_;
}

void McpServer::serverLoop()
{
    listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(listenSocket_ == INVALID_SOCKET)
    {
        LogErrorF("Failed to create listening socket (error %d)", WSAGetLastError());
        running_ = false;
        return;
    }

    sockaddr_in service{};
    service.sin_family = AF_INET;
    bool bindAny = (host_ == "0.0.0.0" || host_ == "*" || host_ == "any");
    if(bindAny)
    {
        service.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else
    {
        in_addr addr{};
        if(inet_pton(AF_INET, host_.c_str(), &addr) != 1)
        {
            LogErrorF("Invalid bind address %s", host_.c_str());
            closesocket(listenSocket_);
            listenSocket_ = INVALID_SOCKET;
            running_ = false;
            return;
        }
        service.sin_addr = addr;
    }
    service.sin_port = htons(port_);

    BOOL reuse = TRUE;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    if(bind(listenSocket_, reinterpret_cast<SOCKADDR*>(&service), sizeof(service)) == SOCKET_ERROR)
    {
        LogErrorF("Failed to bind socket on port %u (error %d)", port_, WSAGetLastError());
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        running_ = false;
        return;
    }

    if(listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR)
    {
        LogErrorF("listen() failed (error %d)", WSAGetLastError());
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        running_ = false;
        return;
    }

    LogInfoF("Listening for MCP clients on %s:%u", bindAny ? "0.0.0.0" : host_.c_str(), port_);

    while(running_)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(listenSocket_, &readSet);
        timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int selectResult = select(0, &readSet, nullptr, nullptr, &timeout);
        if(selectResult == SOCKET_ERROR)
        {
            LogWarningF("select() failed (error %d)", WSAGetLastError());
            continue;
        }

        if(selectResult == 0)
            continue;

        sockaddr_in clientAddr{};
        int addrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket_, reinterpret_cast<SOCKADDR*>(&clientAddr), &addrSize);
        if(clientSocket == INVALID_SOCKET)
        {
            if(running_)
                LogWarningF("accept() failed (error %d)", WSAGetLastError());
            continue;
        }

        char addrBuf[INET_ADDRSTRLEN] = {};
        const char* addrText = inet_ntop(AF_INET, &clientAddr.sin_addr, addrBuf, sizeof(addrBuf));
        unsigned short remotePort = ntohs(clientAddr.sin_port);
        if(addrText)
            LogInfoF("Accepted connection from %s:%u", addrText, remotePort);
        else
            LogInfo("Accepted connection from unknown address");

        handleClient(clientSocket);
        closesocket(clientSocket);
    }
}

void McpServer::handleClient(SOCKET clientSocket)
{
    struct ActiveClientScope
    {
        McpServer* server;
        SOCKET sock;
        ~ActiveClientScope()
        {
            if(!server)
                return;
            std::lock_guard<std::mutex> lock(server->clientMutex_);
            if(server->activeClient_ == sock)
                server->activeClient_ = INVALID_SOCKET;
        }
    } scope{this, clientSocket};

    {
        std::lock_guard<std::mutex> lock(clientMutex_);
        activeClient_ = clientSocket;
    }

    LogInfo("Client connected");
    std::string buffer;
    buffer.reserve(4096);

    char recvBuffer[2048];
    while(running_)
    {
        int received = recv(clientSocket, recvBuffer, sizeof(recvBuffer), 0);
        if(received == 0)
            break; // graceful close
        if(received == SOCKET_ERROR)
        {
            LogWarningF("recv() failed (error %d)", WSAGetLastError());
            break;
        }

        buffer.append(recvBuffer, received);
        size_t newlinePos = std::string::npos;
        while((newlinePos = buffer.find('\n')) != std::string::npos)
        {
            std::string line = buffer.substr(0, newlinePos);
            buffer.erase(0, newlinePos + 1);

            if(line.empty())
                continue;

            if(!line.empty() && line.back() == '\r')
                line.pop_back();

            if(isLikelyHttpRequestLine(line))
            {
                if(handleHttpClient(clientSocket))
                    return;
                continue;
            }

            json request;
            try
            {
                request = json::parse(line);
            }
            catch(const std::exception& ex)
            {
                LogWarningF("Received invalid JSON: %s", sanitizeMessage(ex.what()).c_str());
                sendError(clientSocket, json(), -32700, "Invalid JSON");
                continue;
            }

            json response;
            if(processRequest(request, response))
            {
                if(!response.is_null())
                    sendJson(clientSocket, response);
            }
            else if(!response.is_null())
            {
                sendJson(clientSocket, response);
            }
        }
    }

    LogInfo("Client disconnected");
}

bool McpServer::handleHttpClient(SOCKET clientSocket)
{
    LogInfo("HTTP-style handshake detected; returning guidance page");
    sendHttpHelpResponse(clientSocket);
    shutdown(clientSocket, SD_SEND);
    LogInfo("Client disconnected");
    return true;
}

void McpServer::sendHttpHelpResponse(SOCKET clientSocket)
{
    std::string body =
        "MCPluginForX96Dbg speaks newline-delimited JSON-RPC 2.0.\n"
        "This endpoint is not HTTP; use a JSON-RPC client such as VS Code with the provided mcp.json.\n"
        "Example: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";

    std::ostringstream response;
    response << "HTTP/1.1 200 OK\r\n"
             << "Content-Type: text/plain; charset=utf-8\r\n"
             << "Content-Length: " << body.size() << "\r\n"
             << "Connection: close\r\n\r\n"
             << body;

    const std::string payload = response.str();
    send(clientSocket, payload.c_str(), static_cast<int>(payload.size()), 0);
}

void McpServer::sendJson(SOCKET clientSocket, const json& payload)
{
    std::string text = payload.dump();
    text.push_back('\n');
    send(clientSocket, text.c_str(), static_cast<int>(text.size()), 0);
}

void McpServer::sendError(SOCKET clientSocket, const json& id, int code, const std::string& message)
{
    json response = {
        {"jsonrpc", "2.0"},
        {"id", id.is_null() ? json() : id},
        {"error", {
            {"code", code},
            {"message", message}
        }}
    };
    sendJson(clientSocket, response);
}

bool McpServer::processRequest(const json& request, json& response)
{
    if(!request.contains("jsonrpc") || request["jsonrpc"] != "2.0")
    {
        LogWarning("Received request with invalid JSON-RPC envelope");
        response = {
            {"jsonrpc", "2.0"},
            {"id", nullptr},
            {"error", {
                {"code", -32600},
                {"message", "Invalid JSON-RPC envelope"}
            }}
        };
        return false;
    }

    json id = request.contains("id") ? request["id"] : json();

    if(!request.contains("method") || !request["method"].is_string())
    {
        LogWarning("Received request without method field");
        response = {
            {"jsonrpc", "2.0"},
            {"id", id},
            {"error", {
                {"code", -32600},
                {"message", "Missing method"}
            }}
        };
        return false;
    }

    const std::string method = request["method"].get<std::string>();
    const json params = request.contains("params") ? request["params"] : json::object();

    try
    {
        json result;
        if(method == "initialize")
        {
            LogInfo("Processing initialize request");
            result = handleInitialize(params);
        }
        else if(method == "readMemory")
        {
            LogInfo("Processing readMemory request");
            result = handleReadMemory(params);
        }
        else if(method == "listModules")
        {
            LogInfo("Processing listModules request");
            result = handleListModules(params);
        }
        else if(method == "getExports")
        {
            LogInfo("Processing getExports request");
            result = handleGetExports(params);
        }
        else if(method == "getImports")
        {
            LogInfo("Processing getImports request");
            result = handleGetImports(params);
        }
        else if(method == "getDisassembly")
        {
            LogInfo("Processing getDisassembly request");
            result = handleGetDisassembly(params);
        }
        else if(method == "getPageRights")
        {
            LogInfo("Processing getPageRights request");
            result = handleGetPageRights(params);
        }
        else if(method == "setPageRights")
        {
            LogInfo("Processing setPageRights request");
            result = handleSetPageRights(params);
        }
        else if(method == "writeMemory")
        {
            LogInfo("Processing writeMemory request");
            result = handleWriteMemory(params);
        }
        else if(method == "memIsCodePage")
        {
            LogInfo("Processing memIsCodePage request");
            result = handleMemIsCodePage(params);
        }
        else if(method == "getTraceRecord")
        {
            LogInfo("Processing getTraceRecord request");
            result = handleGetTraceRecord(params);
        }
        else if(method == "memBpSize")
        {
            LogInfo("Processing memBpSize request");
            result = handleMemBpSize(params);
        }
        else if(method == "patternScan")
        {
            LogInfo("Processing patternScan request");
            result = handlePatternScan(params);
        }
        else if(method == "listBreakpoints")
        {
            LogInfo("Processing listBreakpoints request");
            result = handleListBreakpoints(params);
        }
        else if(method == "deleteBreakpoint")
        {
            LogInfo("Processing deleteBreakpoint request");
            result = handleDeleteBreakpoint(params);
        }
        else if(method == "disableBreakpoint")
        {
            LogInfo("Processing disableBreakpoint request");
            result = handleDisableBreakpoint(params);
        }
        else if(method == "enableBreakpoint")
        {
            LogInfo("Processing enableBreakpoint request");
            result = handleEnableBreakpoint(params);
        }
        else if(method == "setBreakpoint")
        {
            LogInfo("Processing setBreakpoint request");
            result = handleSetBreakpoint(params);
        }
        else if(method == "getRegisters")
        {
            LogInfo("Processing getRegisters request");
            result = handleGetRegisters(params);
        }
        else if(method == "runTrace")
        {
            LogInfo("Processing runTrace request");
            result = handleRunTrace(params);
        }
        else if(method == "logging/setLevel")
        {
            LogInfo("Processing logging/setLevel request");
            result = handleLoggingSetLevel(params);
        }
        else if(method == "notifications/initialized")
        {
            LogInfo("Processing notifications/initialized request");
            result = handleNotificationsInitialized(params);
        }
        else if(method == "tools/list")
        {
            LogInfo("Processing tools/list request");
            result = handleToolsList();
        }
        else if(method == "tools/call")
        {
            LogInfo("Processing tools/call request");
            result = handleToolsCall(params);
        }
        else if(method == "resources/list")
        {
            LogInfo("Processing resources/list request");
            result = handleResourcesList(params);
        }
        else if(method == "resources/get")
        {
            LogInfo("Processing resources/get request");
            result = handleResourcesGet(params);
        }
        else if(method == "prompts/list")
        {
            LogInfo("Processing prompts/list request");
            result = handlePromptsList();
        }
        else if(method == "ping")
        {
            result = json::object({{"message", "pong"}});
        }
        else
        {
            LogWarningF("Unknown method requested: %s", method.c_str());
            response = {
                {"jsonrpc", "2.0"},
                {"id", id},
                {"error", {
                    {"code", -32601},
                    {"message", "Unknown method"}
                }}
            };
            return false;
        }

        ensureToolResponseFormat(method, result);

        if(id.is_null())
        {
            // Notification, do not send response
            LogInfoF("Notification %s processed, no response sent", method.c_str());
            response = json();
        }
        else
        {
            response = {
                {"jsonrpc", "2.0"},
                {"id", id},
                {"result", result}
            };
            LogInfoF("Request %s completed successfully", method.c_str());
        }
        return true;
    }
    catch(const std::exception& ex)
    {
        LogErrorF("Request %s failed: %s", method.c_str(), sanitizeMessage(ex.what()).c_str());
        
        if(id.is_null())
        {
             LogWarningF("Notification %s failed, error suppressed", method.c_str());
             response = json();
        }
        else
        {
            response = {
                {"jsonrpc", "2.0"},
                {"id", id},
                {"error", {
                    {"code", -32000},
                    {"message", sanitizeMessage(ex.what())}
                }}
            };
        }
        return false;
    }
}

json McpServer::handleReadMemory(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    size_t size = params.value("size", 0);
    if(size == 0 || size > kMaxMemoryRead)
        throw std::runtime_error("Invalid read size (1-4096 bytes allowed)");

    std::vector<unsigned char> buffer(size);
    if(!DbgMemRead(address, buffer.data(), static_cast<duint>(buffer.size())))
        throw std::runtime_error("DbgMemRead failed");

    LogInfoF("readMemory 0x%llX (%zu bytes)", static_cast<unsigned long long>(address), buffer.size());

    const std::string hexData = bytesToHex(buffer);
    json result = {
        {"address", formatAddress(address)},
        {"size", buffer.size()},
        {"data", hexData},
        {"valueHex", std::string("0x") + hexData}
    };

    return result;
}

json McpServer::handleListModules(const json&)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    BridgeList<Script::Module::ModuleInfo> moduleList;
    if(!Script::Module::GetList(&moduleList))
        throw std::runtime_error("Failed to query module list");

    json modules = json::array();
    auto data = moduleList.Data();
    if(data)
    {
        for(int i = 0; i < moduleList.Count(); ++i)
        {
            const auto& mod = data[i];
            json sections = json::array();
            if(mod.sectionCount > 0)
            {
                BridgeList<Script::Module::ModuleSectionInfo> sectionList;
                if(Script::Module::SectionListFromAddr(mod.base, &sectionList))
                {
                    auto sectionData = sectionList.Data();
                    if(sectionData)
                    {
                        for(int s = 0; s < sectionList.Count(); ++s)
                        {
                            const auto& section = sectionData[s];
                            sections.push_back({
                                {"name", section.name},
                                {"address", formatAddress(section.addr)},
                                {"size", section.size}
                            });
                        }
                    }
                }
            }

            modules.push_back({
                {"name", mod.name},
                {"path", mod.path},
                {"base", formatAddress(mod.base)},
                {"size", mod.size},
                {"entry", formatAddress(mod.entry)},
                {"sectionCount", mod.sectionCount},
                {"sections", sections}
            });
        }
    }

    LogInfoF("listModules returned %d modules", data ? moduleList.Count() : 0);
    return json::object({{"modules", modules}});
}

json McpServer::handleGetExports(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("module"))
        throw std::runtime_error("Missing module parameter");

    Script::Module::ModuleInfo info{};
    if(!resolveModuleInfo(params.at("module"), info))
        throw std::runtime_error("Module not found");

    BridgeList<Script::Module::ModuleExport> exportList;
    if(!Script::Module::GetExports(&info, &exportList))
        throw std::runtime_error("Failed to enumerate exports");

    json entries = json::array();
    auto data = exportList.Data();
    if(data)
    {
        for(int i = 0; i < exportList.Count(); ++i)
        {
            const auto& item = data[i];
            json exportJson = {
                {"ordinal", item.ordinal},
                {"rva", formatAddress(item.rva)},
                {"address", formatAddress(item.va)},
                {"forwarded", item.forwarded}
            };

            exportJson["name"] = std::string(item.name);
            exportJson["undecoratedName"] = std::string(item.undecoratedName);
            if(item.forwarded && item.forwardName[0])
                exportJson["forwardName"] = std::string(item.forwardName);

            entries.push_back(std::move(exportJson));
        }
    }

    LogInfoF("getExports module=%s count=%zu", info.name, entries.size());

    return json::object({
        {"module", std::string(info.name)},
        {"base", formatAddress(info.base)},
        {"path", std::string(info.path)},
        {"count", entries.size()},
        {"exports", entries}
    });
}

json McpServer::handleGetImports(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("module"))
        throw std::runtime_error("Missing module parameter");

    Script::Module::ModuleInfo info{};
    if(!resolveModuleInfo(params.at("module"), info))
        throw std::runtime_error("Module not found");

    BridgeList<Script::Module::ModuleImport> importList;
    if(!Script::Module::GetImports(&info, &importList))
        throw std::runtime_error("Failed to enumerate imports");

    json entries = json::array();
    auto data = importList.Data();
    if(data)
    {
        for(int i = 0; i < importList.Count(); ++i)
        {
            const auto& item = data[i];
            const bool byOrdinal = item.ordinal != static_cast<duint>(-1);

            json importJson = {
                {"iatRva", formatAddress(item.iatRva)},
                {"iatAddress", formatAddress(item.iatVa)},
                {"byOrdinal", byOrdinal}
            };

            if(byOrdinal)
                importJson["ordinal"] = item.ordinal;

            importJson["name"] = std::string(item.name);
            importJson["undecoratedName"] = std::string(item.undecoratedName);

            entries.push_back(std::move(importJson));
        }
    }

    LogInfoF("getImports module=%s count=%zu", info.name, entries.size());

    return json::object({
        {"module", std::string(info.name)},
        {"base", formatAddress(info.base)},
        {"path", std::string(info.path)},
        {"count", entries.size()},
        {"imports", entries}
    });
}

json McpServer::handleGetDisassembly(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    size_t count = params.value("count", static_cast<size_t>(8));
    if(count == 0 || count > 64)
        throw std::runtime_error("Invalid count (1-64 instructions allowed)");

    json instructions = json::array();
    duint current = address;
    const std::string startText = formatAddress(address);

    for(size_t i = 0; i < count; ++i)
    {
        DISASM_INSTR disasm{};
        DbgDisasmAt(current, &disasm);

        json args = json::array();
        for(int argIndex = 0; argIndex < disasm.argcount; ++argIndex)
        {
            const auto& arg = disasm.arg[argIndex];
            json argJson = {
                {"text", std::string(arg.mnemonic)}
            };

            if(arg.constant)
                argJson["constant"] = formatAddress(arg.constant);
            if(arg.value && arg.value != arg.constant)
                argJson["value"] = formatAddress(arg.value);
            if(arg.memvalue)
                argJson["memoryValue"] = formatAddress(arg.memvalue);

            args.push_back(std::move(argJson));
        }

        json instruction = {
            {"address", formatAddress(current)},
            {"size", disasm.instr_size},
            {"text", std::string(disasm.instruction)},
            {"type", disasmTypeToString(disasm.type)}
        };

        if(!args.empty())
            instruction["arguments"] = std::move(args);

        instructions.push_back(std::move(instruction));

        if(disasm.instr_size <= 0)
            break;

        current += static_cast<duint>(disasm.instr_size);
    }

    LogInfoF("getDisassembly start=%s count=%zu", startText.c_str(), instructions.size());

    return json::object({
        {"startAddress", startText},
        {"count", instructions.size()},
        {"instructions", instructions}
    });
}

json McpServer::handleGetThreads(const json&)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    THREADLIST list{};
    list.count = 0;
    list.list = nullptr;
    list.CurrentThread = -1;

    DbgGetThreadList(&list);

    std::unique_ptr<THREADALLINFO, decltype(&BridgeFree)> threadData(list.list, BridgeFree);

    json threads = json::array();

    auto appendTime = [](json& target, const char* key, const FILETIME& fileTime) {
        const uint64_t raw = fileTimeToUInt64(fileTime);
        if(!raw)
            return;

        json timeJson = {
            {"raw", raw},
            {"milliseconds", raw / 10000}
        };

        const std::string iso = fileTimeToIsoString(fileTime);
        if(!iso.empty())
            timeJson["iso8601"] = iso;

        target[key] = timeJson;
    };

    if(threadData)
    {
        for(int i = 0; i < list.count; ++i)
        {
            const THREADALLINFO& info = threadData.get()[i];

            json entry = {
                {"index", i},
                {"threadNumber", info.BasicInfo.ThreadNumber},
                {"threadId", info.BasicInfo.ThreadId},
                {"handle", formatAddress(static_cast<duint>(reinterpret_cast<uintptr_t>(info.BasicInfo.Handle)))},
                {"startAddress", formatAddress(info.BasicInfo.ThreadStartAddress)},
                {"threadLocalBase", formatAddress(info.BasicInfo.ThreadLocalBase)},
                {"cip", formatAddress(info.ThreadCip)},
                {"suspendCount", info.SuspendCount},
                {"priority", json::object({
                    {"value", static_cast<int>(info.Priority)},
                    {"label", threadPriorityToString(info.Priority)}
                })},
                {"waitReason", json::object({
                    {"value", static_cast<int>(info.WaitReason)},
                    {"label", threadWaitReasonToString(info.WaitReason)}
                })},
                {"lastError", info.LastError},
                {"cycles", info.Cycles}
            };

            if(info.BasicInfo.threadName[0] != '\0')
                entry["name"] = std::string(info.BasicInfo.threadName);

            entry["timing"] = json::object();
            appendTime(entry["timing"], "user", info.UserTime);
            appendTime(entry["timing"], "kernel", info.KernelTime);
            appendTime(entry["timing"], "created", info.CreationTime);

            threads.push_back(std::move(entry));
        }
    }

    json result = {
        {"threadCount", list.count},
        {"currentThreadIndex", list.CurrentThread},
        {"threads", threads}
    };

    if(list.CurrentThread >= 0 && list.CurrentThread < list.count && threadData)
    {
        const THREADALLINFO& current = threadData.get()[list.CurrentThread];
        result["currentThreadId"] = current.BasicInfo.ThreadId;
        result["currentThreadHandle"] = formatAddress(static_cast<duint>(reinterpret_cast<uintptr_t>(current.BasicInfo.Handle)));
        result["currentThreadCip"] = formatAddress(current.ThreadCip);
        if(current.BasicInfo.threadName[0] != '\0')
            result["currentThreadName"] = std::string(current.BasicInfo.threadName);
    }

    return result;
}

json McpServer::handleGetPageRights(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    bool includeString = params.value("string", true);

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if(!dbg || !dbg->GetPageRights)
        throw std::runtime_error("GetPageRights unavailable");

    char rightsBuffer[RIGHTS_STRING_SIZE] = {};
    if(!dbg->GetPageRights(address, rightsBuffer))
        throw std::runtime_error("GetPageRights failed");

    unsigned long protect = Script::Memory::GetProtect(address, false, true);
    if(protect == 0 && rightsBuffer[0] == '\0')
        LogWarning("GetProtect returned 0; page may be inaccessible");

    std::string rightsString = rightsBuffer[0] ? std::string(rightsBuffer) : rightsStringFromProtect(protect);

    json flags = json::object({
        {"execute", rightsString.find('E') != std::string::npos},
        {"read", rightsString.find('R') != std::string::npos},
        {"write", rightsString.find('W') != std::string::npos},
        {"copy", rightsString.find('C') != std::string::npos},
        {"guard", rightsString.find('G') != std::string::npos}
    });

    json result = {
        {"address", formatAddress(address)},
        {"protect", protect},
        {"flags", flags}
    };

    if(includeString)
        result["rights"] = rightsString;

    LogInfoF("getPageRights address=%s rights=%s", formatAddress(address).c_str(), rightsString.c_str());
    return result;
}

json McpServer::handleSetPageRights(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address") || !params.contains("protect") || !params.contains("size"))
        throw std::runtime_error("Missing parameters (address, protect, size required)");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    const std::string protectString = params.at("protect").get<std::string>();
    size_t size = params.at("size").get<size_t>();
    if(size == 0)
        throw std::runtime_error("Size must be greater than zero");

    unsigned long protect = protectionFromRightsString(protectString);
    if(!Script::Memory::SetProtect(address, protect, static_cast<duint>(size)))
        throw std::runtime_error("SetProtect failed");

    unsigned long effective = Script::Memory::GetProtect(address, false, true);
    std::string effectiveRights = rightsStringFromProtect(effective);

    LogInfoF("setPageRights address=%s size=%zu protect=%s", formatAddress(address).c_str(), size, protectString.c_str());

    return json::object({
        {"address", formatAddress(address)},
        {"size", size},
        {"requestedRights", protectString},
        {"effectiveProtect", effective},
        {"effectiveRights", effectiveRights}
    });
}

json McpServer::handleMemIsCodePage(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    bool refresh = params.value("refresh", false);

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if(!dbg || !dbg->MemIsCodePage)
        throw std::runtime_error("MemIsCodePage unavailable");

    bool isCode = dbg->MemIsCodePage(address, refresh);

    LogInfoF("memIsCodePage address=%s refresh=%s -> %s", formatAddress(address).c_str(), refresh ? "true" : "false", isCode ? "true" : "false");

    return json::object({
        {"address", formatAddress(address)},
        {"refresh", refresh},
        {"isCode", isCode}
    });
}

json McpServer::handleGetTraceRecord(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if(!dbg || !dbg->GetTraceRecordType || !dbg->GetTraceRecordByteType || !dbg->GetTraceRecordHitCount)
        throw std::runtime_error("Trace record API unavailable");

    const duint pageBase = address & ~(static_cast<duint>(PAGE_SIZE) - 1);
    const auto recordType = dbg->GetTraceRecordType(pageBase);
    const auto byteType = dbg->GetTraceRecordByteType(address);
    const unsigned int hitCount = dbg->GetTraceRecordHitCount(address);

    LogInfoF("getTraceRecord address=%s hits=%u type=%d byteType=%d", formatAddress(address).c_str(), hitCount, static_cast<int>(recordType), static_cast<int>(byteType));

    return json::object({
        {"address", formatAddress(address)},
        {"pageBase", formatAddress(pageBase)},
        {"hitCount", hitCount},
        {"recordType", traceRecordTypeToString(recordType)},
        {"byteType", traceRecordByteTypeToString(byteType)}
    });
}

json McpServer::handleMemBpSize(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if(!dbg || !dbg->MemBpSize)
        throw std::runtime_error("MemBpSize unavailable");

    duint bpSize = dbg->MemBpSize(address);

    LogInfoF("memBpSize address=%s -> %llu", formatAddress(address).c_str(), static_cast<unsigned long long>(bpSize));

    return json::object({
        {"address", formatAddress(address)},
        {"size", bpSize}
    });
}

json McpServer::handleListBreakpoints(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    const bool includeDetails = params.value("includeDetails", true);

    std::vector<BPXTYPE> requestedTypes;
    requestedTypes.reserve(5);

    auto addTypeUnique = [&](BPXTYPE type) {
        if(type == bp_none)
            return;
        if(std::find(requestedTypes.begin(), requestedTypes.end(), type) == requestedTypes.end())
            requestedTypes.push_back(type);
    };

    bool includeAll = false;
    if(params.contains("type"))
    {
        const json& typeValue = params.at("type");
        auto processString = [&](const std::string& text) {
            if(text.empty())
                return;
            BPXTYPE parsed{};
            if(toLowerCopy(text) == "all")
            {
                includeAll = true;
                return;
            }
            if(!parseBreakpointTypeString(text, parsed) || parsed == bp_none)
                throw std::runtime_error("Unknown breakpoint type filter: " + text);
            addTypeUnique(parsed);
        };

        if(typeValue.is_string())
        {
            processString(typeValue.get<std::string>());
        }
        else if(typeValue.is_array())
        {
            for(const auto& item : typeValue)
            {
                if(!item.is_string())
                    throw std::runtime_error("Breakpoint type array must contain strings");
                processString(item.get<std::string>());
            }
        }
        else
        {
            throw std::runtime_error("Breakpoint type filter must be a string or array of strings");
        }
    }

    if(includeAll || requestedTypes.empty())
    {
        requestedTypes = {bp_normal, bp_hardware, bp_memory, bp_dll, bp_exception};
    }

    json breakpoints = json::array();
    json counts = json::object();
    json requested = json::array();
    int total = 0;

    auto appendDetails = [&](json& entry, const BRIDGEBP& bp) {
        if(!includeDetails)
            return;

        if(bp.breakCondition[0])
            entry["breakCondition"] = std::string(bp.breakCondition);
        if(bp.logText[0])
            entry["logText"] = std::string(bp.logText);
        if(bp.logCondition[0])
            entry["logCondition"] = std::string(bp.logCondition);
        if(bp.commandText[0])
            entry["commandText"] = std::string(bp.commandText);
        if(bp.commandCondition[0])
            entry["commandCondition"] = std::string(bp.commandCondition);
    };

    for(BPXTYPE type : requestedTypes)
    {
        requested.push_back(breakpointTypeToString(type));

        BPMAP list{};
        list.count = 0;
        list.bp = nullptr;

        DbgGetBpList(type, &list);

        auto bridgeBpDeleter = [](BRIDGEBP* ptr) {
            if(ptr)
                BridgeFree(ptr);
        };
        std::unique_ptr<BRIDGEBP, decltype(bridgeBpDeleter)> guard(list.bp, bridgeBpDeleter);

        const int count = list.count;
        counts[breakpointTypeToString(type)] = count;
        total += count;

        if(!list.bp || count <= 0)
            continue;

        for(int i = 0; i < count; ++i)
        {
            const BRIDGEBP& bp = list.bp[i];

            json entry = {
                {"type", breakpointTypeToString(bp.type)},
                {"address", formatAddress(bp.addr)},
                {"enabled", bp.enabled},
                {"disabled", !bp.enabled},
                {"active", bp.active},
                {"singleShot", bp.singleshoot},
                {"hitCount", bp.hitCount},
                {"slot", bp.slot},
                {"fastResume", bp.fastResume},
                {"silent", bp.silent}
            };

            if(bp.name[0])
                entry["name"] = std::string(bp.name);
            if(bp.mod[0])
                entry["module"] = std::string(bp.mod);

            switch(bp.type)
            {
            case bp_hardware:
                entry["hardware"] = json::object({
                    {"trigger", hardwareTypeToString(bp.typeEx)},
                    {"size", hardwareSizeToString(bp.hwSize)}
                });
                break;
            case bp_memory:
                entry["memory"] = json::object({
                    {"trigger", memoryTypeToString(bp.typeEx)}
                });
                break;
            case bp_dll:
                entry["dll"] = json::object({
                    {"event", dllTypeToString(bp.typeEx)}
                });
                break;
            case bp_exception:
                entry["exception"] = json::object({
                    {"event", exceptionTypeToString(bp.typeEx)}
                });
                break;
            default:
                break;
            }

            appendDetails(entry, bp);
            breakpoints.push_back(std::move(entry));
        }
    }

    LogInfoF("listBreakpoints total=%d", total);

    return json::object({
        {"breakpoints", breakpoints},
        {"counts", counts},
        {"types", requested},
        {"total", total},
        {"includeDetails", includeDetails}
    });
}

json McpServer::handleDeleteBreakpoint(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    const bool ignoreMissing = params.value("ignoreMissing", false);

    BPXTYPE requestedType = bp_none;
    bool typeProvided = params.contains("type");
    if(typeProvided)
    {
        if(!params.at("type").is_string())
            throw std::runtime_error("Breakpoint type must be a string");
        const std::string typeText = params.at("type").get<std::string>();
        if(!parseBreakpointTypeString(typeText, requestedType) || (requestedType != bp_normal && requestedType != bp_hardware))
            throw std::runtime_error("deleteBreakpoint currently supports 'software' or 'hardware' types");
    }

    BPXTYPE existingType = DbgGetBpxTypeAt(address);
    bool existed = existingType != bp_none;

    if(!typeProvided)
    {
        requestedType = existed ? existingType : bp_normal;
    }

    std::string requestedTypeText = breakpointTypeToString(requestedType);

    if(requestedType != bp_normal && requestedType != bp_hardware)
        throw std::runtime_error("deleteBreakpoint currently supports software or hardware breakpoints only");

    bool removed = false;
    if(requestedType == bp_hardware)
    {
        if(existingType == bp_hardware)
            removed = Script::Debug::DeleteHardwareBreakpoint(address);
        else if(existed && existingType != bp_none)
        {
            if(ignoreMissing)
                removed = false;
            else
                throw std::runtime_error("Breakpoint at address is not hardware");
        }
    }
    else // software
    {
        if(existingType != bp_none && existingType != bp_normal && !ignoreMissing)
            throw std::runtime_error("Breakpoint at address belongs to a different type");

        removed = Script::Debug::DeleteBreakpoint(address);
        if(!removed)
        {
            std::ostringstream cmd;
            cmd << "bc " << std::hex << std::uppercase << address;
            removed = DbgCmdExecDirect(cmd.str().c_str());
        }
        if(removed)
            removed = (DbgGetBpxTypeAt(address) == bp_none);
    }

    if(!removed && !ignoreMissing)
    {
        if(!existed)
            throw std::runtime_error("No breakpoint exists at the specified address");
        throw std::runtime_error("Failed to delete breakpoint");
    }

    LogInfoF("deleteBreakpoint %s -> removed=%s", formatAddress(address).c_str(), removed ? "true" : "false");

    return json::object({
        {"address", formatAddress(address)},
        {"requestedType", requestedTypeText},
        {"removed", removed},
        {"existed", existed},
        {"previousType", breakpointTypeToString(existingType)}
    });
}

json McpServer::handleDisableBreakpoint(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    const bool ignoreMissing = params.value("ignoreMissing", false);

    BPXTYPE existingType = DbgGetBpxTypeAt(address);
    if(existingType == bp_none)
    {
        if(ignoreMissing)
        {
            return json::object({
                {"address", formatAddress(address)},
                {"disabled", false},
                {"existed", false}
            });
        }
        throw std::runtime_error("No breakpoint exists at the specified address");
    }

    if(existingType != bp_normal)
        throw std::runtime_error("disableBreakpoint currently supports software breakpoints only");

    const bool alreadyDisabled = DbgIsBpDisabled(address);
    if(alreadyDisabled)
    {
        return json::object({
            {"address", formatAddress(address)},
            {"disabled", true},
            {"alreadyDisabled", true}
        });
    }

    bool success = Script::Debug::DisableBreakpoint(address);
    if(!success)
    {
        std::ostringstream cmd;
        cmd << "bd " << std::hex << std::uppercase << address;
        success = DbgCmdExecDirect(cmd.str().c_str());
    }

    const bool nowDisabled = DbgIsBpDisabled(address);
    if(!success && !nowDisabled)
    {
        if(ignoreMissing)
        {
            return json::object({
                {"address", formatAddress(address)},
                {"disabled", false},
                {"existed", true}
            });
        }
        throw std::runtime_error("Failed to disable breakpoint");
    }

    LogInfoF("disableBreakpoint %s", formatAddress(address).c_str());

    return json::object({
        {"address", formatAddress(address)},
        {"disabled", nowDisabled},
        {"alreadyDisabled", alreadyDisabled}
    });
}

json McpServer::handleEnableBreakpoint(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    const bool createIfMissing = params.value("createIfMissing", true);

    BPXTYPE existingType = DbgGetBpxTypeAt(address);
    bool createdNew = false;

    if(existingType == bp_none)
    {
        if(!createIfMissing)
            throw std::runtime_error("No breakpoint exists at the specified address");

        if(!Script::Debug::SetBreakpoint(address))
        {
            std::ostringstream cmd;
            cmd << "bp " << std::hex << std::uppercase << address;
            if(!DbgCmdExecDirect(cmd.str().c_str()))
                throw std::runtime_error("Failed to create breakpoint");
        }
        existingType = bp_normal;
        createdNew = true;
    }

    if(existingType != bp_normal)
        throw std::runtime_error("enableBreakpoint currently supports software breakpoints only");

    const bool alreadyDisabled = DbgIsBpDisabled(address);
    if(!alreadyDisabled)
    {
        return json::object({
            {"address", formatAddress(address)},
            {"enabled", true},
            {"alreadyEnabled", !createdNew},
            {"created", createdNew}
        });
    }

    std::ostringstream cmd;
    cmd << "be " << std::hex << std::uppercase << address;
    bool success = DbgCmdExecDirect(cmd.str().c_str());

    const bool nowDisabled = DbgIsBpDisabled(address);
    if(!success && nowDisabled)
        throw std::runtime_error("Failed to enable breakpoint");

    LogInfoF("enableBreakpoint %s", formatAddress(address).c_str());

    return json::object({
        {"address", formatAddress(address)},
        {"enabled", !nowDisabled},
        {"created", createdNew},
        {"alreadyEnabled", false}
    });
}

json McpServer::handleSetBreakpoint(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address"))
        throw std::runtime_error("Missing address parameter");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    std::ostringstream command;
    command << "bp " << std::hex << std::uppercase << address;
    if(!DbgCmdExecDirect(command.str().c_str()))
        throw std::runtime_error("Failed to set breakpoint");

    LogInfoF("setBreakpoint at 0x%llX", static_cast<unsigned long long>(address));
    return json::object({{"status", "ok"}});
}

json McpServer::handleGetRegisters(const json&)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    REGDUMP regDump{};
    if(!DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        throw std::runtime_error("Failed to retrieve registers");

    const auto& regs = regDump.regcontext;

    constexpr bool kIs64Bit = sizeof(duint) == 8;
    const int pointerBits = static_cast<int>(sizeof(duint) * 8);

    auto formatRegisterValue = [&](duint value, int bits) -> std::pair<std::string, unsigned long long>
    {
        if(bits <= 0)
            bits = pointerBits;

        unsigned long long maskedValue = 0;
        if(bits >= 64)
        {
            maskedValue = static_cast<unsigned long long>(value);
        }
        else
        {
            const unsigned long long mask = (1ull << bits) - 1ull;
            maskedValue = static_cast<unsigned long long>(value) & mask;
        }

        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << std::setw((bits + 3) / 4) << std::setfill('0') << maskedValue;
        return {ss.str(), maskedValue};
    };

    auto appendRegister = [&](json& table, json& list, const char* name, duint value, int bits, const char* aliasOf)
    {
        const auto formatted = formatRegisterValue(value, bits);
        table[name] = formatted.first;

        json entry = {
            {"name", name},
            {"hex", formatted.first},
            {"dec", formatted.second},
            {"bits", bits}
        };

        if(aliasOf && *aliasOf)
            entry["aliasOf"] = aliasOf;

        list.push_back(std::move(entry));
    };

    json general = json::object();
    json generalList = json::array();

#ifdef _WIN64
    const std::array<std::pair<const char*, duint>, 9> primaryRegisters = {{
        {"rax", regs.cax},
        {"rbx", regs.cbx},
        {"rcx", regs.ccx},
        {"rdx", regs.cdx},
        {"rsi", regs.csi},
        {"rdi", regs.cdi},
        {"rbp", regs.cbp},
        {"rsp", regs.csp},
        {"rip", regs.cip}
    }};

    for(const auto& reg : primaryRegisters)
        appendRegister(general, generalList, reg.first, reg.second, 64, nullptr);

    const std::array<std::pair<const char*, duint>, 8> extendedRegisters = {{
        {"r8", regs.r8},
        {"r9", regs.r9},
        {"r10", regs.r10},
        {"r11", regs.r11},
        {"r12", regs.r12},
        {"r13", regs.r13},
        {"r14", regs.r14},
        {"r15", regs.r15}
    }};

    for(const auto& reg : extendedRegisters)
        appendRegister(general, generalList, reg.first, reg.second, 64, nullptr);

    struct LegacyRegister
    {
        const char* name;
        duint value;
        const char* aliasOf;
    };

    const std::array<LegacyRegister, 9> legacyRegisters = {{
        {"eax", regs.cax, "rax"},
        {"ebx", regs.cbx, "rbx"},
        {"ecx", regs.ccx, "rcx"},
        {"edx", regs.cdx, "rdx"},
        {"esi", regs.csi, "rsi"},
        {"edi", regs.cdi, "rdi"},
        {"ebp", regs.cbp, "rbp"},
        {"esp", regs.csp, "rsp"},
        {"eip", regs.cip, "rip"}
    }};

    for(const auto& reg : legacyRegisters)
        appendRegister(general, generalList, reg.name, reg.value, 32, reg.aliasOf);
#else
    const std::array<std::pair<const char*, duint>, 9> primaryRegisters = {{
        {"eax", regs.cax},
        {"ebx", regs.cbx},
        {"ecx", regs.ccx},
        {"edx", regs.cdx},
        {"esi", regs.csi},
        {"edi", regs.cdi},
        {"ebp", regs.cbp},
        {"esp", regs.csp},
        {"eip", regs.cip}
    }};

    for(const auto& reg : primaryRegisters)
        appendRegister(general, generalList, reg.first, reg.second, 32, nullptr);
#endif

    json debugRegs = json::object();
    json debugList = json::array();
    const std::array<std::pair<const char*, duint>, 6> debugEntries = {{
        {"dr0", regs.dr0},
        {"dr1", regs.dr1},
        {"dr2", regs.dr2},
        {"dr3", regs.dr3},
        {"dr6", regs.dr6},
        {"dr7", regs.dr7}
    }};

    for(const auto& reg : debugEntries)
        appendRegister(debugRegs, debugList, reg.first, reg.second, pointerBits, nullptr);

    json segments = json::object();
    json segmentList = json::array();
    auto appendSegment = [&](const char* name, unsigned short value)
    {
        segments[name] = value;
        segmentList.push_back(json::object({
            {"name", name},
            {"value", value},
            {"bits", 16}
        }));
    };

    appendSegment("cs", regs.cs);
    appendSegment("ds", regs.ds);
    appendSegment("es", regs.es);
    appendSegment("fs", regs.fs);
    appendSegment("gs", regs.gs);
    appendSegment("ss", regs.ss);

    json flags = {
        {"cf", regDump.flags.c},
        {"pf", regDump.flags.p},
        {"af", regDump.flags.a},
        {"zf", regDump.flags.z},
        {"sf", regDump.flags.s},
        {"tf", regDump.flags.t},
        {"if", regDump.flags.i},
        {"df", regDump.flags.d},
        {"of", regDump.flags.o}
    };

    json flagList = json::array({
        json::object({{"name", "CF"}, {"value", regDump.flags.c}}),
        json::object({{"name", "PF"}, {"value", regDump.flags.p}}),
        json::object({{"name", "AF"}, {"value", regDump.flags.a}}),
        json::object({{"name", "ZF"}, {"value", regDump.flags.z}}),
        json::object({{"name", "SF"}, {"value", regDump.flags.s}}),
        json::object({{"name", "TF"}, {"value", regDump.flags.t}}),
        json::object({{"name", "IF"}, {"value", regDump.flags.i}}),
        json::object({{"name", "DF"}, {"value", regDump.flags.d}}),
        json::object({{"name", "OF"}, {"value", regDump.flags.o}})
    });

    const auto stackFormatted = formatRegisterValue(regs.csp, pointerBits);
    json stackPointer = {
        {"name", kIs64Bit ? "rsp" : "esp"},
        {"hex", stackFormatted.first},
        {"dec", stackFormatted.second},
        {"bits", pointerBits}
    };
#ifdef _WIN64
    stackPointer["aliasOf"] = "esp";
#endif

    const auto ipFormatted = formatRegisterValue(regs.cip, pointerBits);
    json instructionPointer = {
        {"name", kIs64Bit ? "rip" : "eip"},
        {"hex", ipFormatted.first},
        {"dec", ipFormatted.second},
        {"bits", pointerBits}
    };
#ifdef _WIN64
    instructionPointer["aliasOf"] = "eip";
#endif

    const auto flagsFormatted = formatRegisterValue(regs.eflags, pointerBits);
    const char* flagsFieldName = kIs64Bit ? "rflags" : "eflags";

    LogInfo("getRegisters returned register snapshot");

    json architecture = json::object({
        {"bits", pointerBits},
        {"pointerBytes", static_cast<int>(sizeof(duint))},
        {"flavor", MCP_TARGET_ARCH_STRING},
        {"is64Bit", kIs64Bit}
    });

    json result = json::object({
        {"general", general},
        {"flags", flags},
        {flagsFieldName, flagsFormatted.first},
        {"registers", generalList},
        {"debugRegisters", debugList},
        {"debug", debugRegs},
        {"segments", segments},
        {"segmentList", segmentList},
        {"flagList", flagList},
        {"stackPointer", stackPointer},
        {"instructionPointer", instructionPointer},
        {"architecture", architecture}
    });

#ifdef _WIN64
    result["eflags"] = flagsFormatted.first;
#endif

    return result;
}

json McpServer::handleRunTrace(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    const std::string mode = params.value("mode", std::string("into"));
    unsigned int count = params.value("count", 1u);
    if(count == 0)
        count = 1;

    std::string command;
    if(mode == "over")
        command = "traceover";
    else if(mode == "into")
        command = "traceinto";
    else
        throw std::runtime_error("Unsupported trace mode (use 'into' or 'over')");

    if(count > 1)
    {
        command.push_back(' ');
        command += std::to_string(count);
    }

    if(!DbgCmdExecDirect(command.c_str()))
        throw std::runtime_error("Trace command failed");

    LogInfoF("runTrace mode=%s count=%u", mode.c_str(), count);
    return json::object({{"status", "ok"}});
}

json McpServer::handleWriteMemory(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("address") || !params.contains("data"))
        throw std::runtime_error("Missing parameters (address, data required)");

    duint address = 0;
    if(!parseAddress(params.at("address"), address))
        throw std::runtime_error("Invalid address parameter");

    const std::string dataText = params.at("data").get<std::string>();
    if(dataText.empty())
        throw std::runtime_error("Data payload must not be empty");

    const std::string formatText = params.value("format", std::string("hex"));
    const bool force = params.value("force", false);

    const std::vector<unsigned char> bytes = parseFormattedByteString(dataText, formatText);
    if(bytes.empty())
        throw std::runtime_error("No bytes to write");

    unsigned long originalProtect = Script::Memory::GetProtect(address, false, true);
    std::string originalRights = rightsStringFromProtect(originalProtect);

    if(originalRights.empty())
    {
        const DBGFUNCTIONS* dbg = DbgFunctions();
        if(dbg && dbg->GetPageRights)
        {
            char rightsBuffer[RIGHTS_STRING_SIZE] = {};
            if(dbg->GetPageRights(address, rightsBuffer))
                originalRights = rightsBuffer;
        }
    }

    unsigned long elevatedProtect = originalProtect;
    std::string elevatedRights;
    bool changedProtect = false;
    bool restoreSucceeded = true;

    const duint writeSize = static_cast<duint>(bytes.size());

    if(force)
    {
        std::string requestedRights = originalRights;
        if(requestedRights.empty())
            requestedRights = "RW";

        if(requestedRights.find('R') == std::string::npos)
            requestedRights.push_back('R');
        if(requestedRights.find('W') == std::string::npos)
            requestedRights.push_back('W');

        elevatedProtect = protectionFromRightsString(requestedRights);
        if(elevatedProtect == 0)
            elevatedProtect = PAGE_READWRITE;

        if(elevatedProtect != originalProtect)
        {
            if(!Script::Memory::SetProtect(address, elevatedProtect, writeSize))
                throw std::runtime_error("Failed to adjust memory protection prior to force write");
            changedProtect = true;
            elevatedRights = rightsStringFromProtect(elevatedProtect);
        }
    }

    if(!DbgMemWrite(address, bytes.data(), writeSize))
    {
        if(changedProtect)
        {
            if(!Script::Memory::SetProtect(address, originalProtect, writeSize))
                LogWarningF("Failed to restore memory protection after write failure at %s", formatAddress(address).c_str());
        }
        throw std::runtime_error("DbgMemWrite failed");
    }

    if(changedProtect)
    {
        if(!Script::Memory::SetProtect(address, originalProtect, writeSize))
        {
            restoreSucceeded = false;
            LogWarningF("Failed to restore memory protection at %s", formatAddress(address).c_str());
        }
    }

    json result = {
        {"address", formatAddress(address)},
        {"bytesWritten", bytes.size()},
        {"format", toLowerCopy(formatText)},
        {"force", force},
        {"pageProtectBefore", originalRights},
        {"pageProtectAfter", changedProtect ? elevatedRights : originalRights},
        {"protectionRestored", !changedProtect || restoreSucceeded}
    };

    if(changedProtect)
    {
        result["temporaryProtect"] = elevatedRights;
        result["temporaryProtectValue"] = elevatedProtect;
        result["originalProtectValue"] = originalProtect;
    }

    return result;
}

json McpServer::handlePatternScan(const json& params)
{
    if(!DbgIsDebugging())
        throw std::runtime_error("No debuggee attached");

    if(!params.contains("pattern"))
        throw std::runtime_error("Missing pattern parameter");

    const PatternParseResult parsedPattern = parsePatternExpression(params.at("pattern").get<std::string>());
    const size_t patternLength = parsedPattern.pattern.size();
    if(patternLength == 0)
        throw std::runtime_error("Pattern length must be greater than zero");

    duint start = 0;
    bool hasStart = false;
    if(params.contains("start"))
    {
        if(parseAddress(params.at("start"), start)) hasStart = true;
    }
    else if(params.contains("address"))
    {
        if(parseAddress(params.at("address"), start)) hasStart = true;
    }

    duint endInclusive = 0;
    duint endExclusive = 0;
    bool hasEnd = false;

    if(params.contains("end"))
    {
        if(parseAddress(params.at("end"), endInclusive))
        {
            endExclusive = endInclusive + 1;
            hasEnd = true;
        }
    }
    else if(params.contains("size"))
    {
        const auto sizeValue = params.at("size");
        unsigned long long rawSize = 0;
        if(sizeValue.is_number_unsigned())
            rawSize = sizeValue.get<unsigned long long>();
        
        if(rawSize > 0)
        {
            endExclusive = start + static_cast<duint>(rawSize);
            endInclusive = endExclusive - 1;
            hasEnd = true;
        }
    }

    if(!hasStart || !hasEnd)
    {
        // Default to main module if no range specified
        BridgeList<Script::Module::ModuleInfo> moduleList;
        if(Script::Module::GetList(&moduleList) && moduleList.Count() > 0)
        {
            const auto* mainMod = &moduleList.Data()[0];
            if(!hasStart) start = mainMod->base;
            if(!hasEnd)
            {
                endExclusive = mainMod->base + mainMod->size;
                endInclusive = endExclusive - 1;
            }
        }
        else if(!hasStart && !hasEnd)
        {
             throw std::runtime_error("Missing start/end/size parameters and cannot determine main module default range");
        }
    }

    if(endExclusive <= start)
        throw std::runtime_error("Scan range must be positive");

    size_t maxResults = std::numeric_limits<size_t>::max();
    if(params.contains("maxResults"))
    {
        const auto maxValue = params.at("maxResults");
        if(!maxValue.is_number_unsigned())
            throw std::runtime_error("maxResults must be an unsigned integer");
        maxResults = static_cast<size_t>(maxValue.get<unsigned long long>());
        if(maxResults == 0)
            maxResults = std::numeric_limits<size_t>::max();
    }

    const size_t chunkSize = 0x2000;
    std::vector<unsigned char> overlap;
    overlap.reserve(patternLength > 0 ? patternLength - 1 : 0);
    std::vector<duint> matches;
    matches.reserve(16);

    duint cursor = start;
    while(cursor < endExclusive)
    {
        const duint remaining = endExclusive - cursor;
        const size_t readSize = static_cast<size_t>(std::min<duint>(static_cast<duint>(chunkSize), remaining));
        std::vector<unsigned char> chunk(readSize);

        if(!DbgMemRead(cursor, chunk.data(), static_cast<duint>(readSize)))
        {
            cursor += static_cast<duint>(readSize);
            overlap.clear();
            continue;
        }

        std::vector<unsigned char> searchBuffer;
        searchBuffer.reserve(overlap.size() + chunk.size());
        searchBuffer.insert(searchBuffer.end(), overlap.begin(), overlap.end());
        searchBuffer.insert(searchBuffer.end(), chunk.begin(), chunk.end());

        const duint bufferBase = cursor - static_cast<duint>(overlap.size());

        if(searchBuffer.size() >= patternLength)
        {
            const size_t limit = searchBuffer.size() - patternLength;
            for(size_t offset = 0; offset <= limit; ++offset)
            {
                bool matched = true;
                for(size_t i = 0; i < patternLength; ++i)
                {
                    const int patternByte = parsedPattern.pattern[i];
                    if(patternByte >= 0 && static_cast<unsigned char>(patternByte) != searchBuffer[offset + i])
                    {
                        matched = false;
                        break;
                    }
                }

                if(matched)
                {
                    const duint matchAddress = bufferBase + static_cast<duint>(offset);
                    if(matchAddress >= start && matchAddress + static_cast<duint>(patternLength) <= endExclusive)
                    {
                        matches.push_back(matchAddress);
                        if(matches.size() >= maxResults)
                            break;
                    }
                }
            }
        }

        if(matches.size() >= maxResults)
            break;

        if(patternLength > 1)
        {
            const size_t keep = std::min(patternLength - 1, searchBuffer.size());
            overlap.assign(searchBuffer.begin() + (searchBuffer.size() - keep), searchBuffer.end());
        }
        else
        {
            overlap.clear();
        }

        cursor += static_cast<duint>(readSize);
    }

    json matchArray = json::array();
    for(duint matchAddress : matches)
        matchArray.push_back(formatAddress(matchAddress));

    return json::object({
        {"pattern", parsedPattern.normalized},
        {"patternLength", patternLength},
        {"start", formatAddress(start)},
        {"end", formatAddress(endInclusive)},
        {"scannedBytes", static_cast<unsigned long long>(endExclusive - start)},
        {"matchCount", matches.size()},
        {"matches", matchArray},
        {"maxResults", matches.size() >= maxResults ? maxResults : matches.size()}
    });
}

json McpServer::handleInitialize(const json& params)
{
    json client = params.contains("client") ? params.at("client") : json::object();
    std::string clientName = client.value("name", std::string("unknown"));
    LogInfoF("Client '%s' requested initialize", clientName.c_str());

    constexpr const char* kDefaultProtocolVersion = "1.0";
    const std::string requestedProtocolVersion = params.value("protocolVersion", std::string(kDefaultProtocolVersion));
    const std::string negotiatedProtocolVersion = requestedProtocolVersion.empty() ? std::string(kDefaultProtocolVersion) : requestedProtocolVersion;

    if(negotiatedProtocolVersion != kDefaultProtocolVersion)
        LogInfoF("Negotiated protocol version '%s' (default '%s')", negotiatedProtocolVersion.c_str(), kDefaultProtocolVersion);

    json capabilities = json::object({
        {"logging", json::object({
            {"setLevel", true}
        })},
        {"prompts", json::object({
            {"list", true},
            {"get", false}
        })},
        {"tools", json::object({
            {"list", true},
            {"call", true}
        })},
        {"resources", json::object({
            {"list", true},
            {"get", true}
        })}
    });

    return json::object({
        {"protocolVersion", negotiatedProtocolVersion},
        {"capabilities", capabilities},
        {"serverInfo", json::object({
            {"name", "MCPluginForX96Dbg"},
            {"version", "0.1.0"}
        })}
    });
}

json McpServer::handleLoggingSetLevel(const json& params)
{
    const std::string level = params.value("level", std::string("info"));
    LogInfoF("Client requested logging level change: %s (no-op)", level.c_str());
    return json::object({{"accepted", true}});
}

json McpServer::handleNotificationsInitialized(const json& params)
{
    json client = params.contains("client") ? params.at("client") : json::object();
    const std::string name = client.value("name", std::string("unknown"));
    LogInfoF("notifications/initialized acknowledged for client '%s'", name.c_str());
    return json::object();
}

json McpServer::handleToolsList()
{
    json tools = json::array();

    tools.push_back({
        {"name", "readMemory"},
        {"description", "Read a block of memory from the target process."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address to read (0x-prefixed hex or decimal)."}
                })},
                {"size", json::object({
                    {"type", "integer"},
                    {"minimum", 1},
                    {"maximum", static_cast<int>(kMaxMemoryRead)},
                    {"description", "Number of bytes to read (1-4096)."}
                })}
            })},
            {"required", json::array({"address", "size"})}
        })}
    });

    tools.push_back({
        {"name", "listModules"},
        {"description", "Enumerate all loaded modules."},
        {"inputSchema", json::object({{"type", "object"}})}
    });

    tools.push_back({
        {"name", "getExports"},
        {"description", "Enumerate exports for a module."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"module", json::object({
                    {"type", "string"},
                    {"description", "Module name or address."}
                })}
            })},
            {"required", json::array({"module"})}
        })}
    });

    tools.push_back({
        {"name", "getImports"},
        {"description", "Enumerate imports for a module."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"module", json::object({
                    {"type", "string"},
                    {"description", "Module name or address."}
                })}
            })},
            {"required", json::array({"module"})}
        })}
    });

    tools.push_back({
        {"name", "getDisassembly"},
        {"description", "Disassemble instructions at an address."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address to disassemble (0x-prefixed hex or decimal)."}
                })},
                {"count", json::object({
                    {"type", "integer"},
                    {"minimum", 1},
                    {"maximum", 64},
                    {"description", "Number of instructions to return."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "getThreads"},
        {"description", "Enumerate debugger threads and their state."},
        {"inputSchema", json::object({{"type", "object"}})}
    });

    tools.push_back({
        {"name", "getPageRights"},
        {"description", "Query page protection flags at an address."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address to query (0x-prefixed hex or decimal)."}
                })},
                {"string", json::object({
                    {"type", "boolean"},
                    {"description", "When true, returns a human-readable rights string."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "setPageRights"},
        {"description", "Change page protection flags for a memory range."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Start address (0x-prefixed hex or decimal)."}
                })},
                {"protect", json::object({
                    {"type", "string"},
                    {"description", "Protection string such as 'ERW' (Execute/Read/Write)."}
                })},
                {"size", json::object({
                    {"type", "integer"},
                    {"minimum", 1},
                    {"description", "Number of bytes the new protection applies to."}
                })}
            })},
            {"required", json::array({"address", "protect", "size"})}
        })}
    });

    tools.push_back({
        {"name", "memIsCodePage"},
        {"description", "Check if a page contains executable code."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address to inspect."}
                })},
                {"refresh", json::object({
                    {"type", "boolean"},
                    {"description", "When true, forces a refresh of the cached info."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "getTraceRecord"},
        {"description", "Fetch trace record metadata for a page."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address used to calculate the trace record page."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "memBpSize"},
        {"description", "Retrieve the size of a memory breakpoint at an address."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address where the breakpoint resides."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "listBreakpoints"},
        {"description", "Enumerate breakpoints with state and metadata."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"type", json::object({
                    {"type", "string"},
                    {"description", "Breakpoint type filter (software|hardware|memory|dll|exception|all)."}
                })},
                {"includeDetails", json::object({
                    {"type", "boolean"},
                    {"description", "When false, omits conditional/script fields for brevity."}
                })}
            })}
        })}
    });

    tools.push_back({
        {"name", "deleteBreakpoint"},
        {"description", "Remove a software or hardware breakpoint."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address of the breakpoint."}
                })},
                {"type", json::object({
                    {"type", "string"},
                    {"description", "Breakpoint category (software|hardware)."}
                })},
                {"ignoreMissing", json::object({
                    {"type", "boolean"},
                    {"description", "When true, succeeds even if the breakpoint didn't exist."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "disableBreakpoint"},
        {"description", "Disable a software breakpoint without deleting it."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address of the breakpoint."}
                })},
                {"ignoreMissing", json::object({
                    {"type", "boolean"},
                    {"description", "When true, returns success if the breakpoint was missing."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "enableBreakpoint"},
        {"description", "Re-enable a previously disabled breakpoint."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address of the breakpoint."}
                })},
                {"createIfMissing", json::object({
                    {"type", "boolean"},
                    {"description", "When true, creates a new breakpoint if none existed."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "setBreakpoint"},
        {"description", "Set a software breakpoint at the specified address."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Address where the breakpoint should be placed."}
                })}
            })},
            {"required", json::array({"address"})}
        })}
    });

    tools.push_back({
        {"name", "getRegisters"},
        {"description", "Get the current register state."},
        {"inputSchema", json::object({{"type", "object"}})}
    });

    tools.push_back({
        {"name", "runTrace"},
        {"description", "Run traceinto/traceover commands."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"mode", json::object({
                    {"type", "string"},
                    {"enum", json::array({"into", "over"})},
                    {"description", "Trace mode (into or over)."}
                })},
                {"count", json::object({
                    {"type", "integer"},
                    {"minimum", 1},
                    {"description", "Number of steps to trace."}
                })}
            })}
        })}
    });

    tools.push_back({
        {"name", "writeMemory"},
        {"description", "Write data to the target process memory with optional protection override."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Base address to write (0x-prefixed hex or decimal)."}
                })},
                {"data", json::object({
                    {"type", "string"},
                    {"description", "Bytes to write (hex like '90 90' or ASCII)."}
                })},
                {"format", json::object({
                    {"type", "string"},
                    {"enum", json::array({"hex", "ascii"})},
                    {"description", "Encoding of the data string (default hex)."}
                })},
                {"force", json::object({
                    {"type", "boolean"},
                    {"description", "Temporarily elevate page protections to allow the write."}
                })}
            })},
            {"required", json::array({"address", "data"})}
        })}
    });

    tools.push_back({
        {"name", "patternScan"},
        {"description", "Scan memory for a pattern with wildcard support."},
        {"inputSchema", json::object({
            {"type", "object"},
            {"properties", json::object({
                {"pattern", json::object({
                    {"type", "string"},
                    {"description", "Pattern like '48 8B ?? ?? 48 89' (?? wildcards)."}
                })},
                {"start", json::object({
                    {"type", "string"},
                    {"description", "Start address (0x-prefixed hex or decimal)."}
                })},
                {"address", json::object({
                    {"type", "string"},
                    {"description", "Alias for start address."}
                })},
                {"end", json::object({
                    {"type", "string"},
                    {"description", "Inclusive end address."}
                })},
                {"size", json::object({
                    {"type", "integer"},
                    {"minimum", 1},
                    {"description", "Size of range to scan (alternative to end)."}
                })},
                {"maxResults", json::object({
                    {"type", "integer"},
                    {"minimum", 1},
                    {"description", "Maximum number of matches to return."}
                })}
            })},
            {"required", json::array({"pattern"})}
        })}
    });

    tools.push_back({
        {"name", "ping"},
        {"description", "Health check."},
        {"inputSchema", json::object({{"type", "object"}})}
    });

    return json::object({
        {"tools", tools}
    });
}

json McpServer::handlePromptsList()
{
    return json::object({
        {"prompts", json::array()}
    });
}

json McpServer::handleResourcesList(const json& params)
{
    (void)params;

    json resources = json::array();
    for(const auto& resource : kStaticResources)
    {
        json metadata = json::object();
        if(resource.category && *resource.category)
            metadata["category"] = resource.category;
        if(resource.body)
            metadata["length"] = static_cast<int>(std::strlen(resource.body));

        resources.push_back(json::object({
            {"uri", resource.uri},
            {"name", resource.name},
            {"description", resource.description},
            {"mimeType", resource.mimeType},
            {"metadata", metadata}
        }));
    }

    return json::object({{"resources", resources}});
}

json McpServer::handleResourcesGet(const json& params)
{
    if(!params.contains("uri") || !params.at("uri").is_string())
        throw std::runtime_error("resources/get missing uri");

    const std::string uri = params.at("uri").get<std::string>();
    const ResourceDefinition* resource = findResourceDefinition(uri);
    if(!resource)
    {
        LogWarningF("resources/get unknown uri: %s", uri.c_str());
        throw std::runtime_error("Resource not found");
    }

    json content = json::array();
    if(resource->body && *resource->body)
    {
        content.push_back(json::object({
            {"type", "text"},
            {"text", resource->body}
        }));
    }

    if(content.empty())
    {
        content.push_back(json::object({
            {"type", "text"},
            {"text", std::string("No data available for ") + resource->name}
        }));
    }

    return json::object({
        {"uri", resource->uri},
        {"name", resource->name},
        {"mimeType", resource->mimeType},
        {"content", content}
    });
}

json McpServer::handleToolsCall(const json& params)
{
    if(!params.contains("name") || !params.at("name").is_string())
        throw std::runtime_error("tools/call missing name");

    const std::string toolName = params.at("name").get<std::string>();
    const json arguments = params.contains("arguments") ? params.at("arguments") : json::object();

    json payload;
    std::string summary;
    std::vector<std::string> extraText;

    if(toolName == "readMemory")
    {
        payload = handleReadMemory(arguments);
        summary = "Read " + std::to_string(payload.value("size", 0)) + " bytes from " + payload.value("address", std::string(""));

        const std::string dataHex = payload.value("data", std::string());
        const std::string valueHex = payload.value("valueHex", std::string());
        if(!dataHex.empty())
        {
            std::string spaced;
            spaced.reserve(dataHex.size() + dataHex.size() / 2);
            for(size_t i = 0; i < dataHex.size(); i += 2)
            {
                if(i && (i % 32 == 0))
                    spaced.push_back('\n');
                spaced.append(dataHex.substr(i, 2));
                if(i + 2 < dataHex.size())
                    spaced.push_back(' ');
            }

            std::string ascii;
            ascii.reserve(dataHex.size() / 2);
            for(size_t i = 0; i + 1 < dataHex.size(); i += 2)
            {
                int value = std::stoi(dataHex.substr(i, 2), nullptr, 16);
                char c = static_cast<char>(value);
                ascii.push_back((c >= 32 && c <= 126) ? c : '.');
            }

            extraText.push_back(std::string("Hex:\n") + spaced);
            extraText.push_back(std::string("ASCII:\n") + ascii);
        }
        if(!valueHex.empty())
            extraText.push_back(std::string("Value:\n") + valueHex);
    }
    else if(toolName == "writeMemory")
    {
        payload = handleWriteMemory(arguments);
        const std::string address = payload.value("address", std::string(""));
    const size_t written = static_cast<size_t>(payload.value("bytesWritten", 0ull));
        summary = "Wrote " + std::to_string(written) + " bytes to " + address;

        if(payload.value("force", false))
        {
            std::string protectBefore = payload.value("pageProtectBefore", std::string(""));
            std::string protectAfter = payload.value("pageProtectAfter", std::string(""));
            extraText.push_back(std::string("Protection before: ") + (protectBefore.empty() ? "unknown" : protectBefore));
            extraText.push_back(std::string("Protection after: ") + (protectAfter.empty() ? "unknown" : protectAfter));
            extraText.push_back(std::string("Restored: ") + (payload.value("protectionRestored", true) ? "yes" : "no"));
        }
    }
    else if(toolName == "listModules")
    {
        payload = handleListModules(arguments);
        const auto modules = payload.contains("modules") && payload.at("modules").is_array() ? payload.at("modules") : json::array();
        summary = "Modules: " + std::to_string(modules.size());

        if(!modules.empty())
        {
            std::string names;
            for(size_t i = 0; i < modules.size(); ++i)
            {
                const auto& mod = modules[i];
                names += mod.value("name", std::string("?"));
                names += " @ ";
                names += mod.value("base", std::string(""));
                names += " (";
                names += mod.value("path", std::string(""));
                names += ")";
                if(i + 1 < modules.size())
                    names += '\n';
            }
            extraText.push_back(std::string("Modules:\n") + names);
        }
    }
    else if(toolName == "patternScan")
    {
        payload = handlePatternScan(arguments);
    const size_t matchCount = static_cast<size_t>(payload.value("matchCount", 0ull));
        summary = std::to_string(matchCount) + std::string(matchCount == 1 ? " match" : " matches") + " for pattern";

        const auto matchesJson = payload.contains("matches") && payload.at("matches").is_array() ? payload.at("matches") : json::array();
        if(!matchesJson.empty())
        {
            std::string list;
            size_t previewCount = std::min<size_t>(matchesJson.size(), 5);
            for(size_t i = 0; i < previewCount; ++i)
            {
                list += matchesJson[i].get<std::string>();
                if(i + 1 < previewCount)
                    list.push_back('\n');
            }
            extraText.push_back(std::string("Matches:\n") + list);
        }
    }
    else if(toolName == "getExports")
    {
        payload = handleGetExports(arguments);
        const auto exports = payload.contains("exports") && payload.at("exports").is_array() ? payload.at("exports") : json::array();
        summary = "Exports for " + payload.value("module", std::string("?")) + ": " + std::to_string(exports.size());
        if(!exports.empty())
        {
            std::ostringstream lines;
            for(size_t i = 0; i < exports.size(); ++i)
            {
                const auto& entry = exports[i];
                const int ordinal = entry.value("ordinal", 0);
                const std::string name = entry.value("name", std::string("?"));
                const std::string address = entry.value("address", std::string(""));
                const bool forwarded = entry.value("forwarded", false);
                lines << "#" << ordinal << " " << name;
                if(!address.empty())
                    lines << " @ " << address;
                if(forwarded)
                {
                    const std::string forwardName = entry.value("forwardName", std::string(""));
                    if(!forwardName.empty())
                        lines << " -> " << forwardName;
                    else
                        lines << " (forwarded)";
                }
                if(i + 1 < exports.size())
                    lines << '\n';
            }

            std::string text = lines.str();
            if(!text.empty())
                extraText.push_back(std::string("Exports:\n") + text);
        }
    }
    else if(toolName == "getImports")
    {
        payload = handleGetImports(arguments);
        const auto imports = payload.contains("imports") && payload.at("imports").is_array() ? payload.at("imports") : json::array();
        summary = "Imports for " + payload.value("module", std::string("?")) + ": " + std::to_string(imports.size());
        if(!imports.empty())
        {
            std::ostringstream lines;
            for(size_t i = 0; i < imports.size(); ++i)
            {
                const auto& entry = imports[i];
                const bool byOrdinal = entry.value("byOrdinal", false);
                std::string label;
                if(byOrdinal)
                    label = std::string("ord ") + std::to_string(entry.value("ordinal", 0));
                const std::string name = entry.value("name", std::string(""));
                if(!label.empty())
                {
                    if(!name.empty())
                        label += " (" + name + ")";
                }
                else
                {
                    label = !name.empty() ? name : std::string("<anon>");
                }

                const std::string undecorated = entry.value("undecoratedName", std::string(""));
                const std::string iatAddress = entry.value("iatAddress", std::string(""));

                lines << label;
                if(!undecorated.empty() && undecorated != name)
                    lines << " aka " << undecorated;
                if(!iatAddress.empty())
                    lines << " @ " << iatAddress;

                if(i + 1 < imports.size())
                    lines << '\n';
            }

            std::string text = lines.str();
            if(!text.empty())
                extraText.push_back(std::string("Imports:\n") + text);
        }
    }
    else if(toolName == "getDisassembly")
    {
        payload = handleGetDisassembly(arguments);
        const auto instructions = payload.contains("instructions") && payload.at("instructions").is_array() ? payload.at("instructions") : json::array();
        summary = "Disassembly from " + payload.value("startAddress", std::string("")) + " (" + std::to_string(instructions.size()) + " insn)";
        if(!instructions.empty())
        {
            std::string snippet;
            snippet.reserve(instructions.size() * 32);
            size_t previewCount = std::min<size_t>(instructions.size(), 4);
            for(size_t i = 0; i < previewCount; ++i)
            {
                const auto& instr = instructions[i];
                snippet += instr.value("address", std::string(""));
                snippet += ": ";
                snippet += instr.value("text", std::string(""));
                if(i + 1 < previewCount)
                    snippet += '\n';
            }
            extraText.push_back(std::string("Instructions:\n") + snippet);
        }
    }
    else if(toolName == "listBreakpoints")
    {
        payload = handleListBreakpoints(arguments);
        const int total = payload.value("total", 0);
        summary = std::to_string(total) + std::string(total == 1 ? " breakpoint" : " breakpoints");

        if(payload.contains("counts") && payload.at("counts").is_object())
        {
            std::ostringstream lines;
            for(const auto& item : payload.at("counts").items())
            {
                const int count = item.value().is_number() ? item.value().get<int>() : 0;
                lines << item.key() << ": " << count << '\n';
            }
            std::string text = lines.str();
            if(!text.empty())
            {
                if(text.back() == '\n')
                    text.pop_back();
                extraText.push_back(std::string("By type:\n") + text);
            }
        }
    }
    else if(toolName == "deleteBreakpoint")
    {
        payload = handleDeleteBreakpoint(arguments);
        summary = payload.value("removed", false) ? "Breakpoint removed" : "No breakpoint removed";
    }
    else if(toolName == "disableBreakpoint")
    {
        payload = handleDisableBreakpoint(arguments);
        if(payload.value("alreadyDisabled", false))
            summary = "Breakpoint already disabled";
        else
            summary = payload.value("disabled", false) ? "Breakpoint disabled" : "Disable skipped";
    }
    else if(toolName == "enableBreakpoint")
    {
        payload = handleEnableBreakpoint(arguments);
        if(payload.value("created", false))
            summary = "Breakpoint created";
        else if(payload.value("alreadyEnabled", false))
            summary = "Breakpoint already enabled";
        else
            summary = payload.value("enabled", false) ? "Breakpoint enabled" : "Enable skipped";
    }
    else if(toolName == "getThreads")
    {
        payload = handleGetThreads(arguments);
        const int count = payload.value("threadCount", 0);
        const duint currentTid = payload.value("currentThreadId", 0ull);
        const auto threadList = payload.contains("threads") && payload.at("threads").is_array() ? payload.at("threads") : json::array();

        std::ostringstream summaryLine;
        summaryLine << count << " threads";
        if(currentTid)
            summaryLine << " (current=" << currentTid << ")";
        summary = summaryLine.str();

        if(!threadList.empty())
        {
            std::ostringstream allThreads;
            for(const auto& threadEntry : threadList)
            {
                const int index = threadEntry.value("index", -1);
                const int threadNumber = threadEntry.value("threadNumber", -1);
                const duint tid = threadEntry.value("threadId", 0ull);
                const std::string name = threadEntry.value("name", std::string());
                const std::string cip = threadEntry.value("cip", std::string());
                const auto suspendCount = threadEntry.value("suspendCount", 0);
                const auto priority = threadEntry.contains("priority") && threadEntry.at("priority").is_object()
                                          ? threadEntry.at("priority").value("label", std::string())
                                          : std::string();

                allThreads << (index >= 0 ? std::to_string(index) : "?") << ": ";
                if(threadNumber >= 0)
                    allThreads << "thread#" << threadNumber << ' ';
                allThreads << "tid=" << tid;
                if(tid == currentTid)
                    allThreads << " [current]";
                if(!name.empty())
                    allThreads << " (" << name << ')';
                if(!cip.empty())
                    allThreads << " CIP=" << cip;
                if(!priority.empty())
                    allThreads << " priority=" << priority;
                if(suspendCount > 0)
                    allThreads << " suspended=" << suspendCount;
                allThreads << '\n';
            }

            const std::string threadText = allThreads.str();
            if(!threadText.empty())
                extraText.push_back(std::string("Threads:\n") + threadText);
        }
    }
    else if(toolName == "setBreakpoint")
    {
        payload = handleSetBreakpoint(arguments);
        summary = "Breakpoint set successfully";
    }
    else if(toolName == "getRegisters")
    {
        payload = handleGetRegisters(arguments);
        const auto generalMap = payload.contains("general") && payload.at("general").is_object() ? payload.at("general") : json::object();
        const auto regs = payload.contains("registers") && payload.at("registers").is_array() ? payload.at("registers") : json::array();

        const std::string espHex = generalMap.contains("esp") ? generalMap.at("esp").get<std::string>() : std::string();
        const std::string ebpHex = generalMap.contains("ebp") ? generalMap.at("ebp").get<std::string>() : std::string();
        const std::string eipHex = generalMap.contains("eip") ? generalMap.at("eip").get<std::string>() : std::string();
        const std::string eaxHex = generalMap.contains("eax") ? generalMap.at("eax").get<std::string>() : std::string();

        std::string primaryLine;
        if(!espHex.empty())
        {
            primaryLine += "esp=" + espHex;
            if(!ebpHex.empty())
                primaryLine += "  ebp=" + ebpHex;
            if(!eipHex.empty())
                primaryLine += "  eip=" + eipHex;
        }
        if(primaryLine.empty() && !regs.empty())
        {
            size_t take = std::min<size_t>(regs.size(), 6);
            for(size_t i = 0; i < take; ++i)
            {
                const auto& entry = regs[i];
                primaryLine += entry.value("name", std::string("?"));
                primaryLine += '=';
                primaryLine += entry.value("hex", std::string(""));
                if(i + 1 < take)
                    primaryLine += "  ";
            }
        }

        if(primaryLine.empty() && !eaxHex.empty())
            primaryLine = "eax=" + eaxHex;

        summary = primaryLine.empty() ? std::string("Register snapshot") : primaryLine;

        if(!primaryLine.empty())
            extraText.push_back(std::string("Registers (hex):\n") + primaryLine);

        if(payload.contains("flagList") && payload.at("flagList").is_array())
        {
            std::string flagLine;
            for(const auto& flag : payload.at("flagList"))
            {
                flagLine += flag.value("name", std::string("?"));
                flagLine += '=';
                flagLine += flag.value("value", false) ? '1' : '0';
                flagLine += ' ';
            }
            if(!flagLine.empty())
            {
                flagLine.pop_back();
                extraText.push_back(std::string("Flags:\n") + flagLine);
            }
        }

        if(payload.contains("debugRegisters") && payload.at("debugRegisters").is_array())
        {
            std::string dbgLine;
            for(const auto& entry : payload.at("debugRegisters"))
            {
                dbgLine += entry.value("name", std::string("?"));
                dbgLine += '=';
                dbgLine += entry.value("hex", std::string(""));
                dbgLine += ' ';
            }
            if(!dbgLine.empty())
            {
                dbgLine.pop_back();
                extraText.push_back(std::string("Debug registers:\n") + dbgLine);
            }
        }

        if(payload.contains("segmentList") && payload.at("segmentList").is_array())
        {
            std::string segLine;
            for(const auto& segment : payload.at("segmentList"))
            {
                segLine += segment.value("name", std::string("?"));
                segLine += '=';
                segLine += std::to_string(segment.value("value", 0));
                segLine += ' ';
            }
            if(!segLine.empty())
            {
                segLine.pop_back();
                extraText.push_back(std::string("Segments:\n") + segLine);
            }
        }

        if(payload.contains("stackPointer") && payload.at("stackPointer").is_object())
        {
            const auto& sp = payload.at("stackPointer");
            extraText.push_back(std::string("Stack pointer:\n") + sp.value("hex", std::string("")));
        }
    }
    else if(toolName == "runTrace")
    {
        payload = handleRunTrace(arguments);
        summary = "Trace command executed";
    }
    else if(toolName == "getPageRights")
    {
        payload = handleGetPageRights(arguments);
        std::string rightsText = payload.value("rights", std::string(""));
        if(rightsText.empty())
            rightsText = std::to_string(payload.value("protect", 0));
        summary = "Rights at " + payload.value("address", std::string("")) + " = " + rightsText;
        if(payload.contains("flags"))
        {
            const auto& flags = payload.at("flags");
            std::string line;
            if(flags.value("execute", false)) line += "E ";
            if(flags.value("read", false)) line += "R ";
            if(flags.value("write", false)) line += "W ";
            if(flags.value("copy", false)) line += "C ";
            if(flags.value("guard", false)) line += "G ";
            if(!line.empty() && line.back() == ' ')
                line.pop_back();
            if(!line.empty())
                extraText.push_back(std::string("Flags:\n") + line);
        }
    }
    else if(toolName == "setPageRights")
    {
        payload = handleSetPageRights(arguments);
        summary = "Updated rights at " + payload.value("address", std::string(""));
        extraText.push_back(std::string("Effective: ") + payload.value("effectiveRights", std::string("")));
    }
    else if(toolName == "memIsCodePage")
    {
        payload = handleMemIsCodePage(arguments);
        summary = std::string("Code page? ") + (payload.value("isCode", false) ? "yes" : "no");
    }
    else if(toolName == "getTraceRecord")
    {
        payload = handleGetTraceRecord(arguments);
        summary = "Trace hits=" + std::to_string(payload.value("hitCount", 0));
        extraText.push_back(std::string("Type: ") + payload.value("recordType", std::string("")) +
                           " / Byte: " + payload.value("byteType", std::string("")));
    }
    else if(toolName == "memBpSize")
    {
        payload = handleMemBpSize(arguments);
        summary = "Mem BP size=" + std::to_string(payload.value("size", 0));
    }
    else if(toolName == "ping")
    {
        payload = json::object({{"message", "pong"}});
        summary = "pong";
    }

    if(payload.is_null())
        throw std::runtime_error("tools/call received unknown tool");

    json content = json::array();

    auto appendText = [&content](const std::string& text) {
        if(text.empty())
            return;
        content.push_back(json::object({
            {"type", "text"},
            {"text", text}
        }));
    };

    appendText(summary);
    for(const auto& text : extraText)
        appendText(text);

    const std::string payloadText = payload.dump(2);
    appendText(payloadText);

    if(content.empty())
        appendText("Tool executed without additional output.");

    json result = json::object({
        {"content", content}
    });

    if(!payload.is_null())
        result["structured"] = payload;

    return result;
}

bool McpServer::parseAddress(const json& value, duint& address)
{
    try
    {
        if(value.is_string())
        {
            const std::string text = value.get<std::string>();
            address = static_cast<duint>(std::stoull(text, nullptr, 0));
            return true;
        }

        if(value.is_number_unsigned())
        {
            address = static_cast<duint>(value.get<unsigned long long>());
            return true;
        }

        if(value.is_number_integer())
        {
            address = static_cast<duint>(value.get<long long>());
            return true;
        }
    }
    catch(...)
    {
    }

    return false;
}

std::string McpServer::formatAddress(duint address)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setw(sizeof(duint) * 2) << std::setfill('0') << address;
    return ss.str();
}

std::string McpServer::bytesToHex(const std::vector<unsigned char>& data)
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for(unsigned char byte : data)
        ss << std::setw(2) << static_cast<int>(byte);
    return ss.str();
}

bool McpServer::resolveModuleInfo(const json& value, Script::Module::ModuleInfo& info)
{
    if(value.is_string())
    {
        const std::string name = value.get<std::string>();
        if(Script::Module::InfoFromName(name.c_str(), &info))
            return true;
    }
    else if(value.is_object())
    {
        if(value.contains("name") && value.at("name").is_string())
        {
            const std::string name = value.at("name").get<std::string>();
            if(Script::Module::InfoFromName(name.c_str(), &info))
                return true;
        }

        if(value.contains("address"))
        {
            duint address = 0;
            if(parseAddress(value.at("address"), address) && Script::Module::InfoFromAddr(address, &info))
                return true;
        }
    }

    duint address = 0;
    if(parseAddress(value, address) && Script::Module::InfoFromAddr(address, &info))
        return true;

    return false;
}

const char* McpServer::disasmTypeToString(DISASM_INSTRTYPE type)
{
    switch(type)
    {
    case instr_normal:
        return "normal";
    case instr_branch:
        return "branch";
    case instr_stack:
        return "stack";
    default:
        return "unknown";
    }
}

const char* McpServer::traceRecordTypeToString(TRACERECORDTYPE type)
{
    switch(type)
    {
    case TraceRecordNone:
        return "none";
    case TraceRecordBitExec:
        return "bitExec";
    case TraceRecordByteWithExecTypeAndCounter:
        return "byteExecCounter";
    case TraceRecordWordWithExecTypeAndCounter:
        return "wordExecCounter";
    default:
        return "unknown";
    }
}

const char* McpServer::traceRecordByteTypeToString(TRACERECORDBYTETYPE type)
{
    switch(type)
    {
    case InstructionBody:
        return "instructionBody";
    case InstructionHeading:
        return "instructionHeading";
    case InstructionTailing:
        return "instructionTailing";
    case InstructionOverlapped:
        return "instructionOverlapped";
    case DataByte:
        return "dataByte";
    case DataWord:
        return "dataWord";
    case DataDWord:
        return "dataDword";
    case DataQWord:
        return "dataQword";
    case DataFloat:
        return "dataFloat";
    case DataDouble:
        return "dataDouble";
    case DataLongDouble:
        return "dataLongDouble";
    case DataXMM:
        return "dataXmm";
    case DataYMM:
        return "dataYmm";
    case DataMMX:
        return "dataMmx";
    case DataMixed:
        return "dataMixed";
    case InstructionDataMixed:
        return "instructionDataMixed";
    default:
        return "unknown";
    }
}

unsigned long McpServer::protectionFromRightsString(const std::string& rights)
{
    bool hasExecute = false;
    bool hasRead = false;
    bool hasWrite = false;
    bool hasCopy = false;
    bool hasGuard = false;

    for(char ch : rights)
    {
        switch(std::toupper(static_cast<unsigned char>(ch)))
        {
        case 'E': hasExecute = true; break;
        case 'R': hasRead = true; break;
        case 'W': hasWrite = true; break;
        case 'C': hasCopy = true; break;
        case 'G': hasGuard = true; break;
        default: break;
        }
    }

    unsigned long protect = PAGE_NOACCESS;

    if(hasExecute)
    {
        if(hasWrite)
            protect = PAGE_EXECUTE_READWRITE;
        else if(hasCopy)
            protect = PAGE_EXECUTE_WRITECOPY;
        else if(hasRead)
            protect = PAGE_EXECUTE_READ;
        else
            protect = PAGE_EXECUTE;
    }
    else
    {
        if(hasWrite && hasRead)
            protect = PAGE_READWRITE;
        else if(hasCopy && hasRead)
            protect = PAGE_WRITECOPY;
        else if(hasRead)
            protect = PAGE_READONLY;
        else if(hasWrite)
            protect = PAGE_READWRITE;
        else
            protect = PAGE_NOACCESS;
    }

    if(hasGuard)
        protect |= PAGE_GUARD;

    return protect;
}

std::string McpServer::rightsStringFromProtect(unsigned long protect)
{
    const DBGFUNCTIONS* dbg = DbgFunctions();
    if(dbg && dbg->PageRightsToString)
    {
        char rights[RIGHTS_STRING_SIZE] = {};
        if(dbg->PageRightsToString(protect, rights))
            return std::string(rights);
    }

    std::string result;
    switch(protect & 0xFF)
    {
    case PAGE_NOACCESS:
        break;
    case PAGE_READONLY:
        result = "R";
        break;
    case PAGE_READWRITE:
        result = "RW";
        break;
    case PAGE_WRITECOPY:
        result = "RC";
        break;
    case PAGE_EXECUTE:
        result = "E";
        break;
    case PAGE_EXECUTE_READ:
        result = "ER";
        break;
    case PAGE_EXECUTE_READWRITE:
        result = "ERW";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        result = "ERC";
        break;
    default:
        result = "?";
        break;
    }

    if(protect & PAGE_GUARD)
        result.push_back('G');
    if(protect & PAGE_NOCACHE)
        result.push_back('N');

    return result;
}
