#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <winsock2.h>

#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "nlohmann/json.hpp"

class McpServer
{
public:
    McpServer();
    ~McpServer();

    bool start(const std::string& host, unsigned short port);
    void stop();
    bool isRunning() const;
    unsigned short port() const;
    const std::string& host() const;

private:
    void serverLoop();
    void handleClient(SOCKET clientSocket);
    void sendJson(SOCKET clientSocket, const nlohmann::json& payload);
    void sendError(SOCKET clientSocket, const nlohmann::json& id, int code, const std::string& message);
    bool processRequest(const nlohmann::json& request, nlohmann::json& response);
    bool handleHttpClient(SOCKET clientSocket);
    void sendHttpHelpResponse(SOCKET clientSocket);

    nlohmann::json handleReadMemory(const nlohmann::json& params);
    nlohmann::json handleListModules(const nlohmann::json& params);
    nlohmann::json handleListBreakpoints(const nlohmann::json& params);
    nlohmann::json handleDeleteBreakpoint(const nlohmann::json& params);
    nlohmann::json handleDisableBreakpoint(const nlohmann::json& params);
    nlohmann::json handleEnableBreakpoint(const nlohmann::json& params);
    nlohmann::json handleSetBreakpoint(const nlohmann::json& params);
    nlohmann::json handleGetRegisters(const nlohmann::json& params);
    nlohmann::json handleRunTrace(const nlohmann::json& params);
    nlohmann::json handleGetExports(const nlohmann::json& params);
    nlohmann::json handleGetImports(const nlohmann::json& params);
    nlohmann::json handleGetDisassembly(const nlohmann::json& params);
    nlohmann::json handleGetThreads(const nlohmann::json& params);
    nlohmann::json handleGetPageRights(const nlohmann::json& params);
    nlohmann::json handleSetPageRights(const nlohmann::json& params);
    nlohmann::json handleMemIsCodePage(const nlohmann::json& params);
    nlohmann::json handleGetTraceRecord(const nlohmann::json& params);
    nlohmann::json handleMemBpSize(const nlohmann::json& params);
    nlohmann::json handleInitialize(const nlohmann::json& params);
    nlohmann::json handleLoggingSetLevel(const nlohmann::json& params);
    nlohmann::json handleNotificationsInitialized(const nlohmann::json& params);
    nlohmann::json handleToolsList();
    nlohmann::json handlePromptsList();
    nlohmann::json handleToolsCall(const nlohmann::json& params);

    static bool parseAddress(const nlohmann::json& value, duint& address);
    static std::string formatAddress(duint address);
    static std::string bytesToHex(const std::vector<unsigned char>& data);
    static bool resolveModuleInfo(const nlohmann::json& value, Script::Module::ModuleInfo& info);
    static const char* disasmTypeToString(DISASM_INSTRTYPE type);
    static const char* traceRecordTypeToString(TRACERECORDTYPE type);
    static const char* traceRecordByteTypeToString(TRACERECORDBYTETYPE type);
    static unsigned long protectionFromRightsString(const std::string& rights);
    static std::string rightsStringFromProtect(unsigned long protect);

private:
    std::atomic<bool> running_;
    std::thread worker_;
    SOCKET listenSocket_;
    unsigned short port_;
    std::mutex stateMutex_;
    std::mutex clientMutex_;
    SOCKET activeClient_;
    bool wsaInitialized_;
    std::string host_;
};
