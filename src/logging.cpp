#include "logging.h"

#include <cstdarg>
#include <mutex>
#include <string>
#include <vector>

#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_plugins.h"

namespace
{
    constexpr std::string_view kTag = "[MCP]";

    std::mutex& logMutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    std::string formatMessage(const char* format, va_list args)
    {
        va_list copy;
        va_copy(copy, args);
        int required = std::vsnprintf(nullptr, 0, format, copy);
        va_end(copy);

        if(required <= 0)
            return {};

        std::string buffer(static_cast<size_t>(required), '\0');
        std::vsnprintf(buffer.data(), buffer.size() + 1, format, args);
        return buffer;
    }

    void writeLog(std::string_view level, std::string_view message)
    {
        std::lock_guard<std::mutex> guard(logMutex());
        std::string composed;
        composed.reserve(level.size() + kTag.size() + message.size() + 4);
        composed.append("[").append(level).append("] ").append(kTag).append(" ").append(message);

        _plugin_logprintf("%s\n", composed.c_str());
        GuiAddLogMessage(composed.c_str());
    }

    void logFormatted(std::string_view level, const char* format, va_list args)
    {
        std::string message = formatMessage(format, args);
        writeLog(level, message);
    }
}

void LogInfo(std::string_view message)
{
    writeLog("INFO", message);
}

void LogWarning(std::string_view message)
{
    writeLog("WARN", message);
}

void LogError(std::string_view message)
{
    writeLog("ERROR", message);
}

void LogInfoF(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    logFormatted("INFO", format, args);
    va_end(args);
}

void LogWarningF(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    logFormatted("WARN", format, args);
    va_end(args);
}

void LogErrorF(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    logFormatted("ERROR", format, args);
    va_end(args);
}
