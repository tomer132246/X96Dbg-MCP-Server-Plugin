#pragma once

#include <string_view>

void LogInfo(std::string_view message);
void LogWarning(std::string_view message);
void LogError(std::string_view message);

void LogInfoF(const char* format, ...);
void LogWarningF(const char* format, ...);
void LogErrorF(const char* format, ...);
