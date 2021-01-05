/**
 * @file libcomp/src/BaseLog.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Routines to log messages to the console and/or a file.
 *
 * This file is part of the COMP_hack Library (libcomp).
 *
 * Copyright (C) 2012-2020 COMP_hack Team <compomega@tutanota.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "BaseLog.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <thread>

#include "EnumUtils.h"

#ifdef _WIN32
// Windows Includes
#include <windows.h>

// Windows Shell Includes
#include <shlwapi.h>
#include <wincon.h>
#else
#include <unistd.h>
#endif  // _WIN32

// zlib Includes
#include <zlib.h>

using namespace libcomp;

namespace {

/**
 * @internal
 * Message to stop the log thread.
 */
class LogStop : public LogMessage {
 public:
  /**
   * Construct the message.
   */
  LogStop()
      : LogMessage(to_underlying(BaseLogComponent_t::General),
                   BaseLog::Level_t::LOG_LEVEL_CRITICAL) {}

  /**
   * Free the message.
   */
  ~LogStop() override {}

  /**
   * Override this to provide the log message.
   * @returns Log message
   */
  String GetMsg() const override { return {}; }

  /**
   * Override this to tell the log thread to stop.
   * @returns If the log thread should stop.
   */
  bool ShouldStop() const override { return true; }
};

}  // namespace

/// Mapping of log components to their string names
static EnumMap<BaseLogComponent_t, String> gBaseLogComponentMapping = {
    {BaseLogComponent_t::Connection, "Connection"},
    {BaseLogComponent_t::Crypto, "Crypto"},
    {BaseLogComponent_t::Database, "Database"},
    {BaseLogComponent_t::DataStore, "DataStore"},
    {BaseLogComponent_t::DataSyncManager, "DataSyncManager"},
    {BaseLogComponent_t::General, "General"},
    {BaseLogComponent_t::Packet, "Packet"},
    {BaseLogComponent_t::ScriptEngine, "ScriptEngine"},
    {BaseLogComponent_t::Server, "Server"},
};

BaseLogComponent_t libcomp::StringToBaseLogComponent(const String& comp) {
  for (auto pair : gBaseLogComponentMapping) {
    if (pair.second == comp) {
      return pair.first;
    }
  }

  return BaseLogComponent_t::Invalid;
}

String libcomp::BaseLogComponentToString(GenericLogComponent_t comp) {
  if (to_underlying(BaseLogComponent_t::General) == comp) {
    return {};
  }

  auto match = gBaseLogComponentMapping.find((BaseLogComponent_t)comp);

  if (gBaseLogComponentMapping.end() != match) {
    return match->second;
  }

  return "Unknown";
}

/**
 * @internal
 * Singleton pointer for the Log class.
 */
static BaseLog* gLogInst = nullptr;

/*
 * Black       0;30     Dark Gray     1;30
 * Blue        0;34     Light Blue    1;34
 * Green       0;32     Light Green   1;32
 * Cyan        0;36     Light Cyan    1;36
 * Red         0;31     Light Red     1;31
 * Purple      0;35     Light Purple  1;35
 * Brown       0;33     Yellow        1;33
 * Light Gray  0;37     White         1;37
 */

/**
 * Log hook to send all log messages to standard output. This hook will color
 * all log messages depending on their log level.
 * @param level Numeric level representing the log level.
 * @param msg The message to write to standard output.
 * @param pUserData User defined data that was passed with the hook to
 * @ref BaseLog::AddLogHook.
 */
static void LogToStandardOutput(GenericLogComponent_t comp,
                                BaseLog::Level_t level, const String& msg,
                                void* pUserData) {
  // This was handled for us before the hook was called.
  (void)comp;

  // Console colors for each log level.
#ifdef _WIN32
  static const WORD gLogColors[BaseLog::LOG_LEVEL_COUNT] = {
      // Debug
      FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
      // Info
      FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE |
          FOREGROUND_INTENSITY,
      // Warning
      FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
      // Error
      FOREGROUND_RED | FOREGROUND_INTENSITY,
      // Critical
      FOREGROUND_RED | FOREGROUND_INTENSITY,
  };
#else
  static const String gLogColors[BaseLog::LOG_LEVEL_COUNT] = {
      "\e[1;32;40m",  // Debug
      "\e[37;40m",    // Info
      "\e[1;33;40m",  // Warning
      "\e[1;31;40m",  // Error
      "\e[1;37;41m",  // Critical
  };
#endif  // _WIN32

  // This hook has no user data.
  (void)pUserData;

  if (0 > level || BaseLog::LOG_LEVEL_COUNT <= level) {
    level = BaseLog::LOG_LEVEL_CRITICAL;
  }

  // Split the message into lines. Each line will be individually colored.
  std::list<String> msgs = msg.Split("\n");
  String last = msgs.back();
  msgs.pop_back();

  // Each log level has a different color scheme.
  for (String m : msgs) {
#if _WIN32
    (void)SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
                                  gLogColors[level]);

    std::cout << m.ToUtf8();

    (void)SetConsoleTextAttribute(
        GetStdHandle(STD_OUTPUT_HANDLE),
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    std::cout << std::endl;
#elif defined(EXOTIC_PLATFORM)
    printf("%s\n", m.C());
#else
    if (isatty(fileno(stdout))) {
      std::cout << gLogColors[level] << m.ToUtf8() << "\e[0K\e[0m" << std::endl;
    } else {
      std::cout << m.ToUtf8() << std::endl;
    }
#endif  // _WIN32
  }

  // If there is more on the last line, print it as well.
  if (!last.IsEmpty()) {
#if _WIN32
    (void)SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
                                  gLogColors[level]);

    std::cout << last.ToUtf8();

    (void)SetConsoleTextAttribute(
        GetStdHandle(STD_OUTPUT_HANDLE),
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#elif defined(EXOTIC_PLATFORM)
    printf("%s", last.C());
#else
    if (isatty(fileno(stdout))) {
      std::cout << gLogColors[level] << last.ToUtf8() << "\e[0K\e[0m";
    } else {
      std::cout << last.ToUtf8();
    }
#endif  // _WIN32
  }

  // Flush the output so the log messages are immediately avaliable.
  std::cout.flush();
}

BaseLog::BaseLog() : mLogFile(nullptr), mLastLog(-1337) {
  if (nullptr == gLogInst) {
    gLogInst = this;
  }

  mComponentLogLevels[to_underlying(BaseLogComponent_t::General)] =
      Level_t::LOG_LEVEL_INFO;

#ifdef _WIN32
  CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

  if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),
                                 &consoleInfo)) {
    mConsoleAttributes = consoleInfo.wAttributes;
  } else {
    mConsoleAttributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
  }

  (void)SetConsoleTextAttribute(
      GetStdHandle(STD_OUTPUT_HANDLE),
      FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#endif  // _WIN32

  mLogFileTimestampEnabled = false;
  mLogRotationEnabled = false;
  mLogCompression = true;
  mLogRotationCount = 3;
  mLogRotationDays = 1;

  mThread = std::thread([&]() {
#if !defined(EXOTIC_PLATFORM) && !defined(_WIN32) && !defined(__APPLE__)
    pthread_setname_np(pthread_self(), "log");
#endif  // !defined(EXOTIC_PLATFORM) && !defined(_WIN32) && !defined(__APPLE__)

    MessageLoop();
  });
}

BaseLog::~BaseLog() {
  // Issue a stop message.
  LogMessage(new LogStop);

  // Wait for the thread to exit.
  mThread.join();
}

BaseLog* BaseLog::GetBaseSingletonPtr() { return gLogInst; }

void BaseLog::LogMessage(libcomp::LogMessage* pMessage) {
#ifdef _WIN32
  if (Level_t::LOG_LEVEL_CRITICAL == pMessage->GetLevel()) {
    OutputDebugStringA(pMessage->GetMsg().C());
  }
#endif  // _WIN32

  mMessages.Enqueue(pMessage);
}

void BaseLog::LogMessage(
    const std::chrono::time_point<std::chrono::system_clock>& now,
    GenericLogComponent_t comp, BaseLog::Level_t level, const String& msg) {
  // Prepend these to messages.
  static const String gLogMessages[BaseLog::LOG_LEVEL_COUNT] = {
      "DEBUG: %1%2", "%1%2", "WARNING: %1%2", "ERROR: %1%2", "CRITICAL: %1%2",
  };

  // Log a critical error message. If the configuration option is true, log
  // the message to the log file. Regardless, pass the message to all the
  // log hooks for processing. Critical messages have the text "CRITICAL: "
  // appended to them.
  if (!ShouldLog(comp, level)) {
    return;
  }

  String compStr = comp >= LOG_SERVER_SPECIFIC_START_ID
                       ? LogComponentToString(comp)
                       : BaseLogComponentToString(comp);

  if (!compStr.IsEmpty()) {
    compStr += ": ";
  }

  String final = String(gLogMessages[level]).Arg(compStr).Arg(msg);

  if (nullptr != mLogFile) {
    auto duration = std::chrono::duration_cast<
                        std::chrono::duration<int64_t, std::ratio<86400>>>(
                        now.time_since_epoch())
                        .count();

    if (mLogRotationEnabled && mLogRotationDays <= (duration - mLastLog)) {
      RotateLogs();
    }

    mLastLog = duration;

    if (mLogFileTimestampEnabled) {
      auto currentTime = std::chrono::system_clock::to_time_t(now);

      std::stringstream ss;
      ss << std::put_time(std::localtime(&currentTime), "%Y/%m/%d %T");

      String formattedTime = String("[%1] ").Arg(ss.str());

      mLogFile->write(formattedTime.C(),
                      (std::streamsize)(formattedTime.Size() * sizeof(char)));
    }

    mLogFile->write(final.C(), (std::streamsize)(final.Size() * sizeof(char)));
    mLogFile->flush();
  }

  // Call all hooks.
  for (auto i : mHooks) {
    (*i.first)(comp, level, final, i.second);
  }

  // Call all lambda hooks.
  for (auto func : mLambdaHooks) {
    func(comp, level, final);
  }
}

String BaseLog::GetLogPath() const { return mLogPath; }

void BaseLog::SetLogPath(const String& path, bool truncate) {
  bool loaded = true;

  {
    // Set the log path.
    mLogPath = path;

    // Close the old log file if it's open.
    if (nullptr != mLogFile) {
      delete mLogFile;
      mLogFile = nullptr;
    }

    // If the log path isn't empty, log to a file. The file will be
    // truncated and created new first if truncate is set.
    if (!mLogPath.IsEmpty()) {
      int mode = std::ofstream::out;
      if (truncate) {
        mode |= std::ofstream::trunc;
      } else {
        mode |= std::ofstream::app;
      }

      mLogFile = new std::ofstream();
      mLogFile->open(mLogPath.C(), (std::ios_base::openmode)mode);
      mLogFile->flush();

      // If this failed, close it.
      if (!mLogFile->good()) {
        delete mLogFile;
        mLogFile = nullptr;
        mLogPath.Clear();
        loaded = false;
      }
    }
  }

  if (!loaded) {
    LogGeneralCriticalMsg("Failed to open the log file for writing.\n");
    LogGeneralCriticalMsg("The application will now close.\n");
    LogGeneralInfoMsg("Bye!\n");

    // Stop the logger
    delete this;

    exit(EXIT_FAILURE);
  }
}

void BaseLog::AddLogHook(BaseLog::Hook_t func, void* data) {
  // Add the specified log hook.
  mHooks[func] = data;
}

void BaseLog::AddLogHook(
    const std::function<void(GenericLogComponent_t comp, Level_t level,
                             const String& msg)>& func) {
  mLambdaHooks.push_back(func);
}

void BaseLog::AddStandardOutputHook() {
  // Add the default hook to log all messages to the terminal.
  AddLogHook(&LogToStandardOutput);
}

void BaseLog::ClearHooks() {
  // Remove all hooks.
  mHooks.clear();
  mLambdaHooks.clear();
}

BaseLog::Level_t BaseLog::GetLogLevel(GenericLogComponent_t comp) const {
  auto match = mComponentLogLevels.find(comp);

  if (mComponentLogLevels.end() != match) {
    return match->second;
  } else {
    // Log at least warning, error and critical by default.
    return Level_t::LOG_LEVEL_WARNING;
  }
}

void BaseLog::SetLogLevel(GenericLogComponent_t comp, Level_t level) {
  // Set if the level is enabled.
  mComponentLogLevels[comp] = level;
}

bool BaseLog::GetLogFileTimestampsEnabled() const {
  // Get if the log file timestamps are enabled.
  return mLogFileTimestampEnabled;
}

void BaseLog::SetLogFileTimestampsEnabled(bool enabled) {
  // Set if the log file timestamps are enabled.
  mLogFileTimestampEnabled = enabled;
}

bool BaseLog::GetLogRotationEnabled() const { return mLogRotationEnabled; }

void BaseLog::SetLogRotationEnabled(bool enabled) {
  mLogRotationEnabled = enabled;
}

bool BaseLog::GetLogCompression() const { return mLogCompression; }

void BaseLog::SetLogCompression(bool enabled) { mLogCompression = enabled; }

int BaseLog::GetLogRotationCount() const { return mLogRotationCount; }

void BaseLog::SetLogRotationCount(int count) { mLogRotationCount = count; }

int BaseLog::GetLogRotationDays() const { return mLogRotationDays; }

void BaseLog::SetLogRotationDays(int days) { mLogRotationDays = days; }

void BaseLog::RotateLogs() {
  // Do not rotate if the main log does not exist.
  if (!mLogPath.IsEmpty() && !FileExists(mLogPath)) {
    return;
  }

  // Delete the last log that we will rotate out.
  FileDelete(libcomp::String("%1.%2").Arg(mLogPath).Arg(mLogRotationCount));
  FileDelete(libcomp::String("%1.%2.gz").Arg(mLogPath).Arg(mLogRotationCount));

  // Now we need to rotate them out moving the files as we go.
  for (int i = mLogRotationCount - 1; i > 0; --i) {
    FileMove(libcomp::String("%1.%2").Arg(mLogPath).Arg(i),
             libcomp::String("%1.%2").Arg(mLogPath).Arg(i + 1));
    FileMove(libcomp::String("%1.%2.gz").Arg(mLogPath).Arg(i),
             libcomp::String("%1.%2.gz").Arg(mLogPath).Arg(i + 1));
  }

  // Now close the main log and move it.
  if (mLogFile) {
    mLogFile->close();
    delete mLogFile;
  }

  FileMove(mLogPath, mLogPath + ".1");

  // Open the log again.
  mLogFile = new std::ofstream();
  mLogFile->open(mLogPath.C(), std::ofstream::out | std::ofstream::trunc);
  mLogFile->flush();

  // If this failed, close it.
  if (!mLogFile->good()) {
    delete mLogFile;
    mLogFile = nullptr;
    mLogPath.Clear();
  }

  // If compression is enabled compress the log we just moved.
  if (mLogCompression) {
    std::thread th(
        [](libcomp::String compressPath) {
          bool error = false;
          char buffer[4096];
          libcomp::String compressedPath = compressPath + ".gz";

          FILE* in = fopen(compressPath.C(), "rb");
          gzFile gf = gzopen(compressedPath.C(), "wb");

          if (in && gf) {
            while (!feof(in)) {
              auto sz = fread(buffer, 1, sizeof(buffer), in);

              if (0 >= sz) {
                break;
              }

              if ((int)sz != gzwrite(gf, buffer, (unsigned)sz)) {
                error = true;
                break;
              }
            }
          }

          gzclose(gf);
          fclose(in);

          if (error) {
            FileDelete(compressedPath);
          } else {
            FileDelete(compressPath);
          }
        },
        mLogPath + ".1");

    // Detach the thread and let it work on it's own.
    th.detach();
  }
}

bool BaseLog::FileMove(const libcomp::String& oldPath,
                       const libcomp::String& newPath) {
#ifdef _WIN32
  return MoveFileA(oldPath.Replace("/", "\\").C(),
                   newPath.Replace("/", "\\").C());
#else
  return 0 == rename(oldPath.C(), newPath.C());
#endif
}

bool BaseLog::FileExists(const libcomp::String& file) {
#ifdef _WIN32
  return PathFileExistsA(file.Replace("/", "\\").C());
#else
  return 0 == access(file.C(), F_OK);
#endif
}

bool BaseLog::FileDelete(const libcomp::String& file) {
#ifdef _WIN32
  return DeleteFileA(file.Replace("/", "\\").C());
#else
  return 0 == unlink(file.C());
#endif
}

bool BaseLog::ShouldLog(GenericLogComponent_t comp, Level_t level) const {
  auto match = mComponentLogLevels.find(comp);

  Level_t targetLevel;

  if (mComponentLogLevels.end() != match) {
    targetLevel = match->second;
  } else {
    // Log at least warning, error and critical by default.
    targetLevel = Level_t::LOG_LEVEL_WARNING;
  }

  return to_underlying(level) >= to_underlying(targetLevel);
}

void BaseLog::MessageLoop() {
  bool running = true;

  while (running) {
    std::list<libcomp::LogMessage*> messages;
    mMessages.DequeueAll(messages);

    for (auto pMessage : messages) {
      if (pMessage->ShouldStop()) {
        running = false;
      } else {
        LogMessage(pMessage->GetTimestamp(), pMessage->GetComponent(),
                   pMessage->GetLevel(), pMessage->GetMsg());
      }

      delete pMessage;
    }
  }

#ifdef _WIN32
  (void)SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
                                mConsoleAttributes);
#else
  // Clear the last line before the server exits.
  std::cout << "\e[0K\e[0m";
#endif  // _WIN32

  // Close the log file.
  delete mLogFile;
  mLogFile = nullptr;

  // Remove the singleton pointer.
  gLogInst = nullptr;
}

GenericLogComponent_t BaseLog::StringToLogComponent(const String& comp) const {
  (void)comp;

  return (GenericLogComponent_t)StringToBaseLogComponent(comp);
}

String BaseLog::LogComponentToString(GenericLogComponent_t comp) const {
  (void)comp;

  return BaseLogComponentToString(comp);
}
