/**
 * @file libcomp/src/Log.h
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

#ifndef LIBCOMP_SRC_LOG_H
#define LIBCOMP_SRC_LOG_H

#include <chrono>
#include <fstream>
#include <functional>
#include <list>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "CString.h"
#include "EnumMap.h"
#include "MessageQueue.h"

namespace libcomp {

/**
 * Log components a log message may belong to.
 */
enum class LogComponent_t {
  AccountManager,
  ActionManager,
  AIManager,
  Barter,
  Bazaar,
  CharacterManager,
  ChatManager,
  Clan,
  Connection,
  Crypto,
  Database,
  DataStore,
  DataSyncManager,
  DefinitionManager,
  Demon,
  EventManager,
  Friend,
  FusionManager,
  General,
  Invalid,
  Item,
  MatchManager,
  Packet,
  Party,
  ScriptEngine,
  Server,
  ServerConstants,
  ServerDataManager,
  SkillManager,
  Team,
  TokuseiManager,
  Trade,
  WebAPI,
  ZoneManager,
};

/**
 * Convert a string into a log component.
 * @param comp String to convert.
 * @returns Log component the string represents.
 */
LogComponent_t StringToLogComponent(const String& comp);

/**
 * Convert a log component into a string.
 * @param comp Log component to convert.
 * @returns String representation of the log component.
 */
String LogComponentToString(LogComponent_t comp);

// Forward declaration for the Log class.
class LogMessage;

/**
 * Logging interface capable of logging messages to the terminal or a file.
 * The Log class is implemented as a singleton. The constructor should not be
 * called and is protected because of this. Instead, the first call to
 * @ref GetSingletonPtr() will construct the object. Subsequent calls will
 * simply return a pointer to the existing object. The object should only be
 * deleted once at the end of the application or not at all. The method
 * @ref SetLogPath() will open and initialize the log file. Initialization of
 * the log subsystem can be done with the following code:
 *
 * @code
 * Log::GetSingletonPtr()->SetLogPath("/var/log/my.log");
 * @endcode
 *
 * There is currently only one log file created. There is no compression or
 * rotation of log files. The logging subsystem consists of five different log
 * levels. Each level has a macro that saves typing of GetSingletonPtr to log a
 * simple message. These macros are @ref LOG_CRITICAL, @ref LOG_ERROR,
 * @ref LOG_WARNING, @ref LOG_INFO, and @ref LOG_DEBUG. Each log level can be
 * omitted from the log file by setting @ref SetLogLevelEnabled.
 *
 * Log hooks can be implemented to process log messages differently. All hooks
 * must conform to the @ref Log::Hook_t function prototype. This consists of a
 * log level, the message, and the user data provided by the @ref AddLogHook
 * method. For more information on the function prototype, see the docs for
 * @ref Log::Hook_t and @ref AddLogHook.
 */
class Log {
 public:
  /**
   * All valid log levels.
   */
  typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL,
    LOG_LEVEL_COUNT,
  } Level_t;

  /**
   * Prototype of a function to be called when a log event occurs. When a log
   * message is generated, @em level describes the error level of the message,
   * @em msg contains the data, and @em pUserData is optional user defined
   * data passed to @ref Log::AddLogHook along with the function. See
   * @ref Level_t for all possible log levels.
   */
  typedef void (*Hook_t)(LogComponent_t comp, Level_t level, const String& msg,
                         void* pUserData);

  /**
   * Deconstruct and delete the Log singleton.
   */
  ~Log();

  /**
   * Return a pointer to the Log singleton. If the singleton has not been
   * created, this method will create the singleton first.
   * @returns Pointer to the Log singleton. This method should never return
   * a null pointer.
   */
  static Log* GetSingletonPtr();

  /**
   * Log a message.
   * @param pMessage Message to log.
   * @note This function will take ownership of the message.
   */
  void LogMessage(libcomp::LogMessage* pMessage);

  /**
   * Get the path to the log file.
   * @returns Path to the log file.
   */
  String GetLogPath() const;

  /**
   * Set the path to the log file. This will open the log file and optionally
   * truncate.
   * @param path Path to the log file.
   * @param truncate true if the file should be truncated, false if it should
   * append to the existing file.
   */
  void SetLogPath(const String& path, bool truncate);

  /**
   * Add a log hook to the logging subsystem. The log hook @em func will be
   * called for each new log message that is enabled through
   * @ref SetLogLevelEnabled. The log level, message, and user data passed to
   * this method as @em pUserData will be provided to the log hook function.
   * @param func Log hook function to call.
   * @param pUserData User defined data to pass to the log hook function.
   */
  void AddLogHook(Hook_t func, void* pUserData = 0);

  /**
   * Add a log hook to the logging subsystem. The log hook @em func will be
   * called for each new log message that is enabled through
   * @ref SetLogLevelEnabled. The log level and message will be provided to
   * the log hook function.
   * @param func Log hook function to call.
   */
  void AddLogHook(const std::function<void(LogComponent_t comp, Level_t level,
                                           const String& msg)>& func);

  /**
   * Add the built-in hook to log to standard output.
   */
  void AddStandardOutputHook();

  /**
   * Remove all log hooks.
   */
  void ClearHooks();

  /**
   * Get the specified logging level for a component.
   * @param comp A logging component.
   * @returns The logging level for the component.
   */
  Level_t GetLogLevel(LogComponent_t comp) const;

  /**
   * Set the specified logging level for a component.
   * @param comp A logging component.
   * @param level A logging level.
   */
  void SetLogLevel(LogComponent_t comp, Level_t level);

  /**
   * Get if the log file timestamps are enabled.
   * @return true if file logging timestamps are enabled.
   */
  bool GetLogFileTimestampsEnabled() const;

  /**
   * Set if the log file timestamps are enabled.
   * @param enabled If file logging timestamps are enabled.
   */
  void SetLogFileTimestampsEnabled(bool enabled);

  /**
   * Get if the log rotation feature is enabled.
   * @return true if log rotation is enabled.
   */
  bool GetLogRotationEnabled() const;

  /**
   * Set if the log rotation feature is enabled.
   * @param enabled If log rotation is enabled.
   */
  void SetLogRotationEnabled(bool enabled);

  /**
   * Get if the log rotation will compress logs.
   * @return true if log rotation will compress logs.
   */
  bool GetLogCompression() const;

  /**
   * Set if the log rotation will compress logs.
   * @param enabled If log rotation will compress logs.
   */
  void SetLogCompression(bool enabled);

  /**
   * Get the number of logs that will be rotated.
   * @return Number of logs that will be rotated.
   */
  int GetLogRotationCount() const;

  /**
   * Set the number of logs that will be rotated.
   * @param count Number of logs that will be rotated.
   */
  void SetLogRotationCount(int count);

  /**
   * Get the number of days until the logs will be rotated.
   * @return Number of days until the logs will be rotated.
   */
  int GetLogRotationDays() const;

  /**
   * Set the number of days until the logs will be rotated.
   * @param days Number of days until the logs will be rotated.
   */
  void SetLogRotationDays(int days);

  /**
   * Function to determine if a message should be logged given the provided
   * component and log level.
   * @param comp Component to log.
   * @param level Level to log.
   * @returns true if the message should be logged; false otherwise.
   */
  bool ShouldLog(LogComponent_t comp, Level_t level) const;

 protected:
  /**
   * @internal
   * Construct a Log object. This constructor is protected because it should
   * not be called directly. Instead, call @ref GetSingletonPtr and let the
   * method construct the object if it doesn't already exist. This enforces
   * the singleton design pattern.
   * @sa GetSingletonPtr
   */
  Log();

  /**
   * @internal
   * Rotate the log files.
   */
  void RotateLogs();

  /**
   * @internal
   * Log a message.
   * @param timestamp When the log message was created.
   * @param comp Component this log message belongs to.
   * @param level Logging level of the message.
   * @param msg The message to log.
   */
  void LogMessage(
      const std::chrono::time_point<std::chrono::system_clock>& timestamp,
      LogComponent_t comp, Level_t level, const String& msg);

  /**
   * @internal
   *  Loop to process log messages.
   */
  void MessageLoop();

  /**
   * @internal
   * Move a file from one path to another.
   * @return true if the file was moved; false otherwise.
   */
  static bool FileMove(const libcomp::String& oldPath,
                       const libcomp::String& newPath);

  /**
   * @internal
   * Check if a file exists.
   * @return true if the file exists; false otherwise.
   */
  static bool FileExists(const libcomp::String& file);

  /**
   * @internal
   * Delete a file given it's path.
   * @return true if the file was deleted; false otherwise.
   */
  static bool FileDelete(const libcomp::String& file);

  /**
   * @internal
   * Path to the log file.
   */
  String mLogPath;

  /**
   * @internal
   * Whether log file messages will contain a timestamp.
   */
  bool mLogFileTimestampEnabled;

  /**
   * @internal
   * Whether log files rotate.
   */
  bool mLogRotationEnabled;

  /**
   * @internal
   * Whether log files that have rotated compress.
   */
  bool mLogCompression;

  /**
   * @internal
   * Number of past logs to keep when rotation is enabled.
   */
  int mLogRotationCount;

  /**
   * @internal
   * Number of days to keep the log before rotating.
   */
  int mLogRotationDays;

  /**
   * @internal
   * Log file object that messages will be written to.
   */
  std::ofstream* mLogFile;

  /**
   * @internal
   * Mapping of log hooks and their associated user data.
   */
  std::unordered_map<Hook_t, void*> mHooks;

  /**
   * @internal
   * Levels of all the log components.
   */
  EnumMap<LogComponent_t, Level_t> mComponentLogLevels;

  /**
   * @internal
   * List of log hooks.
   */
  std::list<std::function<void(LogComponent_t comp, Level_t level,
                               const String& msg)>>
      mLambdaHooks;

  /**
   * @internal
   * Number of days since the UNIX epoch for the last log message.
   */
  int64_t mLastLog;

  /**
   * @internal
   * Messages for the log thread to process.
   */
  MessageQueue<libcomp::LogMessage*> mMessages;

  /**
   * @internal
   * Thread to process log messages.
   */
  std::thread mThread;

#ifdef _WIN32
  /**
   * @internal
   * Windows standard output console color attributes.
   */
  uint16_t mConsoleAttributes;
#endif
};

/**
 * @internal
 * Log message to pass to the thread.
 */
class LogMessage {
 public:
  /**
   * Construct the log message.
   * @param comp Component for this message.
   * @param level Log level for this message.
   */
  explicit LogMessage(LogComponent_t comp, Log::Level_t level)
      : mComponent(comp),
        mLevel(level),
        mTimestamp(std::chrono::system_clock::now()) {}

  /**
   * Free the log message.
   */
  virtual ~LogMessage() {}

  /**
   * Override this to provide the log message.
   * @returns Log message
   */
  virtual String GetMsg() const = 0;

  /**
   * Indicates if the log thread should stop.
   * @returns true if the log thread should stop
   */
  virtual bool ShouldStop() const { return false; }

  /**
   * Get the component this log message belongs to.
   * @returns Component this log message belongs to.
   */
  LogComponent_t GetComponent() const { return mComponent; }

  /**
   * Get the log level for this message.
   * @returns Log level for this message.
   */
  Log::Level_t GetLevel() const { return mLevel; }

  /**
   * Get the timestamp for this message.
   * @returns Timestamp for this message.
   */
  std::chrono::time_point<std::chrono::system_clock> GetTimestamp() const {
    return mTimestamp;
  }

 private:
  /// Component the message belongs to
  LogComponent_t mComponent;

  /// Log level of the message
  Log::Level_t mLevel;

  /// Timestamp of the message
  std::chrono::time_point<std::chrono::system_clock> mTimestamp;
};

/**
 * @internal
 * Implementation of a log message that takes a lambda function.
 */
template <typename... Function>
class LogMessageImpl : public LogMessage {
 public:
  /// Type for the lambda function binding.
  using BindType_t =
      decltype(std::bind(std::declval<std::function<String(Function...)>>(),
                         std::declval<Function>()...));

  /**
   * Construct a log message that calls a lambda function for the message.
   * @param comp Component this message belongs to.
   * @param level Log level of the message
   * @param f Lambda function to call
   * @param args Arguments to pass to the lambda function.
   */
  template <typename... Args>
  explicit LogMessageImpl(LogComponent_t comp, Log::Level_t level,
                          std::function<String(Function...)> f, Args&&... args)
      : LogMessage(comp, level),
        mBind(std::move(f), std::forward<Args>(args)...) {}

  /**
   * Free the log message.
   */
  ~LogMessageImpl() override {}

  /**
   * Override this to provide the log message.
   * @returns Log message
   */
  String GetMsg() const override { return mBind(); }

 private:
  /// Binding for the lambda function.
  BindType_t mBind;
};

/**
 * @internal
 * Implementation of a log message that has a fixed string.
 */
class LogMessageFixed : public LogMessage {
 public:
  /**
   * Construct a log message with a fixed string.
   * @param comp Component this message belongs to.
   * @param level Log level of the message
   * @param msg Message to log
   */
  explicit LogMessageFixed(LogComponent_t comp, Log::Level_t level,
                           const String& msg)
      : LogMessage(comp, level), mMessage(msg) {}

  /**
   * Free the log message.
   */
  ~LogMessageFixed() override {}

  /**
   * Override this to provide the log message.
   * @returns Log message
   */
  String GetMsg() const override { return mMessage; }

 private:
  /// Fixed string to log
  String mMessage;
};

}  // namespace libcomp

/**
 * Macro to create a log function
 * @param name Name of the function
 * @param comp Component the functions logs
 * @param level Log level the function logs
 */
#define LOG_FUNCTION(name, comp, level)                                      \
  static inline void name(const std::function<libcomp::String(void)>& fun) { \
    auto log = libcomp::Log::GetSingletonPtr();                              \
                                                                             \
    if (log->ShouldLog(libcomp::LogComponent_t::comp, level)) {              \
      auto msg = new libcomp::LogMessageFixed(libcomp::LogComponent_t::comp, \
                                              level, fun());                 \
      log->LogMessage(msg);                                                  \
    }                                                                        \
  }                                                                          \
                                                                             \
  template <typename Function, typename... Args>                             \
  static inline void name##Delayed(Function&& f, Args&&... args) {           \
    auto log = libcomp::Log::GetSingletonPtr();                              \
                                                                             \
    if (log->ShouldLog(libcomp::LogComponent_t::comp, level)) {              \
      auto msg = new libcomp::LogMessageImpl<Args...>(                       \
          libcomp::LogComponent_t::comp, level, std::forward<Function>(f),   \
          std::forward<Args>(args)...);                                      \
      log->LogMessage(msg);                                                  \
    }                                                                        \
  }                                                                          \
                                                                             \
  static inline void name##Msg(const libcomp::String& _msg) {                \
    auto log = libcomp::Log::GetSingletonPtr();                              \
                                                                             \
    if (log->ShouldLog(libcomp::LogComponent_t::comp, level)) {              \
      auto msg = new libcomp::LogMessageFixed(libcomp::LogComponent_t::comp, \
                                              level, _msg);                  \
      log->LogMessage(msg);                                                  \
    }                                                                        \
  }

/**
 * Macro to create a set of log functions for a component
 * @param comp Component to create the functions for
 */
#define LOG_FUNCTIONS(comp)                                               \
  LOG_FUNCTION(Log##comp##Debug, comp, libcomp::Log::LOG_LEVEL_DEBUG)     \
  LOG_FUNCTION(Log##comp##Info, comp, libcomp::Log::LOG_LEVEL_INFO)       \
  LOG_FUNCTION(Log##comp##Warning, comp, libcomp::Log::LOG_LEVEL_WARNING) \
  LOG_FUNCTION(Log##comp##Error, comp, libcomp::Log::LOG_LEVEL_ERROR)     \
  LOG_FUNCTION(Log##comp##Critical, comp, libcomp::Log::LOG_LEVEL_CRITICAL)

// Add a log function set for each component here!
LOG_FUNCTIONS(AccountManager)
LOG_FUNCTIONS(ActionManager)
LOG_FUNCTIONS(AIManager)
LOG_FUNCTIONS(Barter)
LOG_FUNCTIONS(Bazaar)
LOG_FUNCTIONS(CharacterManager)
LOG_FUNCTIONS(ChatManager)
LOG_FUNCTIONS(Clan)
LOG_FUNCTIONS(Connection)
LOG_FUNCTIONS(Crypto)
LOG_FUNCTIONS(Database)
LOG_FUNCTIONS(DataStore)
LOG_FUNCTIONS(DataSyncManager)
LOG_FUNCTIONS(DefinitionManager)
LOG_FUNCTIONS(Demon)
LOG_FUNCTIONS(EventManager)
LOG_FUNCTIONS(Friend)
LOG_FUNCTIONS(FusionManager)
LOG_FUNCTIONS(General)
LOG_FUNCTIONS(Item)
LOG_FUNCTIONS(MatchManager)
LOG_FUNCTIONS(Packet)
LOG_FUNCTIONS(Party)
LOG_FUNCTIONS(ScriptEngine)
LOG_FUNCTIONS(Server)
LOG_FUNCTIONS(ServerConstants)
LOG_FUNCTIONS(ServerDataManager)
LOG_FUNCTIONS(SkillManager)
LOG_FUNCTIONS(Team)
LOG_FUNCTIONS(TokuseiManager)
LOG_FUNCTIONS(Trade)
LOG_FUNCTIONS(WebAPI)
LOG_FUNCTIONS(ZoneManager)

#endif  // LIBCOMP_SRC_LOG_H
