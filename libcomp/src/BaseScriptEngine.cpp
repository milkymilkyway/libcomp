/**
 * @file libcomp/src/BaseScriptEngine.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Class to manage Squirrel scripting.
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

#include "BaseScriptEngine.h"

#ifndef EXOTIC_PLATFORM

// libcomp Includes
#include "BaseConstants.h"
#include "BaseLog.h"
#include "BaseServer.h"
#include "Crypto.h"
#include "Database.h"

// Squirrel Library Includes
#include <sqstdaux.h>
#include <sqstdmath.h>
#include <sqstdstring.h>

#include <cstdarg>
#include <cstdio>

using namespace libcomp;
using namespace Sqrat;

const SQInteger ONE_PARAM = 1;
const SQBool NO_RETURN_VALUE = SQFalse;
const SQBool RAISE_ERROR = SQTrue;

std::unordered_map<std::string, std::function<bool(BaseScriptEngine&,
                                                   const std::string& module)>>
    BaseScriptEngine::mModules;

static bool ScriptInclude(HSQUIRRELVM vm, const char* szPath) {
  return BaseScriptEngine::Self(vm)->Include(szPath);
}

static bool ScriptImport(HSQUIRRELVM vm, const char* szModule) {
  return BaseScriptEngine::Self(vm)->Import(szModule);
}

static void SquirrelPrintFunction(HSQUIRRELVM vm, const SQChar* szFormat, ...) {
  (void)vm;

  va_list args;

  va_start(args, szFormat);
  int bytesNeeded = vsnprintf(NULL, 0, szFormat, args);
  va_end(args);

  char* szBuffer = new char[bytesNeeded + 1];
  szBuffer[0] = 0;

  va_start(args, szFormat);
  vsnprintf(szBuffer, (size_t)bytesNeeded + 1, szFormat, args);
  va_end(args);

  std::list<String> messages = String(szBuffer).Split("\n");

  for (String msg : messages) {
    LogScriptEngineInfo([&]() { return String("SQUIRREL: %1\n").Arg(msg); });
  }

  delete[] szBuffer;
}

static void SquirrelErrorFunction(HSQUIRRELVM vm, const SQChar* szFormat, ...) {
  (void)vm;

  va_list args;

  va_start(args, szFormat);
  int bytesNeeded = vsnprintf(NULL, 0, szFormat, args);
  va_end(args);

  char* szBuffer = new char[bytesNeeded + 1];
  szBuffer[0] = 0;

  va_start(args, szFormat);
  vsnprintf(szBuffer, (size_t)bytesNeeded + 1, szFormat, args);
  va_end(args);

  std::list<String> messages = String(szBuffer).Split("\n");

  for (String msg : messages) {
    LogScriptEngineError([&]() { return String("SQUIRREL: %1\n").Arg(msg); });
  }

  delete[] szBuffer;
}

static void SquirrelPrintFunctionRaw(HSQUIRRELVM vm, const SQChar* szFormat,
                                     ...) {
  (void)vm;

  va_list args;

  va_start(args, szFormat);
  int bytesNeeded = vsnprintf(NULL, 0, szFormat, args);
  va_end(args);

  char* szBuffer = new char[bytesNeeded + 1];
  szBuffer[0] = 0;

  va_start(args, szFormat);
  vsnprintf(szBuffer, (size_t)bytesNeeded + 1, szFormat, args);
  va_end(args);

  std::list<String> messages = String(szBuffer).Split("\n");

  LogScriptEngineInfoMsg(szBuffer);

  delete[] szBuffer;
}

static void SquirrelErrorFunctionRaw(HSQUIRRELVM vm, const SQChar* szFormat,
                                     ...) {
  (void)vm;

  va_list args;

  va_start(args, szFormat);
  int bytesNeeded = vsnprintf(NULL, 0, szFormat, args);
  va_end(args);

  char* szBuffer = new char[bytesNeeded + 1];
  szBuffer[0] = 0;

  va_start(args, szFormat);
  vsnprintf(szBuffer, (size_t)bytesNeeded + 1, szFormat, args);
  va_end(args);

  std::list<String> messages = String(szBuffer).Split("\n");

  for (String msg : messages) {
    LogScriptEngineErrorMsg(msg + "\n");
  }

  delete[] szBuffer;
}

BaseScriptEngine::BaseScriptEngine(bool useRawPrint)
    : mUseRawPrint(useRawPrint) {
  if (mModules.empty()) {
    InitializeBuiltins();
  }

  mVM = sq_open(SQUIRREL_STACK_SIZE);

  sq_setforeignptr(mVM, this);
  sqstd_seterrorhandlers(mVM);
  sq_setcompilererrorhandler(
      mVM, [](HSQUIRRELVM vm, const SQChar* szDescription,
              const SQChar* szSource, SQInteger line, SQInteger column) {
        (void)vm;

        LogScriptEngineError([&]() {
          return String("Failed to compile Squirrel script: %1:%2:%3:  %4\n")
              .Arg(szSource)
              .Arg((int64_t)line)
              .Arg((int64_t)column)
              .Arg(szDescription);
        });
      });
  if (useRawPrint) {
    sq_setprintfunc(mVM, &SquirrelPrintFunctionRaw, &SquirrelErrorFunctionRaw);
  } else {
    sq_setprintfunc(mVM, &SquirrelPrintFunction, &SquirrelErrorFunction);
  }

  sq_pushroottable(mVM);
  sqstd_register_mathlib(mVM);
  sqstd_register_stringlib(mVM);
  sqstd_register_bloblib(mVM);

  Sqrat::RootTable(mVM).VMFunc("include", ScriptInclude);
  Sqrat::RootTable(mVM).VMFunc("import", ScriptImport);

  // These are required by most things so just bind them now.
  Using<Sqrat::s64>();
  Using<Sqrat::u64>();
}

BaseScriptEngine::~BaseScriptEngine() { sq_close(mVM); }

bool BaseScriptEngine::Eval(const String& source, const String& sourceName) {
  bool result = false;

  SQInteger top = sq_gettop(mVM);

  if (SQ_SUCCEEDED(sq_compilebuffer(mVM, source.C(), (SQInteger)source.Size(),
                                    sourceName.C(), 1))) {
    sq_pushroottable(mVM);

    if (SQ_SUCCEEDED(sq_call(mVM, ONE_PARAM, NO_RETURN_VALUE, RAISE_ERROR))) {
      result = true;
    }
  }

  sq_settop(mVM, top);

  return result;
}

HSQUIRRELVM BaseScriptEngine::GetVM() { return mVM; }

std::shared_ptr<BaseScriptEngine> BaseScriptEngine::Self() {
  return shared_from_this();
}

std::shared_ptr<const BaseScriptEngine> BaseScriptEngine::Self() const {
  return shared_from_this();
}

std::shared_ptr<BaseScriptEngine> BaseScriptEngine::Self(HSQUIRRELVM vm) {
  BaseScriptEngine* pScriptEngine = (BaseScriptEngine*)sq_getforeignptr(vm);

  if (pScriptEngine) {
    return pScriptEngine->Self();
  }

  return {};
}

bool BaseScriptEngine::BindingExists(const std::string& name,
                                     bool lockBinding) {
  bool result = mBindings.find(name) != mBindings.end();
  if (!result && lockBinding) {
    mBindings.insert(name);
  }

  return result;
}

bool BaseScriptEngine::Include(const std::string& path) {
  std::vector<char> file = libcomp::Crypto::LoadFile(path);

  LogScriptEngineInfo([&]() { return String("Include: %1\n").Arg(path); });

  if (file.empty()) {
    auto msg = libcomp::String("Failed to include script file: %1\n").Arg(path);

    if (mUseRawPrint) {
      printf("%s", msg.C());
    } else {
      LogScriptEngineErrorMsg(msg);
    }

    return false;
  }

  file.push_back(0);

  if (!Eval(&file[0], path)) {
    auto msg = libcomp::String("Failed to run script file: %1\n").Arg(path);

    if (mUseRawPrint) {
      printf("%s", msg.C());
    } else {
      LogScriptEngineErrorMsg(msg);
    }

    return false;
  }

  return true;
}

bool BaseScriptEngine::Import(const std::string& module) {
  bool result = mImports.find(module) != mImports.end();

  if (result) {
    LogScriptEngineWarning([&]() {
      return String("Module has already been imported: %s\n").Arg(module);
    });

    return false;
  }

  auto it = mModules.find(module);

  if (mModules.end() == it) {
    LogScriptEngineError([&]() {
      return String("Failed to import script module: %1\n").Arg(module);
    });

    return false;
  }

  result = (it->second)(*this, module);

  if (result) {
    mImports.insert(module);
  }

  return result;
}

void BaseScriptEngine::RegisterModule(
    const std::string& module,
    const std::function<bool(BaseScriptEngine&, const std::string& module)>&
        func) {
  mModules[module] = func;
}

void BaseScriptEngine::InitializeBuiltins() {
  RegisterModule(
      "database",
      [](BaseScriptEngine& engine, const std::string& module) -> bool {
        (void)module;

        engine.Using<Database>();
        engine.InitializeDatabaseBuiltins();

        return true;
      });

  RegisterModule(
      "server",
      [](BaseScriptEngine& engine, const std::string& module) -> bool {
        (void)module;

        engine.Using<BaseServer>();
        engine.InitializeServerBuiltins();

        return true;
      });

  InitializeOtherBuiltins();
}

#endif  // !EXOTIC_PLATFORM
