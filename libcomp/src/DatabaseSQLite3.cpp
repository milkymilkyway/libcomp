/**
 * @file libcomp/src/DatabaseSQLite3.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Class to handle an SQLite3 database.
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

#include "DatabaseSQLite3.h"

#ifndef EXOTIC_PLATFORM

// libcomp Includes
#include "BaseLog.h"
#include "DataStore.h"
#include "Database.h"
#include "DatabaseBind.h"
#include "DatabaseQuerySQLite3.h"

// SQLite3 Includes
#include <sqlite3.h>

using namespace libcomp;

DatabaseSQLite3::DatabaseSQLite3(
    const std::shared_ptr<objects::DatabaseConfigSQLite3>& config)
    : Database(std::dynamic_pointer_cast<objects::DatabaseConfig>(config)),
      mDatabase(nullptr) {}

DatabaseSQLite3::~DatabaseSQLite3() { Close(); }

bool DatabaseSQLite3::Open() {
  auto filepath = GetFilepath();

  bool result = true;

  if (SQLITE_OK != sqlite3_open(filepath.C(), &mDatabase)) {
    result = false;

    LogDatabaseError([&]() {
      return String("Failed to open database connection: %1\n")
          .Arg(sqlite3_errmsg(mDatabase));
    });

    (void)Close();
  }

  return result;
}

bool DatabaseSQLite3::Close() {
  bool result = true;

  if (nullptr != mDatabase) {
    if (SQLITE_OK != sqlite3_close(mDatabase)) {
      result = false;

      LogDatabaseErrorMsg("Failed to close database connection.\n");
    }

    mDatabase = nullptr;
  }

  return result;
}

bool DatabaseSQLite3::IsOpen() const { return nullptr != mDatabase; }

DatabaseQuery DatabaseSQLite3::Prepare(const String& query) {
  auto config =
      std::dynamic_pointer_cast<objects::DatabaseConfigSQLite3>(mConfig);
  return DatabaseQuery(
      new DatabaseQuerySQLite3(mDatabase, config->GetMaxRetryCount(),
                               config->GetRetryDelay()),
      query);
}

bool DatabaseSQLite3::Exists() {
  auto filepath = GetFilepath();

  // Check if the database file exists
  if (FILE* file = fopen(filepath.C(), "r")) {
    fclose(file);
    return true;
  } else {
    return false;
  }
}

bool DatabaseSQLite3::Setup(bool rebuild,
                            const std::shared_ptr<BaseServer>& server,
                            const std::shared_ptr<BaseScriptEngine>& engine,
                            DataStore* pDataStore,
                            const std::string& migrationDirectory) {
  if (!IsOpen()) {
    LogDatabaseErrorMsg("Trying to setup a database that is not open!\n");

    return false;
  }

  auto filename =
      std::dynamic_pointer_cast<objects::DatabaseConfigSQLite3>(mConfig)
          ->GetDatabaseName();
  if (!Exists()) {
    LogDatabaseErrorMsg("Database file was not created!\n");
  }

  if (UsingDefaultDatabaseType()) {
    std::list<std::unordered_map<std::string, std::vector<char>>> results;
    auto q = Prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = "
        "'objects';");
    if (!q.IsValid() || !q.Execute() || !q.GetRows(results)) {
      LogDatabaseErrorMsg("Failed to query the master table for schema.\n");

      return false;
    }

    if (results.size() == 0 &&
        !Execute("CREATE TABLE IF NOT EXISTS objects (uid string PRIMARY KEY, "
                 "member_vars blob);")) {
      LogDatabaseErrorMsg("Failed to create the objects table.\n");

      return false;
    }
  }

  LogDatabaseDebug([&]() {
    return String("Database connection established to '%1' file.\n")
        .Arg(filename);
  });

  if (!VerifyAndSetupSchema(rebuild)) {
    LogDatabaseErrorMsg("Schema verification and setup failed.\n");

    return false;
  }

  if (!TableExists("Migrations")) {
    std::stringstream ss;
    ss << "CREATE TABLE IF NOT EXISTS `Migrations` "
       << "(`Migration` varchar(128) PRIMARY KEY);";

    if (Execute(ss.str())) {
      LogDatabaseInfoMsg("Migration table created.\n");
    } else {
      LogDatabaseErrorMsg("Failed to create the migration table!\n");

      return false;
    }
  }

  // Handle migrations if the data store exists.
  if (pDataStore) {
    std::list<libcomp::String> files;
    std::list<libcomp::String> dirs;
    std::list<libcomp::String> symLinks;

    if (pDataStore->GetListing(migrationDirectory, files, dirs, symLinks)) {
      files.sort();

      for (auto file : files) {
        if (file.Right(4) != ".nut") {
          continue;
        }

        libcomp::String migration = file.Left(file.Length() - 4);

        auto query = Prepare(
            "SELECT COUNT(`Migration`) FROM `Migrations` WHERE `Migration` = "
            ":file");

        if (!query.IsValid() || !query.Bind("file", migration)) {
          LogDatabaseErrorMsg("Failed to bind when checking for migration.\n");

          return false;
        }

        if (!query.Execute() || !query.Next()) {
          LogDatabaseErrorMsg(
              "Failed to execute query when checking for migration.\n");

          return false;
        }

        int64_t count = 0;

        if (!query.GetValue("COUNT(`Migration`)", count)) {
          LogDatabaseErrorMsg(
              "Failed to get value from query when checking for migration.\n");
          LogDatabaseDebugMsg(GetLastError());

          return false;
        }

        auto path = libcomp::String("%1/%2").Arg(migrationDirectory).Arg(file);

        if (!count) {
          if (ApplyMigration(server, engine, pDataStore, migration, path)) {
            query =
                Prepare("INSERT INTO `Migrations` (`Migration`) VALUES(:file)");

            if (!query.IsValid() || !query.Bind("file", migration) ||
                !query.Execute()) {
              LogDatabaseErrorMsg(
                  "Failed to insert migration into database.\n");

              return false;
            }
          } else {
            return false;
          }
        }
      }
    } else {
      LogDatabaseErrorMsg("Migration directory does not exist!\n");

      return false;
    }
  }

  return true;
}

bool DatabaseSQLite3::Use() {
  // Since each database is its own file there is nothing to do here.
  return true;
}

bool DatabaseSQLite3::TableHasRows(const String& table) {
  return Database::TableHasRows(table.ToLower());
}

std::list<std::shared_ptr<PersistentObject>> DatabaseSQLite3::LoadObjects(
    size_t typeHash, DatabaseBind* pValue) {
  std::list<std::shared_ptr<PersistentObject>> objects;

  auto metaObject = PersistentObject::GetRegisteredMetadata(typeHash);

  if (nullptr == metaObject) {
    LogDatabaseErrorMsg("Failed to lookup MetaObject.\n");

    return {};
  }

  String sql =
      String("SELECT * FROM %1%2")
          .Arg(metaObject->GetName())
          .Arg((nullptr != pValue
                    ? String(" WHERE %1 = :%1").Arg(pValue->GetColumn())
                    : ""));

  DatabaseQuery query = Prepare(sql);

  if (!query.IsValid()) {
    LogDatabaseError(
        [&]() { return String("Failed to prepare SQL query: %1\n").Arg(sql); });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return {};
  }

  if (nullptr != pValue && !pValue->Bind(query)) {
    LogDatabaseError([&]() {
      return String("Failed to bind value: %1\n").Arg(pValue->GetColumn());
    });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return {};
  }

  if (!query.Execute()) {
    LogDatabaseError(
        [&]() { return String("Failed to execute query: %1\n").Arg(sql); });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return {};
  }

  int failures = 0;

  while (query.Next()) {
    auto obj = LoadSingleObjectFromRow(typeHash, query);

    if (nullptr != obj) {
      objects.push_back(obj);
    } else {
      failures++;
    }
  }

  if (failures > 0) {
    LogDatabaseError([&]() {
      return String("%1 '%2' row%3 failed to load.\n")
          .Arg(failures)
          .Arg(metaObject->GetName())
          .Arg(failures != 1 ? "s" : "");
    });
  }

  return objects;
}

bool DatabaseSQLite3::InsertSingleObject(
    std::shared_ptr<PersistentObject>& obj) {
  auto metaObject = obj->GetObjectMetadata();

  std::stringstream objstream;
  if (!obj->Save(objstream)) {
    return false;
  }

  if (obj->GetUUID().IsNull() && !obj->Register(obj)) {
    return false;
  }

  std::list<String> columnNames;
  columnNames.push_back("UID");

  std::list<String> columnBinds;
  columnBinds.push_back(":UID");

  auto values = obj->GetMemberBindValues(true);

  for (auto value : values) {
    auto columnName = value->GetColumn();
    columnNames.push_back(columnName);
    columnBinds.push_back(String(":%1").Arg(columnName));
  }

  String sql = String("INSERT INTO %1 (%2) VALUES (%3);")
                   .Arg(metaObject->GetName())
                   .Arg(String::Join(columnNames, ", "))
                   .Arg(String::Join(columnBinds, ", "));

  DatabaseQuery query = Prepare(sql);

  if (!query.IsValid()) {
    LogDatabaseError(
        [&]() { return String("Failed to prepare SQL query: %1\n").Arg(sql); });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  if (!query.Bind("UID", obj->GetUUID())) {
    LogDatabaseErrorMsg("Failed to bind value: UID\n");

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  for (auto value : values) {
    if (!value->Bind(query)) {
      LogDatabaseError([&]() {
        return String("Failed to bind value: %1\n").Arg(value->GetColumn());
      });

      LogDatabaseError(
          [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

      return false;
    }

    delete value;
  }

  if (!query.Execute()) {
    LogDatabaseError(
        [&]() { return String("Failed to execute query: %1\n").Arg(sql); });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  return true;
}

bool DatabaseSQLite3::UpdateSingleObject(
    std::shared_ptr<PersistentObject>& obj) {
  auto metaObject = obj->GetObjectMetadata();

  std::stringstream objstream;
  if (!obj->Save(objstream)) {
    return false;
  }

  if (obj->GetUUID().IsNull()) {
    return false;
  }

  auto values = obj->GetMemberBindValues();
  if (values.size() == 0) {
    // Nothing updated, nothing to do
    return true;
  }

  std::list<String> columnNames;

  for (auto value : values) {
    columnNames.push_back(String("%1 = :%1").Arg(value->GetColumn()));
  }

  String sql = String("UPDATE %1 SET %2 WHERE UID = :UID;")
                   .Arg(metaObject->GetName())
                   .Arg(String::Join(columnNames, ", "));

  DatabaseQuery query = Prepare(sql);

  if (!query.IsValid()) {
    LogDatabaseError(
        [&]() { return String("Failed to prepare SQL query: %1\n").Arg(sql); });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  if (!query.Bind("UID", obj->GetUUID())) {
    LogDatabaseErrorMsg("Failed to bind value: UID\n");

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  for (auto value : values) {
    if (!value->Bind(query)) {
      LogDatabaseError([&]() {
        return String("Failed to bind value: %1\n").Arg(value->GetColumn());
      });

      LogDatabaseError(
          [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

      return false;
    }

    delete value;
  }

  if (!query.Execute()) {
    LogDatabaseError(
        [&]() { return String("Failed to execute query: %1\n").Arg(sql); });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  return true;
}

bool DatabaseSQLite3::DeleteObjects(
    std::list<std::shared_ptr<PersistentObject>>& objs) {
  std::unordered_map<std::shared_ptr<libobjgen::MetaObject>,
                     std::list<std::shared_ptr<PersistentObject>>>
      metaObjectMap;
  for (auto obj : objs) {
    auto metaObj = obj->GetObjectMetadata();
    metaObjectMap[metaObj].push_back(obj);
  }

  for (auto mPair : metaObjectMap) {
    auto metaObject = mPair.first;

    std::list<String> uidBindings;
    for (auto obj : mPair.second) {
      auto uuid = obj->GetUUID();
      if (uuid.IsNull()) {
        return false;
      }

      obj->Unregister();

      std::string uuidStr = obj->GetUUID().ToString();
      uidBindings.push_back(String("'%1'").Arg(uuidStr));
    }

    if (!Execute(String("DELETE FROM %1 WHERE UID in (%2);")
                     .Arg(metaObject->GetName())
                     .Arg(String::Join(uidBindings, ", ")))) {
      return false;
    }
  }

  return true;
}

bool DatabaseSQLite3::VerifyAndSetupSchema(bool recreateTables) {
  auto metaObjectTables = GetMappedObjects();
  if (metaObjectTables.size() == 0) {
    return true;
  }

  LogDatabaseInfoMsg("Verifying database table structure.\n");

  DatabaseQuery q = Prepare(
      "SELECT name, type, tbl_name FROM sqlite_master where type in ('table', "
      "'index') and name <> 'objects';");
  if (!q.Execute()) {
    LogDatabaseCriticalMsg("Failed to query for existing columns.\n");

    return false;
  }

  std::unordered_map<std::string, std::unordered_map<std::string, String>>
      fieldMap;
  std::unordered_map<std::string, std::set<std::string>> indexedFields;
  while (q.Next()) {
    String name;
    String type;

    if (!q.GetValue("name", name) || !q.GetValue("type", type)) {
      LogDatabaseCritical([&]() {
        return String(
                   "Invalid query results returned from sqlite_master table.\n")
            .Arg(name);
      });

      return false;
    }

    if (type == "table") {
      std::unordered_map<std::string, String>& m = fieldMap[name.ToUtf8()];

      DatabaseQuery sq = Prepare(String("PRAGMA table_info('%1');").Arg(name));
      if (!sq.Execute() || !sq.Next()) {
        LogDatabaseCritical([&]() {
          return String("Failed to query for '%1' columns.\n").Arg(name);
        });

        return false;
      }

      do {
        String colName;
        String dataType;

        if (sq.GetValue("name", colName) && sq.GetValue("type", dataType)) {
          m[colName.ToUtf8()] = dataType;
        }
      } while (sq.Next());
    } else if (type == "index") {
      String tableName;

      if (q.GetValue("tbl_name", tableName)) {
        std::set<std::string>& s = indexedFields[tableName.ToUtf8()];
        s.insert(name.ToUtf8());
      }
    }
  }

  for (auto metaObjectTable : metaObjectTables) {
    auto metaObject = *metaObjectTable.get();
    auto objName = metaObject.GetName();

    std::vector<std::shared_ptr<libobjgen::MetaVariable>> vars;
    for (auto iter = metaObject.VariablesBegin();
         iter != metaObject.VariablesEnd(); iter++) {
      String type = GetVariableType(*iter);
      if (type.IsEmpty()) {
        LogDatabaseError([&]() {
          return String("Unsupported field type encountered: %1\n")
              .Arg((*iter)->GetCodeType());
        });

        return false;
      }
      vars.push_back(*iter);
    }

    bool creating = false;
    bool recreating = false;
    bool updating = false;
    std::set<std::string> needsIndex;
    auto tableIter = fieldMap.find(objName);
    if (tableIter == fieldMap.end()) {
      creating = true;
    } else {
      recreating = recreateTables;

      std::unordered_map<std::string, String> columns = tableIter->second;

      auto indexes = indexedFields[objName];
      columns.erase("UID");
      for (auto var : vars) {
        auto name = var->GetName();
        auto type = GetVariableType(var);

        if (columns.find(name) == columns.end()) {
          updating = true;
        } else if (columns[name] != type) {
          recreating = true;
        }

        auto indexName = String("idx_%1_%2").Arg(objName).Arg(name).ToUtf8();
        if (var->IsLookupKey() && indexes.find(indexName) == indexes.end()) {
          needsIndex.insert(name);
        }
      }
    }

    if (recreating) {
      if (mConfig->GetAutoSchemaUpdate()) {
        LogDatabaseInfo([&]() {
          return String("Dropping table '%1'...\n").Arg(metaObject.GetName());
        });

        if (Execute(String("DROP TABLE %1;").Arg(objName))) {
          LogDatabaseInfoMsg("Re-creation complete\n");
        } else {
          LogDatabaseErrorMsg("Re-creation failed\n");

          return false;
        }

        creating = true;
      } else {
        LogDatabaseError([&]() {
          return String(
                     "The schema for '%1' does not match and cannot be used "
                     "until it has been corrected!\n")
              .Arg(metaObject.GetName());
        });

        return false;
      }
    }

    if (creating) {
      LogDatabaseInfo([&]() {
        return String("Creating table '%1'...\n").Arg(metaObject.GetName());
      });

      bool success = false;

      std::stringstream ss;
      ss << "CREATE TABLE IF NOT EXISTS " << objName
         << " (UID string PRIMARY KEY";
      for (size_t i = 0; i < vars.size(); i++) {
        auto var = vars[i];
        String type = GetVariableType(var);

        ss << "," << std::endl << var->GetName() << " " << type;
      }
      ss << ");";

      success = Execute(ss.str());

      if (success) {
        LogDatabaseInfoMsg("Creation complete\n");
      } else {
        LogDatabaseErrorMsg("Creation failed\n");

        return false;
      }
    } else if (updating) {
      LogDatabaseInfo([&]() {
        return String("Updating table '%1'...\n").Arg(metaObject.GetName());
      });

      auto objColumns = fieldMap[objName];

      bool hashExists;
      size_t typeHash =
          PersistentObject::GetTypeHashByName(metaObject.GetName(), hashExists);

      auto emptyObj = PersistentObject::New(typeHash);

      std::unordered_map<std::string, DatabaseBind*> defaultVals;
      for (auto val : emptyObj->GetMemberBindValues(true)) {
        defaultVals[val->GetColumn().C()] = val;
      }

      for (size_t i = 0; i < vars.size(); i++) {
        auto var = vars[i];
        auto col = defaultVals[var->GetName()];
        String type = GetVariableType(var);
        if (col && objColumns.find(var->GetName()) == objColumns.end()) {
          if (Execute(String("ALTER TABLE %1 ADD %2 %3;")
                          .Arg(objName)
                          .Arg(var->GetName())
                          .Arg(type))) {
            LogDatabaseInfo([&]() {
              return String("Created column '%1'\n").Arg(var->GetName());
            });
          } else {
            LogDatabaseError([&]() {
              return String("Failed to create column '%1'\n")
                  .Arg(var->GetName());
            });

            return false;
          }

          q = Prepare(String("UPDATE %1 SET %2 = :%3;")
                          .Arg(metaObject.GetName())
                          .Arg(col->GetColumn())
                          .Arg(col->GetColumn()));
          if (!col->Bind(q)) {
            LogDatabaseWarning([&]() {
              return String("Failed to bind default value for column '%1'\n")
                  .Arg(col->GetColumn());
            });
          }

          if (q.Execute()) {
            LogDatabaseInfo([&]() {
              return String(
                         "Created and applied default value to column '%1'\n")
                  .Arg(col->GetColumn());
            });
          } else {
            LogDatabaseError([&]() {
              return String("Failed to apply default value to column '%1'\n")
                  .Arg(col->GetColumn());
            });

            return false;
          }
        }
      }
    }

    // If we made the table or are missing an index, make them now
    if (needsIndex.size() > 0 || creating) {
      for (size_t i = 0; i < vars.size(); i++) {
        auto var = vars[i];

        if (!var->IsLookupKey() ||
            (!creating &&
             needsIndex.find(var->GetName()) == needsIndex.end())) {
          continue;
        }

        auto indexStr = String("idx_%1_%2").Arg(objName).Arg(var->GetName());

        auto cmd = String("CREATE INDEX %1 ON %2(%3);")
                       .Arg(indexStr)
                       .Arg(objName)
                       .Arg(var->GetName());

        if (Execute(cmd)) {
          LogDatabaseInfo([&]() {
            return String("Created '%1' column index.\n").Arg(indexStr);
          });
        } else {
          LogDatabaseError([&]() {
            return String("Creation of '%1' column index failed.\n")
                .Arg(indexStr);
          });

          return false;
        }
      }
    }

    if (!creating && !recreating && !updating && needsIndex.size() == 0) {
      LogDatabaseInfo([&]() {
        return String("'%1': Verified\n").Arg(metaObject.GetName());
      });
    }
  }

  LogDatabaseInfoMsg("Database verification complete.\n");

  return true;
}

bool DatabaseSQLite3::ProcessStandardChangeSet(
    const std::shared_ptr<DBStandardChangeSet>& changes) {
  libcomp::String transactionID = libcomp::String("_%1").Arg(
      libcomp::String(libobjgen::UUID::Random().ToString()).Replace("-", "_"));
  if (!Prepare(libcomp::String("BEGIN TRANSACTION %1").Arg(transactionID))
           .Execute()) {
    return false;
  }

  bool result = true;
  for (auto obj : changes->GetInserts()) {
    if (!InsertSingleObject(obj)) {
      result = false;
      break;
    }
  }

  if (result) {
    for (auto obj : changes->GetUpdates()) {
      if (!UpdateSingleObject(obj)) {
        result = false;
        break;
      }
    }
  }

  auto deletes = changes->GetDeletes();
  if (result && deletes.size()) {
    result = DeleteObjects(deletes);
  }

  if (result) {
    if (!Prepare(libcomp::String("COMMIT TRANSACTION %1").Arg(transactionID))
             .Execute()) {
      return false;
    }
  } else {
    if (!Prepare(libcomp::String("ROLLBACK TRANSACTION %1").Arg(transactionID))
             .Execute()) {
      // If this happens the server may need to be shut down
      LogDatabaseCriticalMsg("Rollback failed!\n");

      return false;
    }
  }

  return result;
}

bool DatabaseSQLite3::ProcessOperationalChangeSet(
    const std::shared_ptr<DBOperationalChangeSet>& changes) {
  libcomp::String transactionID = libcomp::String("_%1").Arg(
      libcomp::String(libobjgen::UUID::Random().ToString()).Replace("-", "_"));
  if (!Prepare(libcomp::String("BEGIN TRANSACTION %1").Arg(transactionID))
           .Execute()) {
    return false;
  }

  bool result = true;
  std::set<std::shared_ptr<libcomp::PersistentObject>> objs;
  for (auto op : changes->GetOperations()) {
    auto obj = op->GetRecord();
    switch (op->GetType()) {
      case DBOperationalChange::DBOperationType::DBOP_INSERT:
        result &= InsertSingleObject(obj);
        break;
      case DBOperationalChange::DBOperationType::DBOP_UPDATE:
        result &= UpdateSingleObject(obj);
        break;
      case DBOperationalChange::DBOperationType::DBOP_DELETE:
        result &= DeleteSingleObject(obj);
        break;
      case DBOperationalChange::DBOperationType::DBOP_EXPLICIT:
        objs.insert(obj);
        result &= ProcessExplicitUpdate(
            std::dynamic_pointer_cast<DBExplicitUpdate>(op));
        break;
    }

    if (!result) {
      break;
    }
  }

  if (result) {
    if (!Prepare(libcomp::String("COMMIT TRANSACTION %1").Arg(transactionID))
             .Execute()) {
      return false;
    }
  } else {
    if (!Prepare(libcomp::String("ROLLBACK TRANSACTION %1").Arg(transactionID))
             .Execute()) {
      // If this happens the server may need to be shut down
      LogDatabaseCriticalMsg("Rollback failed!\n");

      return false;
    }
  }

  if (result) {
    for (auto obj : objs) {
      auto bind = new DatabaseBindUUID("UID", obj->GetUUID());
      result = nullptr != LoadSingleObject(
                              libcomp::PersistentObject::GetTypeHashByName(
                                  obj->GetObjectMetadata()->GetName(), result),
                              bind);

      if (!result) {
        break;
      }
    }
  }

  return result;
}

bool DatabaseSQLite3::ProcessExplicitUpdate(
    const std::shared_ptr<DBExplicitUpdate>& update) {
  auto obj = update->GetRecord();
  auto expectedVals = update->GetExpectedValues();
  auto changedVals = update->GetChanges();
  if (changedVals.size() == 0) {
    return false;
  }

  size_t idx = 1;
  std::list<String> updateClause;
  std::list<String> whereClause;
  // Bind the update clause values
  for (auto cPair : changedVals) {
    auto it = expectedVals.find(cPair.first);
    if (it == expectedVals.end()) {
      return false;
    }

    updateClause.push_back(String("%1 = ?%2").Arg(cPair.first).Arg(idx++));
  }

  auto uidIdx = idx++;

  // Now bind the where clause values
  for (auto cPair : changedVals) {
    whereClause.push_back(String("%1 = ?%2").Arg(cPair.first).Arg(idx++));
  }

  String sql = String("UPDATE `%1` SET %2 WHERE `UID` = :%3 AND %4;")
                   .Arg(obj->GetObjectMetadata()->GetName())
                   .Arg(String::Join(updateClause, ", "))
                   .Arg(uidIdx)
                   .Arg(String::Join(whereClause, " AND "));

  DatabaseQuery query = Prepare(sql);

  if (!query.IsValid()) {
    LogDatabaseError(
        [&]() { return String("Failed to prepare SQL query: %1\n").Arg(sql); });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  idx = 1;
  for (auto cPair : changedVals) {
    if (!cPair.second->Bind(query, idx++)) {
      LogDatabaseError([&]() {
        return String("Failed to bind value: %1\n").Arg(cPair.first);
      });

      LogDatabaseError(
          [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

      return false;
    }
  }

  if (!query.Bind(idx++, obj->GetUUID())) {
    LogDatabaseErrorMsg("Failed to bind value: UID\n");

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  for (auto cPair : changedVals) {
    if (!expectedVals[cPair.first]->Bind(query, idx++)) {
      LogDatabaseError([&]() {
        return String("Failed to bind where clause for value: %1\n")
            .Arg(cPair.first);
      });

      LogDatabaseError(
          [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

      return false;
    }
  }

  if (!query.Execute()) {
    LogDatabaseError(
        [&]() { return String("Failed to execute query: %1\n").Arg(sql); });

    LogDatabaseError(
        [&]() { return String("Database said: %1\n").Arg(GetLastError()); });

    return false;
  }

  return query.AffectedRowCount() == 1;
}

String DatabaseSQLite3::GetFilepath() const {
  auto config =
      std::dynamic_pointer_cast<objects::DatabaseConfigSQLite3>(mConfig);
  auto directory = config->GetFileDirectory();
  auto filename = config->GetDatabaseName();

  return String("%1%2%3.sqlite3")
      .Arg(directory)
      .Arg(directory.Right(1) == "/" ? "" : "/")
      .Arg(filename);
}

String DatabaseSQLite3::GetVariableType(
    const std::shared_ptr<libobjgen::MetaVariable> var) {
  switch (var->GetMetaType()) {
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_STRING:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_REF:
      return "string";
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_BOOL:
      return "bit";
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_S8:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_S16:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_S32:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_U8:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_U16:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_ENUM:
      return "int";
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_U32:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_S64:
      return "bigint";
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_FLOAT:
      return "float";
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_DOUBLE:
      return "double";
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_U64:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_ARRAY:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_LIST:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_MAP:
    case libobjgen::MetaVariable::MetaVariableType_t::TYPE_SET:
    default:
      break;
  }

  return "blob";
}

bool DatabaseSQLite3::TableExists(const libcomp::String& table) {
  String name;

  auto query = Prepare(
      libcomp::String("SELECT name, type, tbl_name FROM sqlite_master where "
                      "type in ('table', 'index') and name = '%1';")
          .Arg(table));
  if (!query.IsValid() || !query.Execute() || !query.Next() ||
      !query.GetValue("name", name)) {
    return false;
  }

  return name == table;
}

#endif  // !EXOTIC_PLATFORM
