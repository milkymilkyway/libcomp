# This file is part of COMP_hack.
#
# Copyright (C) 2010-2020 COMP_hack Team <compomega@tutanota.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

PROJECT(libcomp)

# Assume built-in pthreads on MacOS
# https://stackoverflow.com/questions/54587052/
IF(APPLE)
    SET(CMAKE_THREAD_LIBS_INIT "-lpthread")
    SET(CMAKE_HAVE_THREADS_LIBRARY 1)
    SET(CMAKE_USE_WIN32_THREADS_INIT 0)
    SET(CMAKE_USE_PTHREADS_INIT 1)
    SET(THREADS_PREFER_PTHREAD_FLAG ON)
ELSE()
    FIND_PACKAGE(Threads REQUIRED)
ENDIF()

MESSAGE("** Configuring ${PROJECT_NAME} **")

# Add a target to generate API documentation.
FILE(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/api/libcomp)
GENERATE_DOCS(doc/Doxyfile.in)

# Add a directory to put the objgen output into.
FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/objgen)

SET(SYSTEM_LIBRARIES "")

IF(BSD)
FIND_PACKAGE(ExecInfo REQUIRED)

SET(SYSTEM_LIBRARIES ${SYSTEM_LIBRARIES} ${EXECINFO_LIBRARY})
ENDIF(BSD)

# Write the version information into the BaseConstants.h file.
CONFIGURE_FILE(src/BaseConstants.h.in
    "${CMAKE_CURRENT_BINARY_DIR}/BaseConstants.h"
    ESCAPE_QUOTES @ONLY NEWLINE_STYLE UNIX)

SET(${PROJECT_NAME}_SRCS
    src/ArgumentParser.cpp
    src/BaseLog.cpp
    src/BaseScriptEngine.cpp
    src/BaseServer.cpp
    src/Compress.cpp
    src/Convert.cpp
    src/Crypto.cpp
    src/CString.cpp
    src/Database.cpp
    src/DatabaseBind.cpp
    src/DatabaseChangeSet.cpp
    src/DatabaseMariaDB.cpp
    src/DatabaseQuery.cpp
    src/DatabaseQueryMariaDB.cpp
    src/DatabaseQuerySQLite3.cpp
    src/DatabaseSQLite3.cpp
    src/DataFile.cpp
    src/DataStore.cpp
    src/DataSyncManager.cpp
    src/DynamicObject.cpp
    src/DynamicVariable.cpp
    src/DynamicVariableFactory.cpp
    src/EncryptedConnection.cpp
    src/Exception.cpp
    src/InternalConnection.cpp
    src/ManagerPacket.cpp
    #src/MemoryFile.cpp
    src/MemoryManager.cpp
    src/MessageConnectionClosed.cpp
    src/MessageEncrypted.cpp
    src/MessageInit.cpp
    src/MessagePacket.cpp
    src/MessagePong.cpp
    src/MessageShutdown.cpp
    src/MessageTimeout.cpp
    src/Mutex.cpp
    src/Object.cpp
    src/Packet.cpp
    src/PacketException.cpp
    #src/PacketScript.cpp
    src/PlatformWindows.cpp
    src/PEFile.cpp
    src/PersistentObject.cpp
    src/Randomizer.cpp
    src/ReadOnlyPacket.cpp
    #src/RingBuffer.cpp
    src/ServerCommandLineParser.cpp
    src/Shutdown.cpp
    src/SqratInt64.cpp
    #src/Structgen.cpp
    src/TcpConnection.cpp
    src/TcpServer.cpp
    #src/ThreadManager.cpp
    src/TimerManager.cpp
    src/WindowsService.cpp
    src/Worker.cpp

    # Red-black tree for memory manager.
    src/rbtree.c

    # ASIO sources for exotic platforms.
    ${ASIO_SRCS}
)

IF(NOT WIN32 AND NOT APPLE AND NOT BUILD_EXOTIC)
    SET(${PROJECT_NAME}_SRCS
        ${${PROJECT_NAME}_SRCS}
        # for comp_manager and testing.
        src/Child.cpp
        src/DayCare.cpp
        src/SpawnThread.cpp
        src/WatchThread.cpp
    )
ENDIF(NOT WIN32 AND NOT APPLE AND NOT BUILD_EXOTIC)

IF(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/BaseConfigCustom.cpp)
    SET(${PROJECT_NAME}_SRCS ${${PROJECT_NAME}_SRCS} src/BaseConfigCustom.cpp)
ELSE()
    SET(${PROJECT_NAME}_SRCS ${${PROJECT_NAME}_SRCS} src/BaseConfig.cpp)
ENDIF()

# This is a list of all header files. Adding the header files here ensures they
# are listed in the source files for IDE projects.
SET(${PROJECT_NAME}_HDRS
    "${CMAKE_CURRENT_BINARY_DIR}/BaseConstants.h"

    src/ArgumentParser.h
    src/BaseLog.h
    src/BaseScriptEngine.h
    src/BaseServer.h
    src/Compress.h
    src/ConnectionMessage.h
    src/Convert.h
    src/CryptSupport.h
    src/CString.h
    src/Database.h
    src/DatabaseBind.h
    src/DatabaseChangeSet.h
    src/DatabaseMariaDB.h
    src/DatabaseQuery.h
    src/DatabaseQueryMariaDB.h
    src/DatabaseQuerySQLite3.h
    src/DatabaseSQLite3.h
    src/DataFile.h
    src/DataStore.h
    src/DataSyncManager.h
    src/Crypto.h
    src/DynamicObject.h
    src/DynamicVariable.h
    src/DynamicVariableFactory.h
    src/DynamicVariableInt.h
    src/EncryptedConnection.h
    src/Endian.h
    src/EnumMap.h
    src/EnumUtils.h
    src/Exception.h
    src/InternalConnection.h
    src/Manager.h
    src/ManagerPacket.h
    #src/MemoryFile.h
    src/MemoryManager.h
    src/Message.h
    src/MessageConnectionClosed.h
    src/MessageEncrypted.h
    src/MessageExecute.h
    src/MessageInit.h
    src/MessagePacket.h
    src/MessagePong.h
    src/MessageQueue.h
    src/MessageShutdown.h
    src/MessageTick.h
    src/MessageTimeout.h
    src/Mutex.h
    src/Object.h
    src/ObjectReference.h
    src/Packet.h
    src/PacketException.h
    src/PacketParser.h
    #src/PacketScript.h
    src/PacketStream.h
    src/PEFile.h
    src/PEFormat.h
    src/PersistentObject.h
    #src/Platform.h
    #src/PlatformLinux.h
    #src/PlatformWindows.h
    src/Randomizer.h
    src/ReadOnlyPacket.h
    src/RingBuffer.h
    src/ServerCommandLineParser.h
    src/Shutdown.h
    src/TcpConnection.h
    src/TcpServer.h
    #src/ThreadManager.h
    src/TimerManager.h
    src/WindowsService.h
    src/Worker.h

    # These were generated and are not worth reading.
    src/LookupTableCP1252.h
    src/LookupTableCP932.h

    # Macros to temporarily disable warnings (wrapped around 3rd party libs).
    src/PushIgnore.h
    src/PopIgnore.h

    # Red-black tree for memory manager.
    src/rbtree.h
)

IF(NOT WIN32 AND NOT APPLE AND NOT BUILD_EXOTIC)
    SET(${PROJECT_NAME}_HDRS
        ${${PROJECT_NAME}_HDRS}
        # for comp_manager and testing.
        src/Child.h
        src/DayCare.h
        src/SpawnThread.h
        src/WatchThread.h
    )
ENDIF(NOT WIN32 AND NOT APPLE AND NOT BUILD_EXOTIC)

SET(${PROJECT_NAME}_SCHEMA
    schema/databaseconfig_mariadb.xml
    schema/databaseconfig_sqlite3.xml
    schema/databaseconfig.xml
    schema/server_command_line.xml
    schema/serverconfig.xml
    schema/test.xml
)

SOURCE_GROUP("objgen" ${CMAKE_CURRENT_BINARY_DIR}/objgen/*)

OBJGEN_XML(${PROJECT_NAME}_STRUCTS
    # Main schema
    schema/libcomp-master.xml

    # Included schemas
    ${${PROJECT_NAME}_SCHEMA}

    # Include paths
    schema

    # Output files
    DatabaseConfig.cpp
    DatabaseConfig.h
    DatabaseConfigMariaDB.cpp
    DatabaseConfigMariaDB.h
    DatabaseConfigSQLite3.cpp
    DatabaseConfigSQLite3.h
    ServerCommandLine.cpp
    ServerCommandLine.h
    ServerConfig.cpp
    ServerConfig.h
    TestObject.cpp
    TestObject.h
    TestObjectA.cpp
    TestObjectA.h
    TestObjectB.cpp
    TestObjectB.h
    TestObjectC.cpp
    TestObjectC.h
    TestObjectD.cpp
    TestObjectD.h
    TestObjectE.cpp
    TestObjectE.h
)

COVERALLS_SOURCES(${${PROJECT_NAME}_SRCS})

ADD_LIBRARY(comp STATIC ${${PROJECT_NAME}_SRCS} ${${PROJECT_NAME}_HDRS}
    ${${PROJECT_NAME}_STRUCTS})

IF(BUILD_EXOTIC)
    SET_SOURCE_FILES_LANGUAGE(${${PROJECT_NAME}_SRCS}
        ${${PROJECT_NAME}_STRUCTS})

    TARGET_COMPILE_DEFINITIONS(comp PUBLIC
        "EXOTIC_HEADER=${EXOTIC_HEADER}"
        "EXOTIC_RANDOM_FUNC=${EXOTIC_RANDOM_FUNC}"
    )
ENDIF(BUILD_EXOTIC)

TARGET_COMPILE_DEFINITIONS(comp PUBLIC ${SQRAT_DEFINES})

IF(USE_MBED_TLS)
    TARGET_COMPILE_DEFINITIONS(comp PUBLIC USE_MBED_TLS=1)
ENDIF(USE_MBED_TLS)

SET_TARGET_PROPERTIES(comp PROPERTIES FOLDER "Libraries")

IF(SYSTEMD_FOUND)
    SET(SYSTEMD_INCLUDES ${SYSTEMD_INCLUDE_DIRS})
ENDIF(SYSTEMD_FOUND)

TARGET_INCLUDE_DIRECTORIES(comp PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBCOMP_INCLUDES}
    ${ASIO_INCLUDE_DIRS}
    ${SYSTEMD_INCLUDES}
    ${SQRAT_INCLUDE_DIRS}
)

IF(SYSTEMD_FOUND)
    SET(SYSTEMD_LIBS ${SYSTEMD_LIBRARIES})
ENDIF(SYSTEMD_FOUND)

IF(BUILD_EXOTIC)
    SET(OBJGEN_LIB objgen_exotic)
ELSE(BUILD_EXOTIC)
    SET(OBJGEN_LIB objgen)
ENDIF(BUILD_EXOTIC)

IF(BUILD_EXOTIC)
    IF(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(comp ${LIBOBJECTS_LIB} exotic_mbedcrypto
            ${SYSTEM_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
            ${OBJGEN_LIB} exotic_tinyxml2 physfs ${EXOTIC_ZLIB_LIBRARIES}
        )
    ELSE(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(comp ${LIBOBJECTS_LIB} ${EXOTIC_OPENSSL_LIBRARIES}
            ${SYSTEM_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
            ${OBJGEN_LIB} exotic_tinyxml2 physfs ${EXOTIC_ZLIB_LIBRARIES})
    ENDIF(USE_MBED_TLS)
ELSE(BUILD_EXOTIC)
    IF(USE_MBED_TLS)
        # We still need to link to OpenSSL for the MariaDB library
        TARGET_LINK_LIBRARIES(comp ${LIBOBJECTS_LIB} mariadbclient mbedcrypto
            ${OPENSSL_LIBRARIES} ${SYSTEM_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
            ${OBJGEN_LIB} sqlite3 squirrel sqstdlib ttvfs ttvfs_zip tinyxml2
            physfs ${ZLIB_LIBRARIES} ${SYSTEMD_LIBS})
    ELSE(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(comp ${LIBOBJECTS_LIB} mariadbclient
            ${OPENSSL_LIBRARIES} ${SYSTEM_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
            ${OBJGEN_LIB} sqlite3 squirrel sqstdlib ttvfs ttvfs_zip tinyxml2
            physfs ${ZLIB_LIBRARIES} ${SYSTEMD_LIBS})
    ENDIF(USE_MBED_TLS)
ENDIF(BUILD_EXOTIC)

IF(NOT BUILD_EXOTIC)
    ADD_DEPENDENCIES(comp asio gsl)
ENDIF(NOT BUILD_EXOTIC)

IF(WIN32)
    TARGET_LINK_LIBRARIES(comp shlwapi advapi32 iphlpapi psapi shell32
        userenv ws2_32 dbghelp)
ENDIF(WIN32)

IF(USE_COTIRE)
    cotire(comp)
ENDIF(USE_COTIRE)

IF(NOT BUILD_EXOTIC)
    # List of unit tests to add to CTest.
    SET(${PROJECT_NAME}_TEST_SRCS
        Convert
        Crypto

        # This test can take too long so disable it for now.
        DiffieHellman

        GeneratedObjects
        #MariaDB
        Packet
        #ScriptEngine
        String
        VectorStream
        #XmlUtils
    )

    IF(NOT BSD)
        # Add the unit tests.
        CREATE_GTESTS(LIBS ${LIBOBJECTS_LIB} comp
            SRCS ${${PROJECT_NAME}_TEST_SRCS})
    ENDIF(NOT BSD)

    IF(LIBCOMP_STANDALONE)
        INSTALL(TARGETS comp DESTINATION lib)
        INSTALL(DIRECTORY "${CMAKE_BINARY_DIR}/api/"
            DESTINATION api)

        # Include the PDB file if on Windows
        IF(WIN32)
            INSTALL(FILES ${CMAKE_BINARY_DIR}/bin/$<CONFIG>/comp.pdb DESTINATION lib)
        ENDIF(WIN32)
    ENDIF(LIBCOMP_STANDALONE)
ENDIF(NOT BUILD_EXOTIC)
