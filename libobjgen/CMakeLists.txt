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

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

IF(EXOTIC_LIBOBJGEN)
    PROJECT(libobjgen_exotic ${EXOTIC_LANGUAGE})

    SET(OBJGEN_LIB objgen_exotic)
ELSE(EXOTIC_LIBOBJGEN)
    PROJECT(libobjgen CXX)

    SET(OBJGEN_LIB objgen)
ENDIF(EXOTIC_LIBOBJGEN)

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
FILE(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/api/${PROJECT_NAME})
#GENERATE_DOCS(doc/Doxyfile.in)

SET(${PROJECT_NAME}_SRCS
    src/UUID.cpp
)

IF(NOT EXOTIC_LIBOBJGEN)
    SET(${PROJECT_NAME}_SRCS
        ${${PROJECT_NAME}_SRCS}

        src/MetaObject.cpp
        src/MetaVariable.cpp
        src/MetaVariableArray.cpp
        src/MetaVariableBool.cpp
        src/MetaVariableEnum.cpp
        src/MetaVariableInt.cpp
        src/MetaVariableList.cpp
        src/MetaVariableMap.cpp
        src/MetaVariableReference.cpp
        src/MetaVariableSet.cpp
        src/MetaVariableString.cpp
        src/MetaObjectXmlParser.cpp

        src/Generator.cpp
        src/GeneratorFactory.cpp
        src/GeneratorHeader.cpp
        src/GeneratorSource.cpp

        ${CMAKE_CURRENT_BINARY_DIR}/res/ResourceTemplate.c
    )
ENDIF(NOT EXOTIC_LIBOBJGEN)

SET(${PROJECT_NAME}_HDRS
    src/UUID.h
)

IF(NOT EXOTIC_LIBOBJGEN)
    SET(${PROJECT_NAME}_HDRS
        ${${PROJECT_NAME}_HDRS}

        src/MetaObject.h
        src/MetaVariable.h
        src/MetaVariableArray.h
        src/MetaVariableBool.h
        src/MetaVariableEnum.h
        src/MetaVariableInt.h
        src/MetaVariableList.h
        src/MetaVariableMap.h
        src/MetaVariableReference.h
        src/MetaVariableSet.h
        src/MetaVariableString.h
        src/MetaObjectXmlParser.h

        src/Generator.h
        src/GeneratorFactory.h
        src/GeneratorHeader.h
        src/GeneratorSource.h

        ${CMAKE_CURRENT_BINARY_DIR}/res/ResourceTemplate.h
    )
ENDIF(NOT EXOTIC_LIBOBJGEN)

IF(NOT EXOTIC_LIBOBJGEN)
    FILE(GLOB ${PROJECT_NAME}_TEMPLATES "res/*.cpp")

    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/res/ResourceTemplate.c
            ${CMAKE_CURRENT_BINARY_DIR}/res/ResourceTemplate.h
        COMMAND ${CMAKE_COMMAND} -E make_directory
            ${CMAKE_CURRENT_BINARY_DIR}/res
        COMMAND ${TTVFS_GEN_PATH} ResourceTemplate ResourceTemplateSize
            ${CMAKE_CURRENT_SOURCE_DIR}/res
            ${CMAKE_CURRENT_BINARY_DIR}/res/ResourceTemplate.c
            ${CMAKE_CURRENT_BINARY_DIR}/res/ResourceTemplate.h
        DEPENDS ttvfs-ex ${${PROJECT_NAME}_TEMPLATES}
        COMMENT "Generating resource file for libobjgen templates"
    )
ENDIF(NOT EXOTIC_LIBOBJGEN)

# Don't try to build the headers.
IF(BUILD_EXOTIC)
    SET(${PROJECT_NAME}_HDRS "")
ENDIF(BUILD_EXOTIC)

ADD_LIBRARY(${OBJGEN_LIB} STATIC ${${PROJECT_NAME}_SRCS} ${${PROJECT_NAME}_HDRS})

IF(EXOTIC_LIBOBJGEN)
    SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SRCS} ${${PROJECT_NAME}_HDRS}
        PROPERTIES LANGUAGE ${EXOTIC_LANGUAGE})
ENDIF(EXOTIC_LIBOBJGEN)

IF(NOT BUILD_EXOTIC)
    ADD_DEPENDENCIES(${OBJGEN_LIB} gsl)
ENDIF(NOT BUILD_EXOTIC)

SET_TARGET_PROPERTIES(${OBJGEN_LIB} PROPERTIES FOLDER "Libraries")

TARGET_INCLUDE_DIRECTORIES(${OBJGEN_LIB} PUBLIC
    ${LIBOBJGEN_INCLUDES}
)

TARGET_INCLUDE_DIRECTORIES(${OBJGEN_LIB} PUBLIC
    ${OPENSSL_INCLUDE_DIR}
)

TARGET_INCLUDE_DIRECTORIES(${OBJGEN_LIB} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/res
)

IF(BUILD_EXOTIC)
    TARGET_COMPILE_DEFINITIONS(${OBJGEN_LIB} PUBLIC EXOTIC_BUILD=1)
ENDIF(BUILD_EXOTIC)

IF(EXOTIC_LIBOBJGEN)
    TARGET_COMPILE_DEFINITIONS(${OBJGEN_LIB} PUBLIC EXOTIC_PLATFORM=1)
ENDIF(EXOTIC_LIBOBJGEN)

IF(USE_MBED_TLS)
    TARGET_COMPILE_DEFINITIONS(${OBJGEN_LIB} PUBLIC USE_MBED_TLS=1)
ENDIF(USE_MBED_TLS)

IF(EXOTIC_LIBOBJGEN)
    IF(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(${OBJGEN_LIB} exotic_mbedcrypto
            ${EXOTIC_ZLIB_LIBRARIES} exotic_tinyxml2)
    ELSE(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(${OBJGEN_LIB} ${EXOTIC_OPENSSL_LIBRARIES}
            ${EXOTIC_ZLIB_LIBRARIES} exotic_tinyxml2)
    ENDIF(USE_MBED_TLS)
ELSE(EXOTIC_LIBOBJGEN)
    IF(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(${OBJGEN_LIB} mbedcrypto ${ZLIB_LIBRARIES}
            tinyxml2 ttvfs ttvfs_zip)
    ELSE(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(${OBJGEN_LIB} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES}
            tinyxml2 ttvfs ttvfs_zip)
    ENDIF(USE_MBED_TLS)
ENDIF(EXOTIC_LIBOBJGEN)

IF(WIN32)
    TARGET_LINK_LIBRARIES(${OBJGEN_LIB} crypt32 advapi32 iphlpapi psapi
        shell32 userenv ws2_32)
ENDIF(WIN32)

IF(NOT EXOTIC_LIBOBJGEN)
    # List of unit tests to add to CTest.
    SET(${PROJECT_NAME}_TEST_SRCS
        MetaObject
        MetaVariable
        UUID
    )

    IF(NOT BSD)
        # Add the unit tests.
        CREATE_GTESTS(LIBS objgen ${CMAKE_THREAD_LIBS_INIT}
            SRCS ${${PROJECT_NAME}_TEST_SRCS})
    ENDIF(NOT BSD)

    IF(LIBCOMP_STANDALONE)
        INSTALL(TARGETS objgen DESTINATION lib)

        # Include the PDB file if on Windows
        IF(WIN32)
            INSTALL(FILES ${CMAKE_BINARY_DIR}/bin/$<CONFIG>/objgen.pdb DESTINATION lib)
        ENDIF(WIN32)
    ENDIF(LIBCOMP_STANDALONE)
ENDIF(NOT EXOTIC_LIBOBJGEN)
