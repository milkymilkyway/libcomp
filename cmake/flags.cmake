# This file is part of COMP_hack.
#
# Copyright (C) 2010-2016 COMP_hack Team <compomega@tutanota.com>
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

MACRO(ADD_FLAG_INSIDE flag compiler)
    # Check the flag matches the compiler.
    IF((
            ("${flag}" MATCHES "^[-].*$") AND
            ("${compiler}" STREQUAL "MSVC")
        ) OR (
            ("${flag}" MATCHES "^/.*$") AND NOT
            ("${compiler}" STREQUAL "MSVC")
    ))
        MESSAGE(FATAL_ERROR
            "Flag '${flag}' can't be used with ${compiler}.")
    ENDIF()

    # Strip the string first.
    STRING(STRIP "${flag}" flag)

    # Parse each flag variable.
    FOREACH(flag_var ${ARGN})
        # Start with fresh flags.
        UNSET(flags)

        # Split the flags into a list.
        STRING(REPLACE " " ";" old_flags "${${flag_var}}")

        # Parse each old flag.
        FOREACH(old_flag ${old_flags})
            # If the old flag matches the new one or is empty, filter it.
            IF(
                (NOT "${flag}" STREQUAL "${old_flag}") AND
                (NOT "${flag}" STREQUAL "")
            )
                LIST(APPEND flags "${old_flag}")
            ENDIF()
        ENDFOREACH(old_flag)

        # Add the new flag onto the end of the list.
        LIST(APPEND flags "${flag}")

        # Convert the list back into a string.
        STRING(REPLACE ";" " " flags "${flags}")

        # Update the flags.
        SET(${flag_var} "${flags}")

        # Debug print the flags.
        # MESSAGE("${flag_var}=\"${${flag_var}}\" (ADD)")
    ENDFOREACH(flag_var)
ENDMACRO(ADD_FLAG_INSIDE)

MACRO(ADD_FLAGS_INSIDE compiler compiler_id flag_var)
    FOREACH(flag ${ARGN})
        IF(
            ("${compiler}" STREQUAL "UNIX" AND NOT WIN32) OR
            ("${compiler}" STREQUAL "WIN32" AND WIN32) OR
            ("${compiler}" STREQUAL "${compiler_id}") OR
            ("${compiler}" STREQUAL "ALL")
        )
            ADD_FLAG_INSIDE("${flag}" "${compiler_id}"
                CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
                CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_MINSIZEREL)
        ELSEIF(
            ("${compiler}" STREQUAL "AUTO") AND
            (
                (("${flag}" MATCHES "^[-].*$") AND NOT
                ("${compiler_id}" STREQUAL "MSVC"))
                OR
                (("${flag}" MATCHES "^/.*$") AND
                ("${compiler_id}" STREQUAL "MSVC"))
            )
        )
            ADD_FLAG_INSIDE("${flag}" "${compiler_id}" "${flag_var}")
        ENDIF()
    ENDFOREACH(flag)
ENDMACRO(ADD_FLAGS_INSIDE)

MACRO(REMOVE_FLAGS_INSIDE flag_var)
    # Start with fresh flags.
    UNSET(flags)

    # Split the flags into a list.
    STRING(REPLACE " " ";" old_flags "${${flag_var}}")

    # Look at each flag.
    FOREACH(flag ${old_flags})
        # Don't remove the flag by default.
        SET(remove_flag False)

        # Strip the string first.
        STRING(STRIP "${flag}" flag)

        # Check this flag against the blacklist.
        FOREACH(blacklist_flag ${ARGN})
            # Strip the string first.
            STRING(STRIP "${blacklist_flag}" blacklist_flag)

            # Filter out blank flags too.
            IF(
                ("${flag}" STREQUAL "${blacklist_flag}") OR
                ("${flag}" STREQUAL "")
            )
                SET(remove_flag True)
            ENDIF()
        ENDFOREACH(blacklist_flag)

        # If the flag should not be removed add it back to the list.
        IF(NOT ${remove_flag})
            LIST(APPEND flags "${flag}")
        ENDIF()
    ENDFOREACH(flag)

    # Convert the list back into a string.
    STRING(REPLACE ";" " " flags "${flags}")

    # Update the flags.
    SET(${flag_var} "${flags}")

    # Debug print the flags.
    # MESSAGE("${flag_var}=\"${${flag_var}}\" (REMOVE)")
ENDMACRO(REMOVE_FLAGS_INSIDE)

MACRO(ADD_C_FLAGS compiler)
    FOREACH(flag_var CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_MINSIZEREL
    )
        ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_C_COMPILER_ID}"
            "${flag_var}" ${ARGN})
    ENDFOREACH(flag_var)
ENDMACRO(ADD_C_FLAGS)

MACRO(ADD_C_FLAGS_NONE compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_C_COMPILER_ID}"
        CMAKE_C_FLAGS ${ARGN})
ENDMACRO(ADD_C_FLAGS_NONE)

MACRO(ADD_C_FLAGS_DEBUG compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_C_COMPILER_ID}"
        CMAKE_C_FLAGS_DEBUG ${ARGN})
ENDMACRO(ADD_C_FLAGS_DEBUG)

MACRO(ADD_C_FLAGS_RELEASE compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_C_COMPILER_ID}"
        CMAKE_C_FLAGS_RELEASE ${ARGN})
ENDMACRO(ADD_C_FLAGS_RELEASE)

MACRO(ADD_C_FLAGS_RELWITHDEBINFO compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_C_COMPILER_ID}"
        CMAKE_C_FLAGS_RELWITHDEBINFO ${ARGN})
ENDMACRO(ADD_C_FLAGS_RELWITHDEBINFO)

MACRO(ADD_C_FLAGS_MINSIZEREL compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_C_COMPILER_ID}"
        CMAKE_C_FLAGS_MINSIZEREL ${ARGN})
ENDMACRO(ADD_C_FLAGS_MINSIZEREL)

MACRO(ADD_CXX_FLAGS compiler)
    FOREACH(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_MINSIZEREL
    )
        ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_CXX_COMPILER_ID}"
            "${flag_var}" ${ARGN})
    ENDFOREACH(flag_var)
ENDMACRO(ADD_CXX_FLAGS)

MACRO(ADD_CXX_FLAGS_NONE compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_CXX_COMPILER_ID}"
        CMAKE_CXX_FLAGS ${ARGN})
ENDMACRO(ADD_CXX_FLAGS_NONE)

MACRO(ADD_CXX_FLAGS_DEBUG compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_CXX_COMPILER_ID}"
        CMAKE_CXX_FLAGS_DEBUG ${ARGN})
ENDMACRO(ADD_CXX_FLAGS_DEBUG)

MACRO(ADD_CXX_FLAGS_RELEASE compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_CXX_COMPILER_ID}"
        CMAKE_CXX_FLAGS_RELEASE ${ARGN})
ENDMACRO(ADD_CXX_FLAGS_RELEASE)

MACRO(ADD_CXX_FLAGS_RELWITHDEBINFO compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_CXX_COMPILER_ID}"
        CMAKE_CXX_FLAGS_RELWITHDEBINFO ${ARGN})
ENDMACRO(ADD_CXX_FLAGS_RELWITHDEBINFO)

MACRO(ADD_CXX_FLAGS_MINSIZEREL compiler)
    ADD_FLAGS_INSIDE("${compiler}" "${CMAKE_CXX_COMPILER_ID}"
        CMAKE_CXX_FLAGS_MINSIZEREL ${ARGN})
ENDMACRO(ADD_CXX_FLAGS_MINSIZEREL)

MACRO(REMOVE_C_FLAGS compiler)
    FOREACH(flag_var CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS_MINSIZEREL
    )
        REMOVE_FLAGS_INSIDE("${flag_var}" ${ARGN})
    ENDFOREACH(flag_var)
ENDMACRO(REMOVE_C_FLAGS)

MACRO(REMOVE_C_FLAGS_NONE compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_C_FLAGS ${ARGN})
ENDMACRO(REMOVE_C_FLAGS_NONE)

MACRO(REMOVE_C_FLAGS_DEBUG compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_C_FLAGS_DEBUG ${ARGN})
ENDMACRO(REMOVE_C_FLAGS_DEBUG)

MACRO(REMOVE_C_FLAGS_RELEASE compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_C_FLAGS_RELEASE ${ARGN})
ENDMACRO(REMOVE_C_FLAGS_RELEASE)

MACRO(REMOVE_C_FLAGS_RELWITHDEBINFO compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_C_FLAGS_RELWITHDEBINFO ${ARGN})
ENDMACRO(REMOVE_C_FLAGS_RELWITHDEBINFO)

MACRO(REMOVE_C_FLAGS_MINSIZEREL compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_C_FLAGS_MINSIZEREL ${ARGN})
ENDMACRO(REMOVE_C_FLAGS_MINSIZEREL)

MACRO(REMOVE_CXX_FLAGS compiler)
    FOREACH(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_MINSIZEREL
    )
        REMOVE_FLAGS_INSIDE("${flag_var}" ${ARGN})
    ENDFOREACH(flag_var)
ENDMACRO(REMOVE_CXX_FLAGS)

MACRO(REMOVE_CXX_FLAGS_NONE compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_CXX_FLAGS ${ARGN})
ENDMACRO(REMOVE_CXX_FLAGS_NONE)

MACRO(REMOVE_CXX_FLAGS_DEBUG compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_CXX_FLAGS_DEBUG ${ARGN})
ENDMACRO(REMOVE_CXX_FLAGS_DEBUG)

MACRO(REMOVE_CXX_FLAGS_RELEASE compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_CXX_FLAGS_RELEASE ${ARGN})
ENDMACRO(REMOVE_CXX_FLAGS_RELEASE)

MACRO(REMOVE_CXX_FLAGS_RELWITHDEBINFO compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_CXX_FLAGS_RELWITHDEBINFO ${ARGN})
ENDMACRO(REMOVE_CXX_FLAGS_RELWITHDEBINFO)

MACRO(REMOVE_CXX_FLAGS_MINSIZEREL compiler)
    REMOVE_FLAGS_INSIDE(CMAKE_CXX_FLAGS_MINSIZEREL ${ARGN})
ENDMACRO(REMOVE_CXX_FLAGS_MINSIZEREL)

# Compiler types:
# ALL         Always pass the flag for any platform or compiler
# AUTO        A -flag to non-MSVC and a /flag to MSVC
# WIN32       Only pass the flag on Windows
# UNIX        Only pass the flag on non-Windows
# <Compiler>  Only pass the flag on matching compiler

# Examples:
# ADD_C_FLAGS(AUTO /EHsc -Wall) # All variables
# ADD_C_FLAGS_NONE(AUTO /EHsc -Wall) # Just CMAKE_C_FLAGS
# REMOVE_C_FLAGS(-Wall)
