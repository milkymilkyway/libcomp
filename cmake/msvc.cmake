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

MACRO(MSVC_RUNTIME type)
    # Strip out all existing options first.
    REMOVE_COMPILER_FLAGS("/MT" "/MTd" "/MD" "/MDd" "/clr" "/clr:pure")
    REMOVE_LINKER_FLAGS("/MT" "/MTd" "/MD" "/MDd" "/clr" "/clr:pure")

    IF("${type}" STREQUAL STATIC)
        ADD_C_FLAGS_NONE("/MT")
        ADD_C_FLAGS_RELEASE("/MT")
        ADD_C_FLAGS_RELWITHDEBINFO("/MT")
        ADD_C_FLAGS_MINSIZEREL("/MT")
        ADD_C_FLAGS_DEBUG("/MTd")
    ELSEIF("${type}" STREQUAL DYNAMIC)
        ADD_C_FLAGS_NONE("/MD")
        ADD_C_FLAGS_RELEASE("/MD")
        ADD_C_FLAGS_RELWITHDEBINFO("/MD")
        ADD_C_FLAGS_MINSIZEREL("/MD")
        ADD_C_FLAGS_DEBUG("/MDd")
    ELSE()
        MESSAGE(FATAL_ERROR "Uknown MSVC runtime type '${type}'.\n"
            "Use STATIC or DYNAMIC.")
    ENDIF()
ENDMACRO(MSVC_RUNTIME)
