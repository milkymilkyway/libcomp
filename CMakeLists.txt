# This file is part of COMP_hack.
#
# Copyright (C) 2010-2019 COMP_hack Team <compomega@tutanota.com>
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

CMAKE_MINIMUM_REQUIRED(VERSION 3.2.3)

IF("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    SET(LIBCOMP_DIR ${CMAKE_SOURCE_DIR}/libcomp)
    SET(LIBCOMP_STANDALONE True)
    INCLUDE(standalone.cmake)
ELSEIF(NOT UPDATER_ONLY)
    ADD_SUBDIRECTORY(libobjgen)
    ADD_SUBDIRECTORY(tools)
    ADD_SUBDIRECTORY(libcomp)
ENDIF()
