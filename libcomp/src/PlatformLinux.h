/**
 * @file libcomp/src/PlatformLinux.h
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Linux specific utility functions.
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

#ifndef LIBCOMP_SRC_PLATFORMLINUX_H
#define LIBCOMP_SRC_PLATFORMLINUX_H

#include "CString.h"

namespace libcomp {

namespace Platform {

/**
 * Create a directory at the provided location.
 * @returns Whether the operation was successful or not.
 * @ingroup Platform
 */
bool CreateDirectory(const libcomp::String &path);

/**
 * Determine whether a given character is a valid path separator.
 * @returns Whether the provided character is a path separator.
 * @ingroup Platform
 */
bool IsPathSeparator(char c);

}  // namespace Platform

}  // namespace libcomp

#endif  // LIBCOMP_SRC_PLATFORMLINUX_H
