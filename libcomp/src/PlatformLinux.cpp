/**
 * @file libcomp/src/PlatformLinux.cpp
 * @ingroup libcomp
 *
 * @brief Linux/Unix specific utility functions.
 *
 * This file is part of the COMP_hack Library (libcomp).
 *
 * Copyright (C) 2012-2021 COMP_hack Team <compomega@tutanota.com>
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

#include "PlatformLinux.h"

#ifndef _WIN32

#include <sys/stat.h>
#include <sys/types.h>

bool libcomp::Platform::CreateDirectory(const libcomp::String &path) {
  return mkdir(path.C(), 0770) == 0;
}

bool libcomp::Platform::IsPathSeparator(char c) { return c == '/'; }

#endif  // !_WIN32
