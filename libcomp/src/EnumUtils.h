/**
 * @file libcomp/src/EnumUtils.h
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Utility functions for working with enums.
 *
 * This file is part of the COMP_hack Library (libcomp).
 *
 * Copyright (C) 2012-2019 COMP_hack Team <compomega@tutanota.com>
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

#ifndef LIBCOMP_SRC_ENUMUTILS_H
#define LIBCOMP_SRC_ENUMUTILS_H

// Standard C++11 Includes
#include <type_traits>

/**
 * Casting utility to maintain an enum type when passed as a parameter.
 */
template<typename T>
constexpr typename std::underlying_type<T>::type to_underlying(T val)
{
    return static_cast<typename std::underlying_type<T>::type>(val);
}

#endif // LIBCOMP_SRC_ENUMUTILS_H
