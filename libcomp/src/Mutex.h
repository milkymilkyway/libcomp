/**
 * @file libcomp/src/Mutex.h
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Definition of the Mutex class.
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

#ifndef LIBCOMP_SRC_MUTEX_H
#define LIBCOMP_SRC_MUTEX_H

// Standard C++11 Includes
#include <mutex>

namespace libcomp
{

/**
 * Mutex wrapper that checks if the mutex has already been locked. If the
 * mutex has already been locked an exception will be thrown.
 */
class Mutex
{
public:
    /**
     * Construct a new mutex.
     */
    Mutex();

    /**
     * You may not copy a mutex.
     */
    Mutex(const Mutex&) = delete;

    /**
     * Block until the mutex can be locked by this thread.
     */
    void lock();

    /**
     * Unlock the mutex.
     */
    void unlock();

    /**
     * Attempt to lock this mutex but do not block.
     * @returns true if the mutex is locked; false otherwise.
     */
    bool try_lock();

private:
    /// If the mutex has already been locked.
    bool mLocked;

    /// Underlying mutex.
    std::recursive_mutex mMutex;
};

} // namespace libcomp

#endif // LIBCOMP_SRC_MUTEX_H
