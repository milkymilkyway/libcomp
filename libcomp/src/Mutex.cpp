/**
 * @file libcomp/src/Mutex.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Implementation of the Mutex class.
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

#include "Mutex.h"

using namespace libcomp;

Mutex::Mutex() : mLocked(false)
{
}

void Mutex::lock()
{
    mMutex.lock();

    if(mLocked)
    {
        throw std::system_error(EDEADLK, std::generic_category(),
            "double lock detected");
    }

    mLocked = true;
}

void Mutex::unlock()
{
    if(!mLocked)
    {
        throw std::system_error(EDEADLK, std::generic_category(),
            "double unlock detected");
    }

    mLocked = false;

    mMutex.unlock();
}

bool Mutex::try_lock()
{
    bool didLock = mMutex.try_lock();

    if(didLock)
    {
        if(mLocked)
        {
            throw std::system_error(EDEADLK, std::generic_category(),
                "double lock detected");
        }

        mLocked = true;
    }

    return didLock;
}
