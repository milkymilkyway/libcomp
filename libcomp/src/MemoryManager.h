/**
 * @file libcomp/src/MemoryManager.h
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Memory manager to track usage for leak analysis.
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

#ifndef LIBCOMP_SRC_MEMORYMANAGER_H
#define LIBCOMP_SRC_MEMORYMANAGER_H

// libcomp Includes
#include "rbtree.h"

// Standard C++11 Includes
#include <list>
#include <mutex>
#include <unordered_map>

// Standard C Includes
#include <ctime>
#include <cstdio>
#include <stdint.h>

#define MEMORY_SNAPSHOT_FILE "memory_snapshot.bin"

namespace libcomp
{

/**
 * A memory allocation contains the address, size, timestamp and a backtrace
 * of where the memory was allocated.
 */
struct MemoryAllocation
{
    /// Array of backtrace frames.
    void **allocBacktrace;

    /// Number of backtrace frames recorded.
    uint16_t allocBacktraceCount;

    /// Checksum of the backtrace frames.
    uint32_t allocBacktraceChecksum;

    /// Address of the allocation.
    void  *pAddress;

    /// Size (in bytes) of the allocation.
    size_t size;

    /// Time stamp of when the memory was allocated.
    time_t stamp;

    /**
     * Creates the backtrace.
     */
    void CreateBacktrace();

    /**
     * Frees the backtrace.
     */
    void FreeBacktrace();

    /**
     * Logs the backtrace to the given file.
     * @param out File to log the backtrace to.
     */
    void LogBacktrace(FILE *out);
};

/**
 * This class will track memory allocations for later analysis.
 */
class MemoryManager
{
public:
    /**
     * Called to setup the manager.
     */
    void Setup();

    /**
     * Called to dump the statistics to a file.
     */
    void Snapshot();

    /**
     * Called to track an allocated a block of memory.
     * @param pAddress Address of the memory block.
     * @param size Size of the memory block.
     */
    void Allocate(void *pAddress, size_t size);

    /**
     * Called to remove tracking on a memory block/
     * @param pAddress Address of the memory block.
     */
    void Deallocate(void *pAddress);

    /**
     * Gets basic statistics on the memory usage.
     * @param allocationCount How many blocks of memory are allocated.
     * @param heapSize Size of the heap in bytes (size of all allocations).
     */
    void GetStats(uint64_t& allocationCount, size_t& heapSize);

private:
    /**
     * Add an allocation to the collection during the snapshot progress. This
     * will follow the tree until all allocations are collected. A checksum for
     * the allocation backtrace is generated and used to group allocations made
     * in the same code location.
     * @param collection Collection to add the allocations to.
     * @param node Node to add to the collection (and child notes).
     */
    void CollectAllocation(std::unordered_map<uint32_t,
        std::list<MemoryAllocation*>>& collection, rbtree_node node);

    /// How many blocks of memory are allocated.
    uint64_t mAllocationCount;

    /// Size of the heap in bytes (size of all allocations).
    size_t mHeapSize;

    /// Red-black tree holding the memory allocations.
    rbtree mAllocations;

    /// Indicates that a snapshot is in progress and we should not
    /// track new allocations.
    bool mSnapshotInProgress;

    /// Mutex to protect access to the data structure.
    std::mutex *mLock;
};

/**
 * Check if the memory manager is enabled.
 * @returns true if the memory manager is enabled; false otherwise.
 */
bool IsMemoryManagerEnabled();

/**
 * Initialize and enable the memory manager.
 */
void InitMemoryManager();

/**
 * Trigger a memory snapshot.
 */
void TriggerMemorySnapshot();

/**
 * Gets basic statistics on the memory usage.
 * @param allocationCount How many blocks of memory are allocated.
 * @param heapSize Size of the heap in bytes (size of all allocations).
 */
void GetMemoryStats(uint64_t& allocationCount, size_t& heapSize);

} // namespace libcomp

#endif // LIBCOMP_SRC_MEMORYMANAGER_H

