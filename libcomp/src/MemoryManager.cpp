/**
 * @file libcomp/src/MemoryManager.cpp
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

#include "MemoryManager.h"

// libcomp Includes
#include "Constants.h"
#include "Exception.h"

// zlib Includes
#include <zlib.h>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#else // _WIN32
#include <regex_ext>
#include <execinfo.h>
#include <cxxabi.h>
#endif // _WIN32

#include <climits>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <mutex>
#include <sstream>

#include <signal.h>

using namespace libcomp;

/// Indicates if the memory manager should be used.
static bool gMemoryManagerEnabled = false;

/// Global pointer to the memory manager.
static MemoryManager *gManager = nullptr;

/**
 * Compares two nodes in the red-black tree.
 * @param left Node to compare.
 * @param right Node to compare.
 * @returns Negative value if left < right, positive if
 *   left > right or 0 if equal.
 */
static int compare_tree(rbtree_key left, rbtree_key right)
{
    if(left < right)
    {
        return -1;
    }
    else if(left > right)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

bool libcomp::IsMemoryManagerEnabled()
{
    return gMemoryManagerEnabled;
}

void libcomp::InitMemoryManager()
{
    gManager = (MemoryManager*)malloc(sizeof(MemoryManager));
    gManager->Setup();
    gMemoryManagerEnabled = true;
}

void libcomp::TriggerMemorySnapshot()
{
    if(gManager)
    {
        gManager->Snapshot();
    }
}

void libcomp::GetMemoryStats(uint64_t& allocationCount, size_t& heapSize)
{
    if(gManager)
    {
        gManager->GetStats(allocationCount, heapSize);
    }
    else
    {
        allocationCount = 0;
        heapSize = 0;
    }
}

void MemoryAllocation::CreateBacktrace()
{
    allocBacktrace = nullptr;
    allocBacktraceCount = 0;
    allocBacktraceChecksum = 0;

#ifdef _WIN32
    static std::mutex lock;

    // Lock the mutex before generating the backtrace.
    std::lock_guard<std::mutex> guard(lock);

    // Array to store each backtrace address.
    void *backtraceAddresses[MAX_BACKTRACE_DEPTH];

    USHORT frameCount = CaptureStackBackTrace(0,
        MAX_BACKTRACE_DEPTH, backtraceAddresses, NULL);

    if(frameCount > 0)
    {
        allocBacktrace = (void**)malloc(sizeof(void*) * frameCount);
        memcpy(allocBacktrace, backtraceAddresses, sizeof(void*) * frameCount);
        allocBacktraceCount = frameCount;
    }
#else // _WIN32
    // Array to store each backtrace address.
    void *backtraceAddresses[MAX_BACKTRACE_DEPTH];

    // Populate the array of backtrace addresses and get how many were added.
    backtrace_size_t backtraceSize = ::backtrace(backtraceAddresses,
        MAX_BACKTRACE_DEPTH);

    // If we have a valid array of backtraces, parse them.
    if(backtraceSize > 0)
    {
        allocBacktrace = (void**)malloc((size_t)(
            sizeof(void*) * (uint16_t)backtraceSize));
        memcpy(allocBacktrace, backtraceAddresses, (size_t)(sizeof(void*) *
            (uint16_t)backtraceSize));
        allocBacktraceCount = (uint16_t)backtraceSize;
    }
#endif // _WIN32
}

void MemoryAllocation::FreeBacktrace()
{
    if(nullptr != allocBacktrace)
    {
        free(allocBacktrace);
    }
}

void MemoryAllocation::LogBacktrace(FILE *out)
{
#ifdef _WIN32
    static std::mutex lock;

    SymSetOptions(SYMOPT_LOAD_LINES);

    const static BOOL symInit = SymInitialize(GetCurrentProcess(), NULL, TRUE);

    if(TRUE != symInit)
    {
        return;
    }

    for(USHORT i = 0; i < allocBacktraceCount; ++i)
    {
        DWORD64 displacement = 0;

        uint8_t *pInfoBuffer = new uint8_t[sizeof(SYMBOL_INFO) +
            MAX_SYMBOL_LEN];
        SYMBOL_INFO *pInfo = reinterpret_cast<SYMBOL_INFO*>(pInfoBuffer);
        memset(pInfoBuffer, 0, sizeof(SYMBOL_INFO) + MAX_SYMBOL_LEN);
        pInfo->MaxNameLen = MAX_SYMBOL_LEN;
        pInfo->SizeOfStruct = sizeof(SYMBOL_INFO);

        // Retrieve the symbol for each frame in the array.
        if(TRUE == symInit && TRUE == SymFromAddr(GetCurrentProcess(),
            (DWORD64)allocBacktrace[i], &displacement, pInfo))
        {
            char name[MAX_SYMBOL_LEN];
            char sym[MAX_SYMBOL_LEN];

            std::stringstream ss;

            if(0 >= UnDecorateSymbolName(pInfo->Name, sym,
                MAX_SYMBOL_LEN, UNDNAME_COMPLETE))
            {
                strncpy(sym, pInfo->Name, MAX_SYMBOL_LEN - 1);
            }

            if(0 < GetModuleFileNameA((HMODULE)pInfo->ModBase, name,
                MAX_SYMBOL_LEN))
            {
                char *pModuleName = strrchr(name, '\\');

                if(NULL == pModuleName)
                {
                    pModuleName = name;
                }
                else
                {
                    pModuleName++;
                }

                ss << pModuleName << "(" << sym << "+0x"
                    << std::hex << displacement << ")";
            }
            else
            {
                ss << R"_raw_(???()_raw_" << sym << "+0x"
                    << std::hex << displacement << ")";
            }

            ss << " [0x" << std::hex << (DWORD64)allocBacktrace[i] << "]";

            DWORD lineDisplacement;
            IMAGEHLP_LINE64 line;

            if(TRUE == SymGetLineFromAddr64(GetCurrentProcess(),
                (ULONG64)allocBacktrace[i], &lineDisplacement, &line))
            {
                ss << " " << line.FileName << ":"
                    << std::dec << line.LineNumber;
            }

            auto backtraceString = ss.str();
            uint64_t backtraceAddress = (uint64_t)allocBacktrace[i];
            uint32_t backtraceStringLength = (uint32_t)backtraceString.length();

            fwrite(&backtraceAddress, sizeof(backtraceAddress), 1, out);
            fwrite(&backtraceStringLength, sizeof(backtraceStringLength), 1, out);
            fwrite(backtraceString.c_str(), backtraceStringLength, 1, out);
        }
        else
        {
            std::stringstream ss;
            ss << "0x" << std::hex << (DWORD64)allocBacktrace[i];

            auto backtraceString = ss.str();
            uint64_t backtraceAddresses = (uint64_t)allocBacktrace[i];
            uint32_t backtraceStringLength = (uint32_t)backtraceString.length();

            fwrite(&backtraceAddresses, sizeof(backtraceAddresses), 1, out);
            fwrite(&backtraceStringLength, sizeof(backtraceStringLength), 1, out);
            fwrite(backtraceString.c_str(), backtraceStringLength, 1, out);
        }

        delete[] pInfoBuffer;
        pInfoBuffer = nullptr;
    }
#else // _WIN32
    // If we have a valid array of backtraces, parse them.
    if(allocBacktraceCount > 0)
    {
        // Retrieve the symbols for each backtrace in the array.
        char **backtraceSymbols = backtrace_symbols(
            allocBacktrace, (backtrace_size_t)allocBacktraceCount);

        // If the symbols were created, parse then.
        if(backtraceSymbols)
        {
            // For each symbol in the array, convert it to a String and add it
            // to the backtrace string list. Set i = 1 to skip over this
            // constructor function.
            for(uint16_t i = 1; i < allocBacktraceCount; i++)
            {
                std::string symbol = backtraceSymbols[i];
                std::string demangled;

                // Demangle any C++ symbols in the backtrace.
                auto callback = [&](const std::smatch& match)
                {
                    std::string s;

                    int status = -1;

#if 1 == EXCEPTION_STRIP_MODULE
                    char *szDemangled = abi::__cxa_demangle(
                        match.str(2).c_str(), 0, 0, &status);
#else // 1 != EXCEPTION_STRIP_MODULE
                    char *szDemangled = abi::__cxa_demangle(
                        match.str(1).c_str(), 0, 0, &status);
#endif // 1 == EXCEPTION_STRIP_MODULE

                    if(0 == status)
                    {
                        std::stringstream ss;
#if 1 == EXCEPTION_STRIP_MODULE
                        ss << szDemangled << "+" << match.str(3);
#else // 1 != EXCEPTION_STRIP_MODULE
                        ss << "(" << szDemangled << "+" << match.str(2) << ")";
#endif // 1 == EXCEPTION_STRIP_MODULE
                        s = ss.str();
                    }
                    else
                    {
                        s = match.str(0);
                    }

                    free(szDemangled);

                    return s;
                };

#if 1 == EXCEPTION_STRIP_MODULE
                std::regex re("^(.*)\\((.+)\\+(0x[0-9a-fA-F]+)\\)");
#else // 1 != EXCEPTION_STRIP_MODULE
                std::regex re("\\((.+)\\+(0x[0-9a-fA-F]+)\\)");
#endif // 1 == EXCEPTION_STRIP_MODULE

                demangled = std::regex_replace(symbol.cbegin(), symbol.cend(),
                    re, callback);

                auto backtraceString = demangled;
                uint64_t backtraceAddress = (uint64_t)allocBacktrace[i];
                uint32_t backtraceStringLength = (uint32_t)backtraceString.length();

                fwrite(&backtraceAddress, sizeof(backtraceAddress), 1, out);
                fwrite(&backtraceStringLength, sizeof(backtraceStringLength), 1, out);
                fwrite(backtraceString.c_str(), backtraceStringLength, 1, out);
            }

            // Since backtrace_symbols allocated the array, we must free it.
            // Note that the man page specifies that the strings themselves
            // should not be freed.
            free(backtraceSymbols);
        }
    }
#endif // _WIN32
}

void MemoryManager::Setup()
{
    mSnapshotInProgress = true;
    mLock = new std::mutex();

    mAllocationCount = 0;
    mHeapSize = 0;
    mAllocations = rbtree_create();
    mSnapshotInProgress = false;
}

void MemoryManager::Snapshot()
{
    mLock->lock();

    mSnapshotInProgress = true;

    FILE *out = fopen(MEMORY_SNAPSHOT_FILE, "w");

    {
        std::unordered_map<uint32_t, std::list<MemoryAllocation*>> allocMap;
        CollectAllocation(allocMap, mAllocations->root);

        uint64_t collectionCount = (uint64_t)allocMap.size();

        fwrite("MEMD", 4, 1, out);
        fwrite(&mAllocationCount, sizeof(mAllocationCount), 1, out);
        fwrite(&mHeapSize, sizeof(mHeapSize), 1, out);
        fwrite(&collectionCount, sizeof(collectionCount), 1, out);

        for(auto it = allocMap.begin(); it != allocMap.end(); ++it)
        {
            size_t total = 0;

            for(auto pAllocation : it->second)
            {
                total += pAllocation->size;
            }

            uint32_t checksum = it->first;

            fwrite(&total, sizeof(total), 1, out);
            fwrite(&checksum, sizeof(checksum), 1, out);

            it->second.front()->LogBacktrace(out);

            for(auto pAllocation : it->second)
            {
                uint64_t addr = (uint64_t)pAllocation->pAddress;

                fwrite(&addr, sizeof(addr), 1, out);
                fwrite(&pAllocation->size,
                    sizeof(pAllocation->size), 1, out);
                fwrite(&pAllocation->stamp,
                    sizeof(pAllocation->stamp), 1, out);
            }
        }
    }

    fclose(out);

    mSnapshotInProgress = false;

    mLock->unlock();
}

void MemoryManager::Allocate(void *pAddress, size_t size)
{
    if(nullptr == pAddress || mSnapshotInProgress)
    {
        return;
    }

    mLock->lock();

    MemoryAllocation *pAllocation = (MemoryAllocation*)malloc(
        sizeof(MemoryAllocation));
    pAllocation->pAddress = pAddress;
    pAllocation->size = size;
    pAllocation->stamp = time(0);
    pAllocation->CreateBacktrace();

    mAllocationCount++;
    mHeapSize += size;

    rbtree_insert(mAllocations, (rbtree_key)pAddress,
        (rbtree_value)pAllocation, compare_tree);

    mLock->unlock();
}

void MemoryManager::Deallocate(void *pAddress)
{
    if(nullptr == pAddress || mSnapshotInProgress)
    {
        return;
    }

    mLock->lock();

    MemoryAllocation *pAllocation = (MemoryAllocation*)rbtree_take(
        mAllocations, (rbtree_key)pAddress, compare_tree);

    if(nullptr != pAllocation)
    {
        mAllocationCount--;
        mHeapSize -= pAllocation->size;

        pAllocation->FreeBacktrace();

        free(pAllocation);
    }

    mLock->unlock();
}

void MemoryManager::GetStats(uint64_t& allocationCount, size_t& heapSize)
{
    mLock->lock();
    allocationCount = mAllocationCount;
    heapSize = mHeapSize;
    mLock->unlock();
}

void MemoryManager::CollectAllocation(std::unordered_map<uint32_t,
    std::list<MemoryAllocation*>>& collection, rbtree_node node)
{
    if(!node)
    {
        return;
    }

    uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
    MemoryAllocation *pAllocation = (MemoryAllocation*)node->value;
    pAllocation->allocBacktraceChecksum = (uint32_t)crc32((uLong)crc,
        (Bytef*)pAllocation->allocBacktrace, (uInt)(sizeof(void*) *
        (size_t)pAllocation->allocBacktraceCount));
    collection[pAllocation->allocBacktraceChecksum].push_back(pAllocation);

    CollectAllocation(collection, node->left);
    CollectAllocation(collection, node->right);
}

void* operator new(size_t size)
{
    void *pData = malloc(size);

    if(gMemoryManagerEnabled && gManager)
    {
        gManager->Allocate(pData, size);
    }

    return pData;
}

void* operator new[](size_t size)
{
    void *pData = malloc(size);

    if(gMemoryManagerEnabled && gManager)
    {
        gManager->Allocate(pData, size);
    }

    return pData;
}

void operator delete(void *pData) noexcept
{
    if(0 != pData)
    {
        if(gMemoryManagerEnabled && gManager)
        {
            gManager->Deallocate(pData);
        }

        free(pData);
    }
}

void operator delete(void *pData, size_t) noexcept
{
    if(0 != pData)
    {
        if(gMemoryManagerEnabled && gManager)
        {
            gManager->Deallocate(pData);
        }

        free(pData);
    }
}
