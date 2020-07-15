/**
 * @file libobjgen/src/UUID.cpp
 * @ingroup libobjgen
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Class to handle a UUID.
 *
 * This file is part of the COMP_hack Object Generator Library (libobjgen).
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

#include "UUID.h"

#include "Endian.h"

#ifdef USE_MBED_TLS
#include <mbedtls/ctr_drbg.h>
#else  // USE_MBED_TLS
#include <openssl/rand.h>
#endif  // USE_MBED_TLS

// Standard C++11 Libraries
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <regex>
#include <sstream>

#ifdef USE_MBED_TLS
#ifdef _WIN32
// Windows Includes
#include <windows.h>

// Windows Crypto Includes
#include <wincrypt.h>
#endif  // _WIN32
#endif  // USE_MBED_TLS

libobjgen::UUID::UUID() : mTimeAndVersion(0), mClockSequenceAndNode(0) {}

libobjgen::UUID::UUID(const std::string &other) {
  std::string s = other;

  std::transform(s.begin(), s.end(), s.begin(), ::tolower);

  static const std::regex re(
      "^([0-9A-Fa-f]{8})-([0-9A-Fa-f]{4})-"
      "([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{12})$");

  std::smatch match;

  if (std::regex_match(s, match, re)) {
    uint32_t a;
    uint16_t b, c, d;
    uint64_t e;

    std::stringstream(match[1]) >> std::hex >> a;
    std::stringstream(match[2]) >> std::hex >> b;
    std::stringstream(match[3]) >> std::hex >> c;
    std::stringstream(match[4]) >> std::hex >> d;
    std::stringstream(match[5]) >> std::hex >> e;

    mTimeAndVersion = (uint64_t)a | ((uint64_t)b << 32) | ((uint64_t)c << 48);
    mClockSequenceAndNode = ((uint64_t)d << 48) | (uint64_t)e;
  } else {
    mTimeAndVersion = 0;
    mClockSequenceAndNode = 0;
  }
}

libobjgen::UUID::UUID(const std::vector<char> &data) {
  if ((sizeof(mTimeAndVersion) + sizeof(mClockSequenceAndNode)) <=
      data.size()) {
    uint32_t a;
    uint16_t b, c, d;
    uint64_t e;

    memcpy(&a, &data[0], sizeof(a));
    memcpy(&b, &data[sizeof(a)], sizeof(b));
    memcpy(&c, &data[sizeof(a) + sizeof(b)], sizeof(c));
    memcpy(&d, &data[sizeof(a) + sizeof(b) + sizeof(c)], sizeof(d));
    memcpy(&e, &data[sizeof(a) + sizeof(b) + sizeof(c) + sizeof(d)], 6);

    a = be32toh(a);
    b = be16toh(b);
    c = be16toh(c);
    d = be16toh(d);
    e = be64toh(e) >> 16;

    mTimeAndVersion = (uint64_t)a | ((uint64_t)b << 32) | ((uint64_t)c << 48);
    mClockSequenceAndNode = ((uint64_t)d << 48) | (uint64_t)e;
  } else {
    mTimeAndVersion = 0;
    mClockSequenceAndNode = 0;
  }
}

#ifdef USE_MBED_TLS
static std::vector<char> SeedLoadFile(const std::string &path,
                                      int requestedSize) {
  std::ifstream::streampos fileSize;
  std::vector<char> data;
  std::ifstream file;

  try {
    file.open(path.c_str(), std::ifstream::in | std::ifstream::binary);
    fileSize = static_cast<std::ifstream::streampos>(requestedSize);

    if (file.good() && 0 < fileSize) {
      data.resize(static_cast<std::vector<char>::size_type>(fileSize));
      file.read(&data[0], fileSize);
    }

    if (!file.good() ||
        data.size() != static_cast<std::vector<char>::size_type>(fileSize)) {
      data.clear();
    }

    return data;
  } catch (...) {
    return {};
  }
}

static int RandomSeed(void *pUserData, uint8_t *pBuffer, size_t bufferSize) {
  (void)pUserData;

  // Where to store the random data.
  std::vector<char> random;

  // Copy the size (don't feel like changing this code).
  int sz = (int)bufferSize;

#ifdef _WIN32
  HCRYPTPROV hCryptProv;

  PBYTE pbData = new BYTE[sz];

  if (nullptr == pbData) {
    return -1;
  }

  // On Windows, use the cryto API to generate the random data. Acquire a
  // context to generate the random data with.
  if (TRUE != CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
                                  CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET)) {
    delete[] pbData;

    return -2;
  }

  // Generate the random data.
  if (TRUE != CryptGenRandom(hCryptProv, sz, pbData)) {
    delete[] pbData;

    return -3;
  }

  // Release the context.
  if (TRUE != CryptReleaseContext(hCryptProv, 0)) {
    delete[] pbData;

    return -4;
  }

  // Convert the raw data to a QByteArray.
  random = std::move(std::vector<char>(reinterpret_cast<char *>(pbData),
                                       reinterpret_cast<char *>(pbData) + sz));
#else   // _WIN32
  // On Linux, use /dev/urandom.
  random = SeedLoadFile("/dev/urandom", sz);

  // Check that enough data was read.
  if (random.size() != static_cast<std::vector<char>::size_type>(sz)) {
    return -1;
  }
#endif  // _WIN32

  memcpy(pBuffer, &random[0], bufferSize);

  return 0;
}
#endif  // USE_MBED_TLS

libobjgen::UUID libobjgen::UUID::Random() {
  libobjgen::UUID uuid;

#ifdef USE_MBED_TLS
  static bool didInit = false;
  static mbedtls_ctr_drbg_context ctx;

  if (!didInit) {
    mbedtls_ctr_drbg_init(&ctx);
    mbedtls_ctr_drbg_seed(&ctx, RandomSeed, NULL, NULL, 0);
    didInit = true;
  }

  if (0 == mbedtls_ctr_drbg_random(&ctx, (unsigned char *)&uuid.mTimeAndVersion,
                                   sizeof(uuid.mTimeAndVersion)) &&
      0 == mbedtls_ctr_drbg_random(&ctx,
                                   (unsigned char *)&uuid.mClockSequenceAndNode,
                                   sizeof(uuid.mTimeAndVersion))) {
    uuid.mTimeAndVersion =
        (uuid.mTimeAndVersion & 0x0FFFFFFFFFFFFFFFLL) | ((uint64_t)4 << 60);
    uuid.mClockSequenceAndNode =
        (uuid.mClockSequenceAndNode & 0x3FFFFFFFFFFFFFFFLL) |
        0x8000000000000000LL;
  } else {
    uuid.mTimeAndVersion = 0;
    uuid.mClockSequenceAndNode = 0;
  }

  return uuid;
#else   // USE_MBED_TLS
  if (1 == RAND_bytes((unsigned char *)&uuid.mTimeAndVersion,
                      sizeof(uuid.mTimeAndVersion)) &&
      1 == RAND_bytes((unsigned char *)&uuid.mClockSequenceAndNode,
                      sizeof(uuid.mTimeAndVersion))) {
    uuid.mTimeAndVersion =
        (uuid.mTimeAndVersion & 0x0FFFFFFFFFFFFFFFLL) | ((uint64_t)4 << 60);
    uuid.mClockSequenceAndNode =
        (uuid.mClockSequenceAndNode & 0x3FFFFFFFFFFFFFFFLL) |
        0x8000000000000000LL;
  } else {
    uuid.mTimeAndVersion = 0;
    uuid.mClockSequenceAndNode = 0;
  }

  return uuid;
#endif  // USE_MBED_TLS
}

std::string libobjgen::UUID::ToString() const {
  std::stringstream ss;

  ss << std::hex << std::setfill('0');
  ss << std::setw(8) << (mTimeAndVersion & 0xFFFFFFFF);
  ss << "-";
  ss << std::setw(4) << ((mTimeAndVersion >> 32) & 0xFFFF);
  ss << "-";
  ss << std::setw(4) << ((mTimeAndVersion >> 48) & 0xFFFF);
  ss << "-";
  ss << std::setw(4) << ((mClockSequenceAndNode >> 48) & 0xFFFF);
  ss << "-";
  ss << std::setw(12) << (mClockSequenceAndNode & 0xFFFFFFFFFFFFLL);

  return ss.str();
}

std::vector<char> libobjgen::UUID::ToData() const {
  std::vector<char> data(16);

  uint32_t a = mTimeAndVersion & 0xFFFFFFFF;
  uint16_t b = (mTimeAndVersion >> 32) & 0xFFFF;
  uint16_t c = static_cast<uint16_t>((mTimeAndVersion >> 48) & 0xFFFF);
  uint16_t d = static_cast<uint16_t>((mClockSequenceAndNode >> 48) & 0xFFFF);
  uint64_t e = mClockSequenceAndNode & 0xFFFFFFFFFFFFLL;

  a = htobe32(a);
  b = htobe16(b);
  c = htobe16(c);
  d = htobe16(d);
  e = htobe64(e << 16);

  memcpy(&data[0], &a, sizeof(a));
  memcpy(&data[sizeof(a)], &b, sizeof(b));
  memcpy(&data[sizeof(a) + sizeof(b)], &c, sizeof(c));
  memcpy(&data[sizeof(a) + sizeof(b) + sizeof(c)], &d, sizeof(d));
  memcpy(&data[sizeof(a) + sizeof(b) + sizeof(c) + sizeof(d)], &e, 6);

  return data;
}

bool libobjgen::UUID::IsNull() const {
  return 0 == mTimeAndVersion && 0 == mClockSequenceAndNode;
}

bool libobjgen::UUID::operator==(UUID other) const {
  return mTimeAndVersion == other.mTimeAndVersion &&
         mClockSequenceAndNode == other.mClockSequenceAndNode;
}

bool libobjgen::UUID::operator!=(UUID other) const {
  return mTimeAndVersion != other.mTimeAndVersion ||
         mClockSequenceAndNode != other.mClockSequenceAndNode;
}
