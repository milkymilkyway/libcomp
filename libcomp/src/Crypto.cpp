/**
 * @file libcomp/src/Crypto.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Encryption and decryption function implementations.
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

#include "Crypto.h"

#include "BaseConfig.h"
#include "BaseLog.h"
#include "Endian.h"
#include "Exception.h"
#include "Packet.h"
#include "Platform.h"

#ifdef USE_MBED_TLS
#include <mbedtls/bignum.h>
#include <mbedtls/blowfish.h>
#include <mbedtls/dhm.h>
#include <mbedtls/md.h>
#else
#include <openssl/blowfish.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "CryptSupport.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
// Windows Includes
#include <windows.h>

// Windows Crypto Includes
#include <wincrypt.h>

#undef DecryptFile
#undef EncryptFile
#endif  // _WIN32

#include <cassert>
#include <fstream>
#include <iomanip>
#include <sstream>

#ifdef EXOTIC_PLATFORM
#include EXOTIC_HEADER
#endif  // EXOTIC_PLATFORM

namespace libcomp {
namespace Crypto {

#ifdef USE_MBED_TLS
struct BlowfishPrivate {
  mbedtls_blowfish_context ctx;
};

struct DiffieHellmanPrivate {
  bool mValid;
  String mPublic;
  String mPrime;
  std::vector<char> mSecret;
  mbedtls_dhm_context mContext;
};
#else   // USE_MBED_TLS
struct BlowfishPrivate {
  BF_KEY key;
};

struct DiffieHellmanPrivate {
  bool mValid;
  String mPublic;
  String mPrime;
  std::vector<char> mSecret;
  DH *mContext;
};
#endif  // USE_MBED_TLS

}  // namespace Crypto
}  // namespace libcomp

using namespace libcomp;

// Initializer/finalizer sample for MSVC and GCC/Clang.
// 2010-2016 Joe Lowe. Released into the public domain.
// Source: http://stackoverflow.com/questions/1113409/
#include <cstdio>
#include <cstdlib>

#ifdef __cplusplus
#define INITIALIZER(f)    \
  static void f(void);    \
  struct f##_t_ {         \
    f##_t_(void) { f(); } \
  };                      \
  static f##_t_ f##_;     \
  static void f(void)
#elif defined(_MSC_VER)
#pragma section(".CRT$XCU", read)
#define INITIALIZER2_(f, p)                                \
  static void f(void);                                     \
  __declspec(allocate(".CRT$XCU")) void (*f##_)(void) = f; \
  __pragma(comment(linker, "/include:" p #f "_")) static void f(void)
#ifdef _WIN64
#define INITIALIZER(f) INITIALIZER2_(f, "")
#else
#define INITIALIZER(f) INITIALIZER2_(f, "_")
#endif
#else
#define INITIALIZER(f)                              \
  static void f(void) __attribute__((constructor)); \
  static void f(void)
#endif

/**
 * @brief Setup the Blowfish key when the application starts.
 */
INITIALIZER(InitDecrypt) {
  // Sanity check the configuration.
  assert(4 == strlen(BaseConfig::ENCRYPTED_FILE_MAGIC));
  assert(16 == strlen(BaseConfig::ENCRYPTED_FILE_KEY));
  assert(8 == strlen(BaseConfig::ENCRYPTED_FILE_IV));
}

/**
 * Header for an encrypted file.
 */
#ifdef _WIN32
#pragma pack(push, 1)
typedef struct
#else
typedef struct __attribute__((packed))
#endif  // _WIN32
{
  /// Magic to identify the file type.
  char magic[4];

  /// Size (in bytes) of the file after decryption.
  uint32_t originalSize;
} EncryptedFileHeader_t;
#ifdef _WIN32
#pragma pack(pop)
#endif  // _WIN32

bool Crypto::DecryptFile(std::vector<char> &data) {
  // Check the file is large enough.
  if (sizeof(EncryptedFileHeader_t) < data.size()) {
    EncryptedFileHeader_t *pHeader =
        reinterpret_cast<EncryptedFileHeader_t *>(&data[0]);

    // Check the header.
    if (data.size() >=
            (sizeof(EncryptedFileHeader_t) + pHeader->originalSize) &&
        0 == memcmp(&pHeader->magic[0], BaseConfig::ENCRYPTED_FILE_MAGIC,
                    sizeof(pHeader->magic))) {
      uint32_t originalSize = pHeader->originalSize;
      pHeader = nullptr;

      // Remove the header.
      data.erase(data.begin(), data.begin() + sizeof(EncryptedFileHeader_t));

      // Decrypt the file.
      Crypto::Blowfish bf;
      bf.DecryptCbc(data, originalSize);

      return true;
    } else {
      pHeader = nullptr;
      data.clear();
    }
  }

  return false;
}

std::vector<char> Crypto::DecryptFile(const std::string &path) {
  std::vector<char> data = Crypto::LoadFile(path);

  (void)DecryptFile(data);

  return data;
}

bool Crypto::EncryptFile(std::vector<char> &data) {
  EncryptedFileHeader_t header;
  header.originalSize = static_cast<uint32_t>(data.size());

  memcpy(&header.magic[0], BaseConfig::ENCRYPTED_FILE_MAGIC,
         sizeof(header.magic));

  Crypto::Blowfish bf;
  bf.EncryptCbc(data);

  data.insert(data.begin(), reinterpret_cast<char *>(&header),
              reinterpret_cast<char *>(&header) + sizeof(header));

  return true;
}

bool Crypto::EncryptFile(const std::string &path,
                         const std::vector<char> &data) {
  std::vector<char> dataCopy = data;

  EncryptedFileHeader_t header;
  header.originalSize = static_cast<uint32_t>(data.size());

  memcpy(&header.magic[0], BaseConfig::ENCRYPTED_FILE_MAGIC,
         sizeof(header.magic));

  Crypto::Blowfish bf;
  bf.EncryptCbc(dataCopy);

  std::ofstream out;
  out.open(path, std::ofstream::out | std::ofstream::binary);
  out.write(reinterpret_cast<const char *>(&header), sizeof(header));
  out.write(&dataCopy[0], static_cast<std::streamsize>(dataCopy.size()));

  return out.good();
}

std::vector<char> Crypto::LoadFile(const std::string &path, int requestedSize) {
  std::ifstream::streampos fileSize;
  std::vector<char> data;
  std::ifstream file;

  try {
    if (0 < requestedSize) {
      file.open(path.c_str(), std::ifstream::in | std::ifstream::binary);
      fileSize = static_cast<std::ifstream::streampos>(requestedSize);

      if (file.good() && 0 < fileSize) {
        data.resize(static_cast<std::vector<char>::size_type>(fileSize));
        file.read(&data[0], fileSize);
      }
    } else {
      file.open(path.c_str(),
                std::ifstream::in | std::ifstream::binary | std::ifstream::ate);
      fileSize = file.tellg();
      file.seekg(0);

      if (file.good() && 0 < fileSize) {
        try {
          data.reserve(static_cast<std::vector<char>::size_type>(fileSize));
          data.assign(std::istreambuf_iterator<char>(file),
                      std::istreambuf_iterator<char>());
        } catch (const std::bad_alloc &) {
          data.clear();
        }
      }
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

String Crypto::GenerateRandom(int sz) {
  // Check for an odd size.
  if (0 < sz && 0 != (sz % 2)) {
    EXCEPTION(String("Odd size detected in call to GenerateRandom()"));
  }

  // If no size was passed in, assume 80 digits; otherwise, divide the size
  // by 2 to obtain how many bytes are required.
  sz = sz <= 0 ? 40 : (sz >> 1);

  // Where to store the random data.
  std::vector<char> random;

#ifdef _WIN32
  HCRYPTPROV hCryptProv;

  PBYTE pbData = new BYTE[sz];

  if (nullptr == pbData) {
    EXCEPTION("Failed to allocate pbData");
  }

  // On Windows, use the cryto API to generate the random data. Acquire a
  // context to generate the random data with.
  if (TRUE != CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
                                  CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET)) {
    delete[] pbData;

    EXCEPTION(libcomp::String("CryptAcquireContext: %1")
                  .Arg(Platform::GetLastErrorString()));
  }

  // Generate the random data.
  if (TRUE != CryptGenRandom(hCryptProv, sz, pbData)) {
    delete[] pbData;

    EXCEPTION(libcomp::String("CryptGenRandom: %1")
                  .Arg(Platform::GetLastErrorString()));
  }

  // Release the context.
  if (TRUE != CryptReleaseContext(hCryptProv, 0)) {
    delete[] pbData;

    EXCEPTION(libcomp::String("CryptReleaseContext: %1")
                  .Arg(Platform::GetLastErrorString()));
  }

  // Convert the raw data to a QByteArray.
  random = std::move(std::vector<char>(reinterpret_cast<char *>(pbData),
                                       reinterpret_cast<char *>(pbData) + sz));
#else   // _WIN32
  // On Linux, use /dev/urandom.
  random = LoadFile("/dev/urandom", sz);

  // Check that enough data was read.
  if (random.size() != static_cast<std::vector<char>::size_type>(sz)) {
    EXCEPTION("Failed to read from /dev/urandom");
  }
#endif  // _WIN32

  std::stringstream ss;

  // Convert the bytes into a base-16 string.
  for (char byte : random) {
    ss << std::hex << std::setw(2) << std::setfill('0') << ((int)byte & 0xFF);
  }

#ifdef WIN32
  // After conversion this buffer isn't needed.
  delete[] pbData;
#endif  // WIN32

  return ss.str();
}

uint32_t Crypto::GenerateSessionKey() {
  uint32_t sessionKey = 0;

#ifdef WIN32
  HCRYPTPROV hCryptProv;

  // On Windows, use the cryto API to generate the random data. Acquire a
  // context to generate the random data with.
  if (TRUE != CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
    return 0;
  }

  // Generate the random data.
  if (TRUE !=
      CryptGenRandom(hCryptProv, 4, reinterpret_cast<PBYTE>(&sessionKey))) {
    return 0;
  }

  // Release the context.
  if (TRUE != CryptReleaseContext(hCryptProv, 0)) {
    return 0;
  }
#else   // WIN32
  // On Linux, use /dev/urandom.
  std::vector<char> data = LoadFile("/dev/urandom", sizeof(sessionKey));

  // Sanity check the size of the random data.
  if (sizeof(sessionKey) != data.size()) {
    return 0;
  }

  // Copy the session key.
  sessionKey = *reinterpret_cast<uint32_t *>(&data[0]);
#endif  // WIN32

  // Ensure the session key won't be interpreted as a negative number.
  sessionKey &= 0x7FFFFFFF;

  // For the unlikely situation the random value is zero.
  if (0 == sessionKey) {
    sessionKey = 0x8BADF00D;
  }

  return sessionKey;
}

#ifdef USE_MBED_TLS
/**
 * Because BF_encrypt and BF_decrypt are used instead of BF_ecb_encrypt
 * the bytes need to be swapped when using mbedtls instead.
 * @param block Block of data to swap.
 * @returns Swapped data block.
 */
static inline uint64_t SwapOpenSSLInternal(uint64_t block) {
  uint32_t *pBlock32 = (uint32_t *)&block;
  pBlock32[0] = htobe32(pBlock32[0]);
  pBlock32[1] = htobe32(pBlock32[1]);

  return block;
}

/**
 * Because BF_encrypt and BF_decrypt are used instead of BF_ecb_encrypt
 * the bytes need to be swapped when using mbedtls instead.
 * @param pBlock Pointer to block of data to swap.
 */
static inline void SwapOpenSSL(void *pBlock) {
  *(uint64_t *)pBlock = SwapOpenSSLInternal(*(uint64_t *)pBlock);
}

/**
 * Because BF_encrypt and BF_decrypt are used instead of BF_ecb_encrypt
 * the bytes need to be swapped when using mbedtls instead.
 * @param block Reference to block of data to swap.
 */
static inline void SwapOpenSSL(uint64_t &block) {
  block = SwapOpenSSLInternal(block);
}

String Crypto::GenDiffieHellman(const String &g, const String &p,
                                const String &a, int outputSize) {
  (void)g;
  (void)p;
  (void)a;
  (void)outputSize;

  // This is not implemented with mbedtls (it is only used by the logger).
  assert(false && "This should not be called!");

  return {};
}

Crypto::Blowfish::Blowfish() {
  d = new BlowfishPrivate;

  // Initialize the context.
  mbedtls_blowfish_init(&d->ctx);

  // Use the default key.
  SetKey(
      reinterpret_cast<const unsigned char *>(BaseConfig::ENCRYPTED_FILE_KEY),
      16);
}

Crypto::Blowfish::~Blowfish() {
  // Free the context.
  mbedtls_blowfish_free(&d->ctx);

  delete d;
  d = nullptr;
}

void Crypto::Blowfish::SetKey(const void *pData, size_t dataSize) {
  mbedtls_blowfish_setkey(&d->ctx,
                          reinterpret_cast<const unsigned char *>(pData),
                          (uint32_t)(dataSize * 8));
}

void Crypto::Blowfish::Encrypt(void *pVoidData, uint32_t dataSize) {
  // Make room for the padded block.
  if (0 == (dataSize % BLOWFISH_BLOCK_SIZE)) {
    char *pData = reinterpret_cast<char *>(pVoidData);

    // Encrypt each full block.
    while (BLOWFISH_BLOCK_SIZE <= dataSize) {
      SwapOpenSSL(pData);
      mbedtls_blowfish_crypt_ecb(&d->ctx, MBEDTLS_BLOWFISH_ENCRYPT,
                                 reinterpret_cast<uint8_t *>(pData),
                                 reinterpret_cast<uint8_t *>(pData));
      SwapOpenSSL(pData);
      pData += BLOWFISH_BLOCK_SIZE;
      dataSize -= static_cast<uint32_t>(BLOWFISH_BLOCK_SIZE);
    }
  }
}

void Crypto::Blowfish::Encrypt(std::vector<char> &data) {
  std::vector<char>::size_type size = data.size();

  // Make room for the padded block.
  if (0 != (size % BLOWFISH_BLOCK_SIZE)) {
    // Round up to a multiple of the block size.
    size = ((size + BLOWFISH_BLOCK_SIZE - 1) / BLOWFISH_BLOCK_SIZE) *
           BLOWFISH_BLOCK_SIZE;

    // Resize the data vector.
    data.resize(size, 0);
  }

  char *pData = &data[0];

  // Encrypt each full block.
  while (BLOWFISH_BLOCK_SIZE <= size) {
    SwapOpenSSL(pData);
    mbedtls_blowfish_crypt_ecb(&d->ctx, MBEDTLS_BLOWFISH_ENCRYPT,
                               reinterpret_cast<uint8_t *>(pData),
                               reinterpret_cast<uint8_t *>(pData));
    SwapOpenSSL(pData);
    pData += BLOWFISH_BLOCK_SIZE;
    size -= BLOWFISH_BLOCK_SIZE;
  }
}

void Crypto::Blowfish::Decrypt(void *pVoidData, uint32_t dataSize) {
  // Make room for the padded block.
  if (0 == (dataSize % BLOWFISH_BLOCK_SIZE)) {
    char *pData = reinterpret_cast<char *>(pVoidData);

    // Decrypt each full block.
    while (BLOWFISH_BLOCK_SIZE <= dataSize) {
      SwapOpenSSL(pData);
      mbedtls_blowfish_crypt_ecb(&d->ctx, MBEDTLS_BLOWFISH_DECRYPT,
                                 reinterpret_cast<uint8_t *>(pData),
                                 reinterpret_cast<uint8_t *>(pData));
      SwapOpenSSL(pData);
      pData += BLOWFISH_BLOCK_SIZE;
      dataSize -= static_cast<uint32_t>(BLOWFISH_BLOCK_SIZE);
    }
  }
}

void Crypto::Blowfish::Decrypt(std::vector<char> &data,
                               std::vector<char>::size_type realSize) {
  std::vector<char>::size_type size = data.size();
  char *pData = &data[0];

  if ((0 == realSize || realSize <= size) &&
      0 == (size % BLOWFISH_BLOCK_SIZE)) {
    // Decrypt each full block.
    while (BLOWFISH_BLOCK_SIZE <= size) {
      SwapOpenSSL(pData);
      mbedtls_blowfish_crypt_ecb(&d->ctx, MBEDTLS_BLOWFISH_DECRYPT,
                                 reinterpret_cast<uint8_t *>(pData),
                                 reinterpret_cast<uint8_t *>(pData));
      SwapOpenSSL(pData);
      pData += BLOWFISH_BLOCK_SIZE;
      size -= BLOWFISH_BLOCK_SIZE;
    }
  }

  // Resize the data if requested.
  if (0 != realSize) {
    data.resize(realSize);
  }
}

void Crypto::Blowfish::EncryptCbc(uint64_t &initializationVector,
                                  std::vector<char> &data) {
  std::vector<char>::size_type size = data.size();
  uint64_t previousBlock = initializationVector;

  // Make room for the padded block.
  if (0 != (size % BLOWFISH_BLOCK_SIZE)) {
    // Round up to a multiple of the block size.
    size = ((size + BLOWFISH_BLOCK_SIZE - 1) / BLOWFISH_BLOCK_SIZE) *
           BLOWFISH_BLOCK_SIZE;

    // Resize the data vector.
    data.resize(size, 0);
  }

  char *pData = &data[0];

  // Encrypt each full block.
  while (BLOWFISH_BLOCK_SIZE <= size) {
    uint64_t unencryptedBlock = *reinterpret_cast<uint64_t *>(pData);
    uint64_t encryptedBlock = unencryptedBlock ^ previousBlock;

    SwapOpenSSL(encryptedBlock);
    mbedtls_blowfish_crypt_ecb(&d->ctx, MBEDTLS_BLOWFISH_ENCRYPT,
                               reinterpret_cast<uint8_t *>(&encryptedBlock),
                               reinterpret_cast<uint8_t *>(&encryptedBlock));
    SwapOpenSSL(encryptedBlock);

    // Save the data back into the vector.
    *reinterpret_cast<uint64_t *>(pData) = encryptedBlock;

    pData += BLOWFISH_BLOCK_SIZE;
    size -= BLOWFISH_BLOCK_SIZE;

    // Save this for the next round.
    previousBlock = encryptedBlock;
  }

  // Save the vector used so one may call this function again.
  initializationVector = previousBlock;
}

void Crypto::Blowfish::DecryptCbc(uint64_t &initializationVector,
                                  std::vector<char> &data,
                                  std::vector<char>::size_type realSize) {
  std::vector<char>::size_type size = data.size();
  uint64_t previousBlock = initializationVector;
  char *pData = &data[0];

  if ((0 == realSize || realSize <= size) &&
      0 == (size % BLOWFISH_BLOCK_SIZE)) {
    // Decrypt each full block.
    while (BLOWFISH_BLOCK_SIZE <= size) {
      uint64_t encryptedBlock = *reinterpret_cast<uint64_t *>(pData);
      uint64_t unencryptedBlock = encryptedBlock;

      SwapOpenSSL(unencryptedBlock);
      mbedtls_blowfish_crypt_ecb(
          &d->ctx, MBEDTLS_BLOWFISH_DECRYPT,
          reinterpret_cast<uint8_t *>(&unencryptedBlock),
          reinterpret_cast<uint8_t *>(&unencryptedBlock));
      SwapOpenSSL(unencryptedBlock);

      unencryptedBlock ^= previousBlock;

      // Save the data back into the vector.
      *reinterpret_cast<uint64_t *>(pData) = unencryptedBlock;

      pData += BLOWFISH_BLOCK_SIZE;
      size -= BLOWFISH_BLOCK_SIZE;

      // Save this for the next round.
      previousBlock = encryptedBlock;
    }
  }

  // Resize the data if requested.
  if (0 != realSize) {
    data.resize(realSize);
  }

  // Save the vector used so one may call this function again.
  initializationVector = previousBlock;
}

String Crypto::HashPassword(const String &password, const String &salt) {
  String hash;
  uint8_t output[MBEDTLS_MD_MAX_SIZE];
  std::string input = String(password + salt).ToUtf8();

  auto pInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

  if (0 == mbedtls_md(pInfo, reinterpret_cast<const uint8_t *>(input.c_str()),
                      input.size(), output)) {
    std::stringstream ss;

    // Convert the bytes into a base-16 string.
    for (int i = 0; i < (int)mbedtls_md_get_size(pInfo); ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0')
         << ((int)output[i] & 0xFF);
    }

    hash = ss.str();
  }

  return hash;
}

String Crypto::SHA1(const std::vector<char> &data) {
  String hash;
  uint8_t output[MBEDTLS_MD_MAX_SIZE];

  auto pInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

  if (0 == mbedtls_md(pInfo, reinterpret_cast<const uint8_t *>(&data[0]),
                      data.size(), output)) {
    std::stringstream ss;

    // Convert the bytes into a base-16 string.
    for (int i = 0; i < (int)mbedtls_md_get_size(pInfo); ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0')
         << ((int)output[i] & 0xFF);
    }

    hash = ss.str();
  }

  return hash;
}

String Crypto::MD5(const std::vector<char> &data) {
  String hash;
  uint8_t output[MBEDTLS_MD_MAX_SIZE];

  auto pInfo = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);

  if (0 == mbedtls_md(pInfo, reinterpret_cast<const uint8_t *>(&data[0]),
                      data.size(), output)) {
    std::stringstream ss;

    // Convert the bytes into a base-16 string.
    for (int i = 0; i < (int)mbedtls_md_get_size(pInfo); ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0')
         << ((int)output[i] & 0xFF);
    }

    hash = ss.str();
  }

  return hash;
}

/**
 * Function to generate random data used by mbedtls.
 * @param rng_state Pointer value passed into the callback.
 * @param output Pointer to the buffer to store the random data.
 * @param len Number of bytes of random data to generate.
 * @returns 0 on success and any other value indicates an error.
 */
static int DiffieHellmanRandom(void *rng_state, unsigned char *output,
                               size_t len) {
  (void)rng_state;

#ifdef WIN32
  HCRYPTPROV hCryptProv;

  // On Windows, use the cryto API to generate the random data. Acquire a
  // context to generate the random data with.
  if (TRUE != CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
    return -1;
  }

  // Generate the random data.
  if (TRUE != CryptGenRandom(hCryptProv, (DWORD)len,
                             reinterpret_cast<PBYTE>(&sessionKey))) {
    return -1;
  }

  // Release the context.
  if (TRUE != CryptReleaseContext(hCryptProv, 0)) {
    return -1;
  }
#elif defined(EXOTIC_PLATFORM)
  return EXOTIC_RANDOM_FUNC(output, len);
#else   // WIN32
  // On Linux, use /dev/urandom.
  std::vector<char> data = Crypto::LoadFile("/dev/urandom", (int)len);

  // Sanity check the size of the random data.
  if (len != data.size()) {
    return -1;
  }

  // Copy the session key.
  memcpy(output, &data[0], len);
#endif  // WIN32

  return 0;
}

Crypto::DiffieHellman::DiffieHellman(const String &prime) {
  d = new DiffieHellmanPrivate;
  d->mValid = false;
  d->mPrime = prime;

  mbedtls_dhm_init(&d->mContext);

  mbedtls_mpi p, g;
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&g);

  if (0 == mbedtls_mpi_read_string(&p, 16, prime.C()) &&
      0 == mbedtls_mpi_read_string(&g, 16, "2") &&
      0 == mbedtls_dhm_set_group(&d->mContext, &p, &g)) {
    d->mValid = true;
  }

  mbedtls_mpi_free(&p);
  mbedtls_mpi_free(&g);
}

Crypto::DiffieHellman::~DiffieHellman() {
  mbedtls_dhm_free(&d->mContext);

  delete d;
  d = nullptr;
}

String Crypto::DiffieHellman::BufferToHexString(const uint8_t *pBuffer,
                                                size_t bufferSize) {
  size_t szBufferSize = 2 * bufferSize + sizeof(uint32_t);
  char *szBuffer = new char[szBufferSize];

  String result;
  mbedtls_mpi x;

  mbedtls_mpi_init(&x);

  size_t olen = 0;

  if (0 == mbedtls_mpi_read_binary(&x, pBuffer, bufferSize) &&
      0 == mbedtls_mpi_write_string(&x, 16, szBuffer, szBufferSize, &olen)) {
    result = String(szBuffer);
  }

  mbedtls_mpi_free(&x);

  delete[] szBuffer;
  szBuffer = nullptr;

  return result;
}

std::vector<uint8_t> Crypto::DiffieHellman::HexStringToBuffer(const String &s) {
  std::vector<uint8_t> result;

  mbedtls_mpi value;
  mbedtls_mpi_init(&value);

  size_t szBufferSize = s.Length() / 2;
  uint8_t *pBuffer = new uint8_t[szBufferSize];

  if (0 == mbedtls_mpi_read_string(&value, 16, s.C()) &&
      0 == mbedtls_mpi_write_binary(&value, pBuffer, szBufferSize)) {
    result = std::vector<uint8_t>(pBuffer, pBuffer + szBufferSize);
  }

  delete[] pBuffer;

  mbedtls_mpi_free(&value);

  return result;
}

String Crypto::DiffieHellman::GetPrime() const { return d->mPrime; }

String Crypto::DiffieHellman::GeneratePublic() {
  String result;

  uint8_t pPublicBinary[DH_KEY_BIT_SIZE / 8];

  if (0 == mbedtls_dhm_make_public(&d->mContext, DH_KEY_BIT_SIZE / 8,
                                   pPublicBinary, sizeof(pPublicBinary),
                                   DiffieHellmanRandom, NULL)) {
    result = BufferToHexString(pPublicBinary, sizeof(pPublicBinary));

    if (!result.IsEmpty()) {
      result = result.RightJustified(DH_KEY_HEX_SIZE, '0');
      d->mPublic = result;
    }
  }

  return result;
}

String Crypto::DiffieHellman::GetPublic() const { return d->mPublic; }

std::vector<char> Crypto::DiffieHellman::GenerateSecret(
    const String &otherPublic) {
  std::vector<char> result;

  uint8_t pSecretBinary[DH_KEY_BIT_SIZE / 8];
  memset(pSecretBinary, 0, sizeof(pSecretBinary));

  std::vector<uint8_t> otherPublicBinary = HexStringToBuffer(otherPublic);

  size_t olen = 0;

  if (0 == mbedtls_dhm_read_public(&d->mContext, &otherPublicBinary[0],
                                   otherPublicBinary.size()) &&
      0 == mbedtls_dhm_calc_secret(&d->mContext, pSecretBinary,
                                   sizeof(pSecretBinary), &olen,
                                   DiffieHellmanRandom, NULL) &&
      olen >= BF_NET_KEY_BYTE_SIZE) {
    result = std::vector<char>((char *)pSecretBinary,
                               (char *)pSecretBinary + BF_NET_KEY_BYTE_SIZE);
    d->mSecret = result;
  }

  return result;
}

std::vector<char> Crypto::DiffieHellman::GetSecret() const {
  return d->mSecret;
}

bool Crypto::DiffieHellman::IsValid() const { return d->mValid; }

std::shared_ptr<Crypto::DiffieHellman> Crypto::DiffieHellman::Generate() {
  assert(false && "You may not generate a Diffie-Hellman prime with mbedtls");
  return {};
}
#else   // USE_MBED_TLS
String Crypto::GenDiffieHellman(const String &g, const String &p,
                                const String &a, int outputSize) {
  BIGNUM *pBase = nullptr, *pPrime = nullptr, *pSecret = nullptr;

  // Convert each argument from a base-16 string to a bignum object.
  if (0 >= BN_hex2bn(&pBase, g.C()) || nullptr == pBase) {
    BN_clear_free(pBase);

    return String();
  }

  if (0 >= BN_hex2bn(&pPrime, p.C()) || nullptr == pPrime) {
    BN_clear_free(pBase);
    BN_clear_free(pPrime);

    return String();
  }

  if (0 >= BN_hex2bn(&pSecret, a.C()) || nullptr == pSecret) {
    BN_clear_free(pBase);
    BN_clear_free(pPrime);
    BN_clear_free(pSecret);

    return String();
  }

  // Create a context.
  BN_CTX *pCtx = BN_CTX_new();

  if (nullptr == pCtx) {
    BN_clear_free(pBase);
    BN_clear_free(pPrime);
    BN_clear_free(pSecret);

    return String();
  }

  // Allocate a bignum object to store the result in.
  BIGNUM *pResult = BN_new();

  if (nullptr == pResult) {
    BN_clear_free(pBase);
    BN_clear_free(pPrime);
    BN_clear_free(pSecret);
    BN_CTX_free(pCtx);

    return String();
  }

  // Clear the value first (this might not be needed).
  BN_clear(pResult);

  // Peform the operation on the value.
  if (1 != BN_mod_exp(pResult, pBase, pSecret, pPrime, pCtx)) {
    BN_clear_free(pResult);
    BN_clear_free(pBase);
    BN_clear_free(pPrime);
    BN_clear_free(pSecret);
    BN_CTX_free(pCtx);

    return String();
  }

  // Free the context and arguments after use.
  BN_clear_free(pBase);
  BN_clear_free(pPrime);
  BN_clear_free(pSecret);
  BN_CTX_free(pCtx);

  // Convert the result to a base-16 string.
  char *pHexResult = BN_bn2hex(pResult);

  if (nullptr == pHexResult) {
    BN_clear_free(pResult);

    return String();
  }

  // Convert the base-16 string to a QString.
  String result = pHexResult;

  // If a specific output size was specified, pad the output to that size.
  if (0 < outputSize) {
    result = result.RightJustified(static_cast<size_t>(outputSize), '0');
  }

  // We no longer need the converted string so free it.
  OPENSSL_free(pHexResult);

  // We no longer need the result.
  BN_clear_free(pResult);

  // Return the final result.
  return result;
}

Crypto::Blowfish::Blowfish() {
  d = new BlowfishPrivate;

  // Use the default key.
  SetKey(
      reinterpret_cast<const unsigned char *>(BaseConfig::ENCRYPTED_FILE_KEY),
      16);
}

Crypto::Blowfish::~Blowfish() {
  delete d;
  d = nullptr;
}

void Crypto::Blowfish::SetKey(const void *pData, size_t dataSize) {
  BF_set_key(&d->key, (int)dataSize,
             reinterpret_cast<const unsigned char *>(pData));
}

void Crypto::Blowfish::Encrypt(void *pVoidData, uint32_t dataSize) {
  // Make room for the padded block.
  if (0 == (dataSize % BLOWFISH_BLOCK_SIZE)) {
    char *pData = reinterpret_cast<char *>(pVoidData);

    // Encrypt each full block.
    while (BLOWFISH_BLOCK_SIZE <= dataSize) {
      BF_encrypt(reinterpret_cast<BF_LONG *>(pData), &d->key);
      pData += BLOWFISH_BLOCK_SIZE;
      dataSize -= static_cast<uint32_t>(BLOWFISH_BLOCK_SIZE);
    }
  }
}

void Crypto::Blowfish::Encrypt(std::vector<char> &data) {
  std::vector<char>::size_type size = data.size();

  // Make room for the padded block.
  if (0 != (size % BLOWFISH_BLOCK_SIZE)) {
    // Round up to a multiple of the block size.
    size = ((size + BLOWFISH_BLOCK_SIZE - 1) / BLOWFISH_BLOCK_SIZE) *
           BLOWFISH_BLOCK_SIZE;

    // Resize the data vector.
    data.resize(size, 0);
  }

  char *pData = &data[0];

  // Encrypt each full block.
  while (BLOWFISH_BLOCK_SIZE <= size) {
    BF_encrypt(reinterpret_cast<BF_LONG *>(pData), &d->key);
    pData += BLOWFISH_BLOCK_SIZE;
    size -= BLOWFISH_BLOCK_SIZE;
  }
}

void Crypto::Blowfish::Decrypt(void *pVoidData, uint32_t dataSize) {
  // Make room for the padded block.
  if (0 == (dataSize % BLOWFISH_BLOCK_SIZE)) {
    char *pData = reinterpret_cast<char *>(pVoidData);

    // Decrypt each full block.
    while (BLOWFISH_BLOCK_SIZE <= dataSize) {
      BF_decrypt(reinterpret_cast<BF_LONG *>(pData), &d->key);
      pData += BLOWFISH_BLOCK_SIZE;
      dataSize -= static_cast<uint32_t>(BLOWFISH_BLOCK_SIZE);
    }
  }
}

void Crypto::Blowfish::Decrypt(std::vector<char> &data,
                               std::vector<char>::size_type realSize) {
  std::vector<char>::size_type size = data.size();
  char *pData = &data[0];

  if ((0 == realSize || realSize <= size) &&
      0 == (size % BLOWFISH_BLOCK_SIZE)) {
    // Decrypt each full block.
    while (BLOWFISH_BLOCK_SIZE <= size) {
      BF_decrypt(reinterpret_cast<BF_LONG *>(pData), &d->key);
      pData += BLOWFISH_BLOCK_SIZE;
      size -= BLOWFISH_BLOCK_SIZE;
    }
  }

  // Resize the data if requested.
  if (0 != realSize) {
    data.resize(realSize);
  }
}

void Crypto::Blowfish::EncryptCbc(uint64_t &initializationVector,
                                  std::vector<char> &data) {
  std::vector<char>::size_type size = data.size();
  uint64_t previousBlock = initializationVector;

  // Make room for the padded block.
  if (0 != (size % BLOWFISH_BLOCK_SIZE)) {
    // Round up to a multiple of the block size.
    size = ((size + BLOWFISH_BLOCK_SIZE - 1) / BLOWFISH_BLOCK_SIZE) *
           BLOWFISH_BLOCK_SIZE;

    // Resize the data vector.
    data.resize(size, 0);
  }

  char *pData = &data[0];

  // Encrypt each full block.
  while (BLOWFISH_BLOCK_SIZE <= size) {
    uint64_t unencryptedBlock = *reinterpret_cast<uint64_t *>(pData);
    uint64_t encryptedBlock = unencryptedBlock ^ previousBlock;

    BF_encrypt(reinterpret_cast<BF_LONG *>(&encryptedBlock), &d->key);

    // Save the data back into the vector.
    *reinterpret_cast<uint64_t *>(pData) = encryptedBlock;

    pData += BLOWFISH_BLOCK_SIZE;
    size -= BLOWFISH_BLOCK_SIZE;

    // Save this for the next round.
    previousBlock = encryptedBlock;
  }

  // Save the vector used so one may call this function again.
  initializationVector = previousBlock;
}

void Crypto::Blowfish::DecryptCbc(uint64_t &initializationVector,
                                  std::vector<char> &data,
                                  std::vector<char>::size_type realSize) {
  std::vector<char>::size_type size = data.size();
  uint64_t previousBlock = initializationVector;
  char *pData = &data[0];

  if ((0 == realSize || realSize <= size) &&
      0 == (size % BLOWFISH_BLOCK_SIZE)) {
    // Decrypt each full block.
    while (BLOWFISH_BLOCK_SIZE <= size) {
      uint64_t encryptedBlock = *reinterpret_cast<uint64_t *>(pData);
      uint64_t unencryptedBlock = encryptedBlock;

      BF_decrypt(reinterpret_cast<BF_LONG *>(&unencryptedBlock), &d->key);

      unencryptedBlock ^= previousBlock;

      // Save the data back into the vector.
      *reinterpret_cast<uint64_t *>(pData) = unencryptedBlock;

      pData += BLOWFISH_BLOCK_SIZE;
      size -= BLOWFISH_BLOCK_SIZE;

      // Save this for the next round.
      previousBlock = encryptedBlock;
    }
  }

  // Resize the data if requested.
  if (0 != realSize) {
    data.resize(realSize);
  }

  // Save the vector used so one may call this function again.
  initializationVector = previousBlock;
}

String Crypto::HashPassword(const String &password, const String &salt) {
  String hash;
  std::string input = String(password + salt).ToUtf8();
  unsigned char output[SHA512_DIGEST_LENGTH];

  if (output == SHA512(reinterpret_cast<const unsigned char *>(input.c_str()),
                       static_cast<size_t>(input.size()), output)) {
    std::stringstream ss;

    // Convert the bytes into a base-16 string.
    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0')
         << ((int)output[i] & 0xFF);
    }

    hash = ss.str();
  }

  return hash;
}

String Crypto::SHA1(const std::vector<char> &data) {
  String hash;
  unsigned char output[SHA512_DIGEST_LENGTH];

  if (output == ::SHA1(reinterpret_cast<const unsigned char *>(&data[0]),
                       static_cast<size_t>(data.size()), output)) {
    std::stringstream ss;

    // Convert the bytes into a base-16 string.
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0')
         << ((int)output[i] & 0xFF);
    }

    hash = ss.str();
  }

  return hash;
}

String Crypto::MD5(const std::vector<char> &data) {
  String hash;
  unsigned char output[MD5_DIGEST_LENGTH];

  if (output == ::MD5(reinterpret_cast<const unsigned char *>(&data[0]),
                      static_cast<size_t>(data.size()), output)) {
    std::stringstream ss;

    // Convert the bytes into a base-16 string.
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0')
         << ((int)output[i] & 0xFF);
    }

    hash = ss.str();
  }

  return hash;
}

Crypto::DiffieHellman::DiffieHellman(const String &prime) {
  d = new DiffieHellmanPrivate;
  d->mValid = false;
  d->mContext = nullptr;
  d->mPrime = prime;

  if (DH_KEY_HEX_SIZE == prime.Length()) {
    d->mContext = DH_new();

    if (nullptr != d->mContext) {
      DH_set0_key(d->mContext, nullptr, nullptr);

      BIGNUM *p = nullptr, *g = nullptr;

      if (0 >= BN_hex2bn(&p, prime.C()) || 0 >= BN_hex2bn(&g, DH_BASE_STRING) ||
          nullptr == p || nullptr == g) {
        LogCryptoDebug([&]() { return String("prime=%1\n").Arg(prime); });

        DH_free(d->mContext);
        d->mContext = nullptr;

        if (nullptr != p) {
          OPENSSL_free(p);
          p = nullptr;
        }

        if (nullptr != g) {
          OPENSSL_free(g);
          g = nullptr;
        }
      }

      if (d->mContext) {
        DH_set0_pqg(d->mContext, p, nullptr, g);
      }

      if (d->mContext && DH_SHARED_DATA_SIZE != DH_size(d->mContext)) {
        LogCryptoDebug([&]() { return String("prime=%1\n").Arg(prime); });

        LogCryptoDebug([&]() {
          return String("DH_SHARED_DATA_SIZE=%1/%2\n")
              .Arg(DH_SHARED_DATA_SIZE)
              .Arg(DH_size(d->mContext));
        });

        DH_free(d->mContext);
        d->mContext = nullptr;
      } else {
        d->mValid = true;
      }
    } else {
      LogCryptoErrorMsg("Failed to alloc diffie hellman\n");
    }
  } else {
    LogCryptoError([&]() {
      return String("DH_KEY_HEX_SIZE=%1/%2")
          .Arg(DH_KEY_HEX_SIZE)
          .Arg(prime.Length());
    });
  }
}

Crypto::DiffieHellman::~DiffieHellman() {
  DH_free(d->mContext);

  delete d;
  d = nullptr;
}

String Crypto::DiffieHellman::BufferToHexString(const uint8_t *pBuffer,
                                                size_t bufferSize) {
  (void)pBuffer;
  (void)bufferSize;

  return {};
}

std::vector<uint8_t> Crypto::DiffieHellman::HexStringToBuffer(const String &s) {
  (void)s;

  return {};
}

String Crypto::DiffieHellman::GetPrime() const { return d->mPrime; }

String Crypto::DiffieHellman::GeneratePublic() {
  if (!d->mContext) {
    return {};
  }

  String publicKey;

  const BIGNUM *p = nullptr, *q = nullptr, *g = nullptr;
  DH_get0_pqg(d->mContext, &p, &q, &g);

  if (nullptr != p && nullptr != g && 1 == DH_generate_key(d->mContext)) {
    const BIGNUM *pub_key = DH_get0_pub_key(d->mContext);

    if (nullptr != pub_key) {
      char *pHexResult = BN_bn2hex(pub_key);

      if (nullptr != pHexResult) {
        publicKey = String(pHexResult);
        d->mPublic = publicKey;

        OPENSSL_free(pHexResult);
      }
    }
  }

  return publicKey;
}

String Crypto::DiffieHellman::GetPublic() const { return d->mPublic; }

std::vector<char> Crypto::DiffieHellman::GenerateSecret(
    const String &otherPublic) {
  if (!d->mContext) {
    return {};
  }

  std::vector<char> data;

  unsigned char sharedData[DH_SHARED_DATA_SIZE];

  const BIGNUM *pub_key = DH_get0_pub_key(d->mContext);
  const BIGNUM *p = nullptr, *q = nullptr, *g = nullptr;
  DH_get0_pqg(d->mContext, &p, &q, &g);

  if (nullptr != p && nullptr != g && nullptr != pub_key &&
      DH_SHARED_DATA_SIZE == DH_size(d->mContext)) {
    BIGNUM *pOtherPublic = nullptr;

    if (0 < BN_hex2bn(&pOtherPublic, otherPublic.C()) &&
        nullptr != pOtherPublic &&
        BF_NET_KEY_BYTE_SIZE <=
            DH_compute_key(sharedData, pOtherPublic, d->mContext)) {
      data.insert(
          data.begin(), reinterpret_cast<const char *>(sharedData),
          reinterpret_cast<const char *>(sharedData) + BF_NET_KEY_BYTE_SIZE);
      d->mSecret = data;
    }

    if (nullptr != pOtherPublic) {
      BN_clear_free(pOtherPublic);
      pOtherPublic = nullptr;
    }
  }

  return data;
}

std::vector<char> Crypto::DiffieHellman::GetSecret() const {
  return d->mSecret;
}

bool Crypto::DiffieHellman::IsValid() const { return d->mValid; }

static String GetDiffieHellmanPrime(const DH *pDiffieHellman) {
  if (!pDiffieHellman) {
    return {};
  }

  String prime;

  const BIGNUM *p = DH_get0_p(pDiffieHellman);

  if (nullptr != p) {
    char *pHexResult = BN_bn2hex(p);

    if (nullptr != pHexResult) {
      prime = pHexResult;

      OPENSSL_free(pHexResult);

      if (DH_KEY_HEX_SIZE != prime.Length()) {
        prime.Clear();
      }
    }
  }

  return prime;
}

std::shared_ptr<Crypto::DiffieHellman> Crypto::DiffieHellman::Generate() {
  auto dh = std::make_shared<Crypto::DiffieHellman>(String());
  DH_free(dh->d->mContext);
  dh->d->mValid = false;
  dh->d->mPrime.Clear();

  int codes;

  dh->d->mContext = DH_new();

  if (nullptr != dh->d->mContext) {
    if (1 != DH_generate_parameters_ex(dh->d->mContext, DH_KEY_BIT_SIZE,
                                       DH_BASE_INT, NULL)) {
      DH_free(dh->d->mContext);
      dh->d->mContext = nullptr;
    }

    const BIGNUM *p = nullptr, *q = nullptr, *g = nullptr;

    if (dh->d->mContext) {
      DH_get0_pqg(dh->d->mContext, &p, &q, &g);
    }

    if (dh->d->mContext && (nullptr == p || nullptr == g ||
                            1 != DH_check(dh->d->mContext, &codes) ||
                            DH_SHARED_DATA_SIZE != DH_size(dh->d->mContext))) {
      DH_free(dh->d->mContext);
      dh->d->mContext = nullptr;
    } else {
      dh->d->mPrime = GetDiffieHellmanPrime(dh->d->mContext);
      dh->d->mValid = !dh->d->mPrime.IsEmpty();
    }
  }

  if (dh->d->mContext) {
    dh.reset();
  }

  return dh;
}
#endif  // USE_MBED_TLS

void Crypto::Blowfish::SetKey(const std::vector<char> &key) {
  SetKey(&key[0], key.size());
}

void Crypto::Blowfish::EncryptCbc(std::vector<char> &data) {
  uint64_t initializationVector =
      *reinterpret_cast<const uint64_t *>(BaseConfig::ENCRYPTED_FILE_IV);

  EncryptCbc(initializationVector, data);
}

void Crypto::Blowfish::DecryptCbc(std::vector<char> &data,
                                  std::vector<char>::size_type realSize) {
  uint64_t initializationVector =
      *reinterpret_cast<const uint64_t *>(BaseConfig::ENCRYPTED_FILE_IV);

  DecryptCbc(initializationVector, data, realSize);
}

void Crypto::Blowfish::EncryptPacket(Packet &packet) {
  uint32_t realSize =
      packet.Size() - 2 * static_cast<uint32_t>(sizeof(uint32_t));

  // Write the real size.
  packet.Seek(sizeof(uint32_t));
  packet.WriteU32Big(realSize);

  // Round up the size of the packet to a multiple of BLOWFISH_BLOCK_SIZE.
  uint32_t paddedSize = static_cast<uint32_t>(
      ((realSize + BLOWFISH_BLOCK_SIZE - 1) / BLOWFISH_BLOCK_SIZE) *
      BLOWFISH_BLOCK_SIZE);

  // Make sure the packet is padded.
  if (realSize != paddedSize) {
    packet.End();
    packet.WriteBlank(paddedSize - realSize);
  }

  // Determine the start of the data to encrypt.
  char *pData = packet.Data();
  pData += 2 * sizeof(uint32_t);

  // Encrypt the packet.
  Encrypt(pData, paddedSize);

  // Write the padded size.
  packet.Rewind();
  packet.WriteU32Big(paddedSize);
  packet.End();
}

void Crypto::Blowfish::DecryptPacket(Packet &packet) {
  // The packet must have at least one block and the sizes.
  if ((2 * sizeof(uint32_t) + BLOWFISH_BLOCK_SIZE) <= packet.Size()) {
    // Start from the beginning of the packet.
    packet.Rewind();

    // Get the padded size of the packet.
    uint32_t paddedSize = packet.ReadU32Big();

    // Determine the start of the data to decrypt.
    char *pData = packet.Data();
    pData += 2 * sizeof(uint32_t);

    // Encrypt the packet.
    Decrypt(pData, paddedSize);
  }
}
