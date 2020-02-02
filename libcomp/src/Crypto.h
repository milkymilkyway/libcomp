/**
 * @file libcomp/src/Crypto.h
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Encryption and decryption function definitions.
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

#ifndef LIBCOMP_SRC_DECRYPT_H
#define LIBCOMP_SRC_DECRYPT_H

/// libcomp Includes
#include "CString.h"

#include <stdint.h>

#include <string>
#include <vector>

namespace libcomp
{

/// Size (in bytes) of a block of Blowfish encrypted data.
const std::size_t BLOWFISH_BLOCK_SIZE = sizeof(uint64_t);

class Packet;

/**
 * Encryption and Decryption functions.
 */
namespace Crypto
{

/**
 * @brief Decrypt a file buffer.
 * @param buffer Buffer of the file to be decrypted.
 * @retval true File was decrypted.
 * @retval false File was not decrypted.
 * @sa Decrypt::EncryptFile
 * @sa Config::ENCRYPTED_FILE_MAGIC
 * @sa Config::ENCRYPTED_FILE_KEY
 * @sa Config::ENCRYPTED_FILE_IV
 */
bool DecryptFile(std::vector<char>& buffer);

/**
 * @brief Decrypt a file into a buffer.
 * @param path Path to the file to be decrypted.
 * @returns Buffer of the decrypted file. Will be empty if an error occurred.
 * @sa Decrypt::EncryptFile
 * @sa Config::ENCRYPTED_FILE_MAGIC
 * @sa Config::ENCRYPTED_FILE_KEY
 * @sa Config::ENCRYPTED_FILE_IV
 */
std::vector<char> DecryptFile(const std::string& path);

/**
 * Encrypt a file buffer.
 * @param buffer Buffer of the file to be encrypted.
 * @retval true File was encrypted.
 * @retval false File was not encrypted.
 * @sa Decrypt::DecryptFile
 * @sa Config::ENCRYPTED_FILE_MAGIC
 * @sa Config::ENCRYPTED_FILE_KEY
 * @sa Config::ENCRYPTED_FILE_IV
 */
bool EncryptFile(std::vector<char>& data);

/**
 * Encrypt a file from a buffer.
 * @param Path to the file to be written to.
 * @param data Data to be encrypted.
 * @retval true File was encrypted.
 * @retval false File was not encrypted.
 * @sa Decrypt::DecryptFile
 * @sa Config::ENCRYPTED_FILE_MAGIC
 * @sa Config::ENCRYPTED_FILE_KEY
 * @sa Config::ENCRYPTED_FILE_IV
 */
bool EncryptFile(const std::string& path, const std::vector<char>& data);

/**
 * Load a file into a buffer
 * @param path Path to the file to be loaded.
 * @param requestedSize Number of bytes to read from the file. If this is
 *   negative, the entire file will be read.
 * @returns The loaded file data or an empty vector if an error occured.
 */
std::vector<char> LoadFile(const std::string& path, int requestedSize = -1);

/**
 * Generates random data to be used during key exchange. The returned data will
 * be a series of hex digits.
 *
 * @param sz Number of digits of random data to generate. If -1 is used, the
 *   default number of digits will be generated (80 digits).
 * @returns The random data encoded as a base-16 string or an empty string if
 *   an error occured.
 */
String GenerateRandom(int sz = -1);

/**
 * Generates a random value. This value is used to identify a login session
 * when passing an authenticated user from the lobby server to the
 * channel server.
 *
 * @returns Random value to identify a transitioning client or 0 if an error
 *   occured.
 */
uint32_t GenerateSessionKey();

/**
 * Generate the result of the operation g^a % p
 * @param g Base number represented as a base-16 string.
 * @param p Prime number represented as a base-16 string.
 * @param a Secret number represented as a base-16 string.
 * @param outputSize Number of characters to output. Smaller values will be
 *   padded with zeros. Any value of 0 or less will disable output padding.
 * @returns A base-16 string representing the operation g^a % p or an empty
 *   string if an error occured.
 */
String GenDiffieHellman(const String& g, const String& p,
    const String& a, int outputSize = -1);

struct BlowfishPrivate;
struct DiffieHellmanPrivate;

/**
 * This class will perform a Diffie-Hellman-Merkle key exchange.
 */
class DiffieHellman
{
public:
    /**
     * Construct a new pair using the given prime.
     * @param prime Prime number in big endian hex.
     */
    explicit DiffieHellman(const String &prime);

    /**
     * Free the key pair.
     */
    ~DiffieHellman();

    /**
     * Get the prime used for this key.
     */
    String GetPrime() const;

    /**
     * Generate and return the public key.
     * @returns Public key for this side of the exchange or a blank string
     * on error.
     */
    String GeneratePublic();

    /**
     * Get the public key for this side of the exchange.
     * @returns Public key for this side of the exchange.
     */
    String GetPublic() const;

    /**
     * Take the other side's public key and generate the shared secret.
     * @returns Shared secret from the key exchange or an empty vector on error.
     */
    std::vector<char> GenerateSecret(const String &otherPublic);

    /**
     * Gets the shared secret from the key exchange.
     * @returns Shared secret from the key exchange.
     */
    std::vector<char> GetSecret() const;

    /**
     * Check if the key exchange is valid. This should only be needed if the
     * prime is wrong.
     * @returns true if the key exchange is valid; false otherwise.
     */
    bool IsValid() const;

    /**
     * Generate a Diffie-Hellman key exchange with a new prime.
     * @note This only works when using OpenSSL.
     * @returns Generated key exchange.
     */
    static std::shared_ptr<Crypto::DiffieHellman> Generate();

protected:
    /**
     * Convert the binary buffer to a big endian hex string.
     * @param pBuffer Pointer to the binary buffer.
     * @param bufferSize Size in bytes of the binary buffer.
     * @returns Hex string representing the binary buffer.
     */
    static String BufferToHexString(const uint8_t *pBuffer,
                                    size_t bufferSize);

    /**
     * Convert the big endian hex string to a binary buffer.
     * @param s Hex string to convert to a binary buffer
     * @returns A binary buffer for the hex string.
     */
    static std::vector<uint8_t> HexStringToBuffer(const String &s);

private:
    /// Private data that is specific to the libary.
    DiffieHellmanPrivate *d;
};

/**
 * This class will encrypt and decrypt data using the blowfish algorithm.
 */
class Blowfish
{
public:
    /**
     * Encrypt and decrypt with the default Blowfish key.
     * @sa Config::ENCRYPTED_FILE_KEY
     */
    Blowfish();

    /**
     * Free the blowfish key.
     */
    ~Blowfish();

    /**
     * Copy not allowed.
     */
    Blowfish(const Blowfish& other) = delete;

    /**
     * Copy not allowed.
     */
    Blowfish& operator=(const Blowfish& other) = delete;

    /**
     * Set the blowfish key.
     * @param pData Pointer to the buffer with the key.
     * @param dataSize Size in bytes of the key.
     */
    void SetKey(const void *pData, size_t dataSize);

    /**
     * Set the blowfish key.
     * @param key Blowfish key to use.
     */
    void SetKey(const std::vector<char>& key);

    /**
     * Encrypt a data buffer with Blowfish.
     * @param pData Data to be encrypted.
     * @param dataSize Size of the data to be encrypted (in bytes).
     * @note The data size should be a multiple of BLOWFISH_BLOCK_SIZE.
     */
    void Encrypt(void *pData, uint32_t dataSize);

    /**
     * Encrypt a data buffer with Blowfish.
     * @param data Data to be encrypted. The size may change on return.
     */
    void Encrypt(std::vector<char>& data);

    /**
     * Decrypt a data buffer with Blowfish.
     * @param pData Data to be decrypted.
     * @param dataSize Size of the data to be decrypted (in bytes).
     * @note The data size should be a multiple of BLOWFISH_BLOCK_SIZE.
     */
    void Decrypt(void *pData, uint32_t dataSize);

    /**
     * Decrypt a data buffer with Blowfish.
     * @param data Data to be decrypted.
     * @param realSize Size to shrink the buffer to after decryption.
     */
    void Decrypt(std::vector<char>& data,
        std::vector<char>::size_type realSize = 0);

    /**
     * Encrypt a data buffer with Blowfish and Cipher Block Chaining (CBC).
     * @param initializationVector Initial value to feed into the CBC algorithm.
     * @param data Data to be encrypted. The size may change on return.
     */
    void EncryptCbc(uint64_t& initializationVector,
        std::vector<char>& data);

    /**
     * Encrypt a data buffer with the default Blowfish key and Cipher Block
     * Chaining (CBC) initialization vector (IV).
     *
     * @param data Data to be encrypted. The size may change on return.
     * @sa Config::ENCRYPTED_FILE_KEY
     * @sa Config::ENCRYPTED_FILE_IV
     */
    void EncryptCbc(std::vector<char>& data);

    /**
     * Decrypt a data buffer with Blowfish and Cipher Block Chaining (CBC).
     * @param initializationVector Initial value to feed into the CBC algorithm.
     * @param data Data to be decrypted.
     * @param realSize Size to shrink the buffer to after decryption.
     */
    void DecryptCbc(uint64_t& initializationVector,
        std::vector<char>& data, std::vector<char>::size_type realSize = 0);

    /**
     * Decrypt a data buffer with the default Blowfish key and Cipher Block
     * Chaining (CBC) initialization vector (IV).
     *
     * @param data Data to be decrypted.
     * @param realSize Size to shrink the buffer to after decryption.
     * @sa Config::ENCRYPTED_FILE_KEY
     * @sa Config::ENCRYPTED_FILE_IV
     */
    void DecryptCbc(std::vector<char>& data,
        std::vector<char>::size_type realSize = 0);

    /**
     * Encrypt a packet.
     * @param p The packet to encrypt.
     */
    void EncryptPacket(Packet& p);

    /**
     * Decrypt a packet.
     * @param p The packet to decrypt.
     */
    void DecryptPacket(Packet& p);

private:
    /// Private data for the blowfish algorithm (the key).
    BlowfishPrivate *d;
};

/**
 * Generate a password hash.
 * @param password Clear text password to hash.
 * @param salt Salt to append to the password before hashing.
 * @returns Hash for the given password.
 */
String HashPassword(const String& password, const String& salt);

/**
 * Generate a SHA-1 hash of the given data.
 * @param data Data to generate the hash of.
 * @returns SHA-1 hash string of the given data.
 */
String SHA1(const std::vector<char>& data);

/**
 * Generate a MD5 hash of the given data.
 * @param data Data to generate the hash of.
 * @returns MD5 hash string of the given data.
 */
String MD5(const std::vector<char>& data);

} // namespace Crypto

} // namespace libcomp

#endif // LIBCOMP_SRC_DECRYPT_H
