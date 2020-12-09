/**
 * @file libcomp/tests/Crypto.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Encryption unit tests.
 *
 * This file is part of the COMP_hack Library (libcomp).
 *
 * Copyright (C) 2014-2020 COMP_hack Team <compomega@tutanota.com>
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

// Ignore warnings
#include <PopIgnore.h>

// Google Test Includes
#include <gtest/gtest.h>

// Stop ignoring warnings
#include <Config.h>
#include <Crypto.h>
#include <Exception.h>
#include <PushIgnore.h>

#include <regex>

using namespace libcomp;

TEST(GenerateRandom, DefaultsTo80Digits) {
  ASSERT_FALSE(Crypto::GenerateRandom().IsEmpty())
      << "GenerateRandom "
         "should not return an error on any sane server.";

  ASSERT_EQ(Crypto::GenerateRandom().Length(), 80)
      << "GenerateRandom defaults to a wrong string length.";
}

TEST(GenerateRandom, OddOutputGeneratesError) {
  ASSERT_THROW(Crypto::GenerateRandom(3), libcomp::Exception)
      << "GenerateRandom should return an error for odd string lengths.";
}

TEST(GenerateRandom, OutputIsHex) {
  ASSERT_TRUE(std::regex_match(Crypto::GenerateRandom().ToUtf8(),
                               std::regex("^[a-zA-Z0-9]*$")))
      << "GenerateRandom should return "
         "valid hex.";
}

TEST(GenerateRandom, OutputChanges) {
  ASSERT_NE(Crypto::GenerateRandom(), Crypto::GenerateRandom())
      << "GenerateRandom is always returning the same value.";
}

TEST(GenerateRandom, SpecificLengthEqualsOutput) {
  ASSERT_EQ(Crypto::GenerateRandom(20).Length(), 20)
      << "GenerateRandom should return the length given.";
}

TEST(GenerateRandom, NegativeOrZeroReturnsDefault) {
  EXPECT_EQ(Crypto::GenerateRandom(0).Length(), 80)
      << "GenerateRandom should return an empty string for an invalid size.";

  EXPECT_EQ(Crypto::GenerateRandom(-11).Length(), 80)
      << "GenerateRandom should return an empty string for an invalid size.";
}

TEST(GenerateSessionKey, ValueIsNotNegative) {
  for (int i = 0; i < 1000; ++i) {
    EXPECT_GT((int)Crypto::GenerateSessionKey(), 0)
        << "GenerateSessionKey should not be negative.";
  }
}

TEST(GenerateSessionKey, ValueChangesBetweenCalls) {
  for (int i = 0; i < 1000; ++i) {
    EXPECT_NE(Crypto::GenerateSessionKey(), 0)
        << "GenerateSessionKey should not return an error on any sane server.";

    EXPECT_NE(Crypto::GenerateSessionKey(), Crypto::GenerateSessionKey())
        << "GenerateSessionKey is always returning the same value.";
  }
}

TEST(Decrypt, LoadFile) {
  // Read the first 4 bytes from a file. Should be OK for a stream.
#if _WIN32
  EXPECT_EQ(4, Crypto::LoadFile("c:\\windows\\explorer.exe", 4).size());
#else
  EXPECT_EQ(4, Crypto::LoadFile("/dev/urandom", 4).size());
#endif  // _WIN32

  // Attempt to read an entire stream. This should fail.
  EXPECT_EQ(0, Crypto::LoadFile("/dev/urandom").size());

  // We should be able to read the entire contents of a regular file.
#if _WIN32
  EXPECT_NE(0, Crypto::LoadFile("c:\\windows\\system.ini").size());
#else
  EXPECT_NE(0, Crypto::LoadFile("/proc/version").size());
#endif  // _WIN32

  // Try a directory.
#if _WIN32
  EXPECT_EQ(0, Crypto::LoadFile("c:\\windows").size());
#else
  EXPECT_EQ(0, Crypto::LoadFile("/etc").size());
#endif  // _WIN32

  // Try a bad path.
  EXPECT_EQ(0, Crypto::LoadFile("/_bad_path_").size());
}

#ifndef USE_MBED_TLS
TEST(GenDiffieHellman, EmptyArgsReturnError) {
  EXPECT_TRUE(Crypto::GenDiffieHellman(String(), String(), String()).IsEmpty())
      << "GenDiffieHellman should return an empty string with empty arguments.";
}

TEST(GenDiffieHellman, BadArgsReturnError) {
  EXPECT_TRUE(Crypto::GenDiffieHellman("Z", "200", "3").IsEmpty())
      << "GenDiffieHellman should return an empty string with bad arguments.";

  EXPECT_TRUE(Crypto::GenDiffieHellman("a", "^", "3").IsEmpty())
      << "GenDiffieHellman should return an empty string with bad arguments.";

  EXPECT_TRUE(Crypto::GenDiffieHellman("a", "200", "*").IsEmpty())
      << "GenDiffieHellman should return an empty string with bad arguments.";
}

TEST(GenDiffieHellman, ReturnsCorrectAnswer) {
  EXPECT_EQ(Crypto::GenDiffieHellman("a", "200", "3").ToLower(), "01e8")
      << "GenDiffieHellman should return the correct answer.";

  EXPECT_EQ(
      Crypto::GenDiffieHellman(
          "132D492f1B19DC66171851Be1736fC7c1658f3F610Ce0632139843b01732D5A2",
          "0010000000000000000", "2")
          .ToLower(),
      "4032b73b418efa84")
      << "GenDiffieHellman should return the correct answer.";
}

TEST(GenDiffieHellman, PaddingWorks) {
  EXPECT_EQ(Crypto::GenDiffieHellman("a", "200", "3", 8).ToLower(), "000001e8")
      << "GenDiffieHellman should return the correct answer with padding "
         "added.";

  // A padding (outputSize) value that is too low should not truncate
  // the result.
  EXPECT_EQ(
      Crypto::GenDiffieHellman(
          "132D492f1B19DC66171851Be1736fC7c1658f3F610Ce0632139843b01732D5A2",
          "0010000000000000000", "2", 8)
          .ToLower(),
      "4032b73b418efa84")
      << "GenDiffieHellman should return the correct answer with padding if "
         "the result is less thanthe output size specified.";
}
#endif

TEST(EncryptDecrypt, File) {
#if _WIN32
#define TEMP_FILE "c:\\windows\\temp\\test.bin"
#else
#define TEMP_FILE "/tmp/test.bin"
#endif  // _WIN32

  static const unsigned char decryptedFile[] = {
      0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
      0x65, 0x73, 0x74, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x0a};

  static const unsigned char encryptedFile[] = {
      0x89, 0x58, 0x42, 0x46, 0x15, 0x00, 0x00, 0x00, 0x20, 0xd6, 0xb3,
      0xca, 0x17, 0xc6, 0xfd, 0xd1, 0xae, 0x31, 0xcf, 0x7c, 0xe5, 0xdd,
      0x37, 0xba, 0xc5, 0x98, 0x7d, 0xba, 0x82, 0x1a, 0x9f, 0x48};

  static const unsigned char encryptedFile2[] = {
      0x43, 0x48, 0x45, 0x44, 0x15, 0x00, 0x00, 0x00, 0x20, 0x9b, 0x0e,
      0x4a, 0x65, 0x48, 0x05, 0x46, 0xb2, 0x55, 0x3b, 0x53, 0x2c, 0x71,
      0xcf, 0x77, 0xbd, 0xa0, 0xb3, 0x1c, 0x2b, 0x53, 0x5e, 0xaf};

  std::vector<char> decryptedData(
      reinterpret_cast<const char *>(decryptedFile),
      reinterpret_cast<const char *>(decryptedFile) + sizeof(decryptedFile));
  std::vector<char> encryptedData;

  if (0 == strcmp("CHED", Config::ENCRYPTED_FILE_MAGIC)) {
    encryptedData =
        std::vector<char>(reinterpret_cast<const char *>(encryptedFile2),
                          reinterpret_cast<const char *>(encryptedFile2) +
                              sizeof(encryptedFile2));
  } else {
    encryptedData = std::vector<char>(
        reinterpret_cast<const char *>(encryptedFile),
        reinterpret_cast<const char *>(encryptedFile) + sizeof(encryptedFile));
  }

  ASSERT_TRUE(Crypto::EncryptFile(TEMP_FILE, decryptedData));

  std::vector<char> dataCopy = Crypto::LoadFile(TEMP_FILE);

  EXPECT_EQ(dataCopy.size(), encryptedData.size());

  if (dataCopy.size() == encryptedData.size()) {
    EXPECT_EQ(memcmp(&dataCopy[0], &encryptedData[0], encryptedData.size()), 0);
  }

  dataCopy = Crypto::DecryptFile(TEMP_FILE);

  EXPECT_EQ(dataCopy.size(), decryptedData.size());

  if (dataCopy.size() == decryptedData.size()) {
    EXPECT_EQ(memcmp(&dataCopy[0], &decryptedData[0], decryptedData.size()), 0);
  }
}

TEST(Hash, Password) {
  String hash =
      "e6e8ba72bf2bab68c923599a08489c6f3a35018e870d490fa25b4c2a2d82361093b9a8f1"
      "d0cdd02e5a7dd5e714dc090263e2e90af3d3d861c056f28a4adb2d95";

  EXPECT_EQ(hash, Crypto::HashPassword("test", "12345"));
}

TEST(Hash, SHA1) {
  String hash = "e6c4fbd4fe7607f3e6ebf68b2ea4ef694da7b4fe";

  static const unsigned char dataBuffer[] = {
      0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
      0x65, 0x73, 0x74, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x0a};

  std::vector<char> data(
      reinterpret_cast<const char *>(dataBuffer),
      reinterpret_cast<const char *>(dataBuffer) + sizeof(dataBuffer));

  EXPECT_EQ(hash, Crypto::SHA1(data));
}

TEST(Hash, MD5) {
  String hash = "2d282102fa671256327d4767ec23bc6b";

  static const unsigned char dataBuffer[] = {
      0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
      0x65, 0x73, 0x74, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x0a};

  std::vector<char> data(
      reinterpret_cast<const char *>(dataBuffer),
      reinterpret_cast<const char *>(dataBuffer) + sizeof(dataBuffer));

  EXPECT_EQ(hash, Crypto::MD5(data));
}

int main(int argc, char *argv[]) {
  try {
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
  } catch (...) {
    return EXIT_FAILURE;
  }
}
