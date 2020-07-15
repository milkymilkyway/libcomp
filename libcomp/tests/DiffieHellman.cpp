/**
 * @file libcomp/tests/DiffieHellman.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Test the Diffie-Hellman key exchange.
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
#include <Crypto.h>
#include <PushIgnore.h>
#include <TcpConnection.h>
#include <TcpServer.h>

using namespace libcomp;

TEST(DiffieHellman, KeyExchange) {
  // (server=>client) First packet.
  // Sends base, prime, and server public.
  String prime =
      "9C4169BBE8F535F7A7404D4EB3AE22CF63C0450FC2C7B2A5A03794D4CFA9F290FF577426"
      "7885E60B848280E3A07468366E62F040DAC3CB67E95E8F3DC4D97F94AD1D3D98F0B066F7"
      "2B65CB391643A95BB96CF048ED5D60FB7AF7A969F38ABD2301F6A7EC4DB7DAFC2CFD1F41"
      "7E0B634033FEE8B102D62A28EC03D95266E2B0B3";
  ASSERT_EQ(prime.Length(), DH_KEY_HEX_SIZE);

  Crypto::DiffieHellman dhServer(prime);
  ASSERT_TRUE(dhServer.IsValid());

  String serverPublic = dhServer.GeneratePublic();
  ASSERT_EQ(serverPublic.Length(), DH_KEY_HEX_SIZE);

  // (client=>server) Second packet.
  // Gets base, prime, and server public.
  // Sends client public.
  // Calculates client copy of shared data.
  Crypto::DiffieHellman dhClient(prime);
  ASSERT_TRUE(dhClient.IsValid());

  String clientPublic = dhClient.GeneratePublic();
  ASSERT_EQ(clientPublic.Length(), DH_KEY_HEX_SIZE);

  std::vector<char> clientData = dhClient.GenerateSecret(serverPublic);
  ASSERT_EQ(clientData.size(), BF_NET_KEY_BYTE_SIZE);

  // (server) Third packet.
  // Gets client public.
  // Calculates server copy of shared data.
  std::vector<char> serverData = dhServer.GenerateSecret(clientPublic);
  ASSERT_EQ(serverData.size(), BF_NET_KEY_BYTE_SIZE);

  // Check they have the same data.
  ASSERT_EQ(memcmp(&serverData[0], &clientData[0], serverData.size()), 0);

  // Check the public keys do not match.
  ASSERT_NE(serverPublic, clientPublic);
}

int main(int argc, char *argv[]) {
  try {
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
  } catch (...) {
    return EXIT_FAILURE;
  }
}
