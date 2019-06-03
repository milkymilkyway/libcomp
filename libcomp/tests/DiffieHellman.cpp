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
 * Copyright (C) 2014-2016 COMP_hack Team <compomega@tutanota.com>
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

#include <PushIgnore.h>
#include <gtest/gtest.h>
#include <PopIgnore.h>

#include <Log.h>
#include <TcpServer.h>
#include <TcpConnection.h>

using namespace libcomp;

TEST(DiffieHellman, GenerateSaveLoad)
{
    DH *pDiffieHellman = TcpServer::GenerateDiffieHellman();
    ASSERT_NE(pDiffieHellman, nullptr);

    String prime = TcpConnection::GetDiffieHellmanPrime(pDiffieHellman);
    ASSERT_EQ(prime.Length(), DH_KEY_HEX_SIZE);

    DH *pCopy = TcpServer::CopyDiffieHellman(pDiffieHellman);
    ASSERT_NE(pCopy, nullptr);

    std::vector<char> data = TcpServer::SaveDiffieHellman(pDiffieHellman);
    ASSERT_EQ(data.size(), DH_SHARED_DATA_SIZE);

    ASSERT_EQ(TcpConnection::GetDiffieHellmanPrime(pCopy), prime);

    DH_free(pDiffieHellman);
    DH_free(pCopy);

    pDiffieHellman = TcpServer::LoadDiffieHellman(data);
    ASSERT_NE(pDiffieHellman, nullptr);

    ASSERT_EQ(TcpConnection::GetDiffieHellmanPrime(pDiffieHellman), prime);

    DH_free(pDiffieHellman);
}

#if 0
inline void ExecTime(std::chrono::high_resolution_clock::time_point& t1,
    const libcomp::String& title = "Time")
{
    std::chrono::high_resolution_clock::time_point t2 =
        std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<
        std::chrono::microseconds>(t2 - t1).count();
    LOG_DEBUG(libcomp::String("%1: %2\n").Arg(title).Arg(duration));
}
#else
inline void ExecTime(std::chrono::high_resolution_clock::time_point& t1,
    const libcomp::String& title = "Time")
{
    (void)t1;
    (void)title;
}
#endif

TEST(DiffieHellman, KeyExchange)
{
    std::chrono::high_resolution_clock::time_point t1;

    Log::GetSingletonPtr()->AddStandardOutputHook();

    DH *pClient = nullptr;
    DH *pServer = nullptr;

    // (server=>client) First packet.
    // Sends base, prime, and server public.
    String prime = "9C4169BBE8F535F7A7404D4EB3AE22CF63C0450FC2C7B2A5A03794D4"
        "CFA9F290FF5774267885E60B848280E3A07468366E62F040DAC3CB67E95E8F3DC4D"
        "97F94AD1D3D98F0B066F72B65CB391643A95BB96CF048ED5D60FB7AF7A969F38ABD"
        "2301F6A7EC4DB7DAFC2CFD1F417E0B634033FEE8B102D62A28EC03D95266E2B0B3";
    ASSERT_EQ(prime.Length(), DH_KEY_HEX_SIZE);

    t1 = std::chrono::high_resolution_clock::now();
    pServer = TcpServer::LoadDiffieHellman(prime);
    ExecTime(t1, "LoadDiffieHellman");
    ASSERT_NE(pServer, nullptr);

    t1 = std::chrono::high_resolution_clock::now();
    String serverPublic = TcpConnection::GenerateDiffieHellmanPublic(pServer);
    ExecTime(t1, "GenerateDiffieHellmanPublic");
    ASSERT_EQ(serverPublic.Length(), DH_KEY_HEX_SIZE);

    // (client=>server) Second packet.
    // Gets base, prime, and server public.
    // Sends client public.
    // Calculates client copy of shared data.
    pClient = TcpServer::LoadDiffieHellman(prime);
    ASSERT_NE(pClient, nullptr);

    String clientPublic = TcpConnection::GenerateDiffieHellmanPublic(pClient);
    ASSERT_EQ(clientPublic.Length(), DH_KEY_HEX_SIZE);

    t1 = std::chrono::high_resolution_clock::now();
    std::vector<char> clientData =
        TcpConnection::GenerateDiffieHellmanSharedData(pClient, serverPublic);
    ASSERT_EQ(clientData.size(), BF_NET_KEY_BYTE_SIZE);
    ExecTime(t1, "GenerateDiffieHellmanSharedData");

    // (server) Third packet.
    // Gets client public.
    // Calculates server copy of shared data.
    std::vector<char> serverData =
        TcpConnection::GenerateDiffieHellmanSharedData(pServer, clientPublic);
    ASSERT_EQ(serverData.size(), BF_NET_KEY_BYTE_SIZE);

    // Check they have the same data.
    ASSERT_EQ(memcmp(&serverData[0], &clientData[0], serverData.size()), 0);

    // Check the public keys do not match.
    ASSERT_NE(serverPublic, clientPublic);

    DH_free(pClient);
    DH_free(pServer);
}

int main(int argc, char *argv[])
{
    try
    {
        ::testing::InitGoogleTest(&argc, argv);

        return RUN_ALL_TESTS();
    }
    catch(...)
    {
        return EXIT_FAILURE;
    }
}
