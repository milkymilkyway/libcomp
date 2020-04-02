/**
 * @file libcomp/src/TcpServer.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Base TCP/IP server class.
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

#include "TcpServer.h"

#include "Constants.h"
#include "Log.h"
#include "TcpConnection.h"
#include "WindowsService.h"

#ifndef USE_MBED_TLS
#include "CryptSupport.h"
#endif

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif // HAVE_SYSTEMD

using namespace libcomp;

TcpServer::TcpServer(const String& listenAddress, uint16_t port) :
    mAcceptor(mService), mDiffieHellman(nullptr),
    mListenAddress(listenAddress), mPort(port)
{
#if !defined(_WIN32)
    // Do not set this as it will cause the process name to change.
    // pthread_setname_np(pthread_self(), "server");
#endif // !defined(_WIN32)
}

TcpServer::~TcpServer()
{
}

int TcpServer::Start(bool delayReady)
{
    // Check for a DH key pair.
    if(nullptr == mDiffieHellman)
    {
        LogCryptoWarningMsg("Generating a DH key pair. "
            "This could take several minutes.\n");

        // Generate it since we don't have one yet.
        mDiffieHellman = GenerateDiffieHellman();

        // Check if the key was made.
        if(nullptr == mDiffieHellman)
        {
            LogCryptoCriticalMsg("Failed to generate Diffie-Hellman prime!\n");
        }
        else
        {
            LogCryptoWarning([&]()
            {
                return String("Please add the following to your "
                    "configuration XML: <prime>%1</prime>\n")
                    .Arg(TcpConnection::GetDiffieHellmanPrime(mDiffieHellman));
            });
        }
    }

    asio::ip::tcp::endpoint endpoint;

    if(mListenAddress.IsEmpty() || "any" == mListenAddress.ToLower())
    {
        endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v4(), mPort);
    }
    else
    {
        endpoint = asio::ip::tcp::endpoint(asio::ip::address::from_string(
            mListenAddress.ToUtf8()), mPort);
    }

    mAcceptor.open(endpoint.protocol());
    mAcceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    mAcceptor.bind(endpoint);
    mAcceptor.listen();

    asio::ip::tcp::socket socket(mService);

    mAcceptor.async_accept(socket,
        [this, &socket](asio::error_code errorCode)
        {
            AcceptHandler(errorCode, socket);
        });

    mServiceThread = std::thread([this]()
    {
#if !defined(_WIN32) && !defined(__APPLE__)
        pthread_setname_np(pthread_self(), "asio");
#endif // !defined(_WIN32) && !defined(__APPLE__)

        mService.run();
    });

    if(!delayReady)
    {
        ServerReady();
    }

    int returnCode = Run();

    mServiceThread.join();

    return returnCode;
}

void TcpServer::RemoveConnection(std::shared_ptr<TcpConnection>& connection)
{
    // Lock the mutex.
    std::lock_guard<std::mutex> lock(mConnectionsLock);

    auto iter = std::find(mConnections.begin(), mConnections.end(), connection);
    if(iter != mConnections.end())
    {
        mConnections.remove(connection);
    }
}

int TcpServer::Run()
{
    return 0;
}

void TcpServer::ServerReady()
{
    LogGeneralInfoMsg("Server ready!\n");

#ifdef HAVE_SYSTEMD
    sd_notify(0, "READY=1");
#endif // HAVE_SYSTEMD

#if defined(_WIN32) && defined(WIN32_SERV)
    if(gService)
    {
        gService->Started();
    }
#endif // defined(_WIN32) && defined(WIN32_SERV)
}

std::shared_ptr<TcpConnection> TcpServer::CreateConnection(
    asio::ip::tcp::socket& socket)
{
    return std::make_shared<TcpConnection>(socket,
        LoadDiffieHellman(mDiffieHellman->GetPrime()));
}

void TcpServer::AcceptHandler(asio::error_code errorCode,
    asio::ip::tcp::socket& socket)
{
    if(errorCode)
    {
        LogConnectionError([&]()
        {
            return String("async_accept error: %1\n").Arg(errorCode.message());
        });
    }
    else
    {
        // Make sure the DH key pair is valid.
        if(nullptr != mDiffieHellman)
        {
            LogConnectionDebug([&]()
            {
                return String("New connection from %1\n")
                    .Arg(socket.remote_endpoint().address().to_string());
            });

            auto connection = CreateConnection(socket);
            if(nullptr == connection)
            {
                LogConnectionCriticalMsg(
                    "The connection could not be created\n");

                return;
            }

            {
                // Lock the muxtex.
                std::lock_guard<std::mutex> lock(mConnectionsLock);

                mConnections.push_back(connection);
            }

            // This is actually using a different socket because the
            // CreateConnection() call will use std::move on the socket which
            // will reset this socket (which is a reference to the local
            // variable in the Start() function).
            mAcceptor.async_accept(socket,
                [this, &socket](asio::error_code acceptErrorCode)
                {
                    AcceptHandler(acceptErrorCode, socket);
                });
        }
        else
        {
            LogCryptoCriticalMsg(
                "Somehow you got this far without a DH key pair!\n");
        }
    }
}

std::shared_ptr<Crypto::DiffieHellman> TcpServer::GetDiffieHellman() const
{
    return mDiffieHellman;
}

void TcpServer::SetDiffieHellman(const std::shared_ptr<
    Crypto::DiffieHellman>& diffieHellman)
{
    mDiffieHellman = diffieHellman;
}

std::shared_ptr<Crypto::DiffieHellman> TcpServer::GenerateDiffieHellman()
{
    return Crypto::DiffieHellman::Generate();
}

std::shared_ptr<Crypto::DiffieHellman> TcpServer::LoadDiffieHellman(
    const String& prime)
{
    return std::make_shared<Crypto::DiffieHellman>(prime);
}
