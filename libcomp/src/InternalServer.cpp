/**
 * @file libcomp/src/InternalServer.cpp
 * @ingroup libcomp
 *
 * @author HACKfrost
 *
 * @brief Internal server class.
 *
 * This file is part of the COMP_hack Library (libcomp).
 *
 * Copyright (C) 2012-2016 COMP_hack Team <compomega@tutanota.com>
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

#include "InternalServer.h"

// libcomp Includes
#include "InternalConnection.h"
#include "LobbyConnection.h"
#include "Log.h"
#include "MessageWorldNotification.h"

using namespace libcomp;

InternalServer::InternalServer(const String& listenAddress, uint16_t port) :
    TcpServer(listenAddress, port)
{
    asio::io_service service;

    // Connect to the world server.
    std::shared_ptr<libcomp::LobbyConnection> lobbyConnection(
        new libcomp::LobbyConnection(service,
            libcomp::LobbyConnection::ConnectionMode_t::MODE_WORLD_UP));

    std::shared_ptr<libcomp::MessageQueue<libcomp::Message::Message*>>
        messageQueue(new libcomp::MessageQueue<libcomp::Message::Message*>());

    lobbyConnection->SetSelf(lobbyConnection);
    lobbyConnection->SetMessageQueue(messageQueue);

    /// @todo Load this from the configuration.
    lobbyConnection->Connect("127.0.0.1", 10666, false);

    std::thread serviceThread([&service]()
    {
        service.run();
    });

    bool connected = libcomp::TcpConnection::STATUS_CONNECTED ==
        lobbyConnection->GetStatus();

    if(!connected)
    {
        LOG_CRITICAL("Failed to connect to the lobby server!\n");
    }

    libcomp::Message::Message *pMessage = messageQueue->Dequeue();

    if(nullptr == dynamic_cast<libcomp::Message::WorldNotification*>(pMessage))
    {
        LOG_CRITICAL("Lobby server did not accept the world server "
            "notification.\n");
    }

    delete pMessage;

    lobbyConnection->Close();
    serviceThread.join();
    lobbyConnection.reset();
    messageQueue.reset();
}

InternalServer::~InternalServer()
{
    /// @todo stop workers
}

std::shared_ptr<libcomp::TcpConnection> InternalServer::CreateConnection(
    asio::ip::tcp::socket& socket)
{
    auto connection = std::shared_ptr<libcomp::TcpConnection>(
        new InternalConnection(socket, CopyDiffieHellman(
            GetDiffieHellman())
        )
    );

    // Assign this to the only worker available.
    std::dynamic_pointer_cast<libcomp::InternalConnection>(
        connection)->SetMessageQueue(mWorker.GetMessageQueue());

    // Make sure this is called after connecting.
    connection->SetSelf(connection);
    connection->ConnectionSuccess();

    return connection;
}
