/**
 * @file libcomp/src/TcpConnection.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Base TCP/IP connection class.
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

#include "TcpConnection.h"

#include "BaseConstants.h"
#include "BaseLog.h"
#include "Object.h"

#ifndef USE_MBED_TLS
#include "CryptSupport.h"
#endif

using namespace libcomp;

TcpConnection::TcpConnection(asio::io_service& io_service)
    : mSocket(io_service),
      mDiffieHellman(nullptr),
      mStatus(TcpConnection::STATUS_NOT_CONNECTED),
      mRole(TcpConnection::ROLE_CLIENT),
      mRemoteAddress("0.0.0.0"),
      mSendingPacket(false) {}

TcpConnection::TcpConnection(
    asio::ip::tcp::socket& socket,
    const std::shared_ptr<Crypto::DiffieHellman>& diffieHellman)
    : mSocket(std::move(socket)),
      mDiffieHellman(diffieHellman),
      mStatus(TcpConnection::STATUS_CONNECTED),
      mRole(TcpConnection::ROLE_SERVER),
      mRemoteAddress("0.0.0.0"),
      mSendingPacket(false) {
  // Cache the remote address.
  try {
    mRemoteAddress = mSocket.remote_endpoint().address().to_string();
  } catch (...) {
    // Just use the cache.
  }
}

TcpConnection::~TcpConnection() {
  LogConnectionDebug(
      [&]() { return String("Deleting connection '%1'\n").Arg(GetName()); });
}

bool TcpConnection::Connect(const String& host, uint16_t port, bool async) {
  bool result = false;

  // Modified from: http://stackoverflow.com/questions/5486113/
  asio::ip::tcp::resolver resolver(mSocket.get_executor());

  // Setup the query with the given port (if any).
  asio::ip::tcp::resolver::query query(
      host.ToUtf8(),
      0 < port ? String("%1").Arg(port).ToUtf8() : std::string());

  // Resolve the hostname.
  auto it = resolver.resolve(query);

  // If the hostname resolved, connect to it.
  if (asio::ip::tcp::resolver::iterator() != it) {
    Connect(*it, async);
    result = true;
  }

  return result;
}

bool TcpConnection::Close() {
  if (mStatus != STATUS_NOT_CONNECTED) {
    LogConnectionDebug(
        [&]() { return String("Closing connection '%1'\n").Arg(GetName()); });

    mStatus = STATUS_NOT_CONNECTED;
    mSocket.close();
    return true;
  } else {
    return false;
  }
}

void TcpConnection::QueuePacket(Packet& packet) {
  ReadOnlyPacket copy(std::move(packet));

  QueuePacket(copy);
}

void TcpConnection::QueuePacket(ReadOnlyPacket& packet) {
  std::lock_guard<std::mutex> guard(mOutgoingMutex);

  mOutgoingPackets.push_back(std::move(packet));
}

void TcpConnection::QueuePacketCopy(libcomp::Packet& packet) {
  libcomp::Packet pCopy(packet);
  QueuePacket(pCopy);
}

bool TcpConnection::QueueObject(const Object& obj) {
  Packet p;

  if (!obj.SavePacket(p)) {
    return false;
  }

  QueuePacket(p);

  return true;
}

bool TcpConnection::QueueObject(uint16_t packetCode, const Object& obj) {
  Packet p;
  p.WriteU16Little(packetCode);

  if (!obj.SavePacket(p)) {
    return false;
  }

  QueuePacket(p);

  return true;
}

void TcpConnection::SendPacket(Packet& packet, bool closeConnection) {
  ReadOnlyPacket copy(std::move(packet));

  SendPacket(copy, closeConnection);
}

void TcpConnection::SendPacket(ReadOnlyPacket& packet, bool closeConnection) {
  QueuePacket(packet);
  FlushOutgoing(closeConnection);
}

void TcpConnection::SendPacketCopy(libcomp::Packet& packet,
                                   bool closeConnection) {
  libcomp::Packet pCopy(packet);
  SendPacket(pCopy, closeConnection);
}

bool TcpConnection::SendObject(const Object& obj, bool closeConnection) {
  if (!QueueObject(obj)) {
    return false;
  }

  FlushOutgoing(closeConnection);

  return true;
}

bool TcpConnection::SendObject(uint16_t packetCode, const Object& obj,
                               bool closeConnection) {
  if (!QueueObject(packetCode, obj)) {
    return false;
  }

  FlushOutgoing(closeConnection);

  return true;
}

bool TcpConnection::RequestPacket(size_t size) {
  bool result = false;

  // Make sure the buffer is there.
  mReceivedPacket.Allocate();

  if (0 < mReceivedPacket.Size()) {
    LogConnectionDebug([&]() {
      return String(
                 "TcpConnection::RequestPacket() called when there is still %1 "
                 "bytes in the buffer.\n")
          .Arg(mReceivedPacket.Size());
    });
  }

  // Get direct access to the buffer.
  char* pDestination = mReceivedPacket.Data();

  if (0 != size && MAX_PACKET_SIZE >= (mReceivedPacket.Size() + size) &&
      nullptr != pDestination) {
    // Calculate where to write the data.
    pDestination += mReceivedPacket.Size();

    // Get a shared pointer to the connection so it outlives the callback.
    auto self = shared_from_this();

    // Request packet data from the socket.
    mSocket.async_receive(
        asio::buffer(pDestination, size), 0,
        [self](asio::error_code errorCode, std::size_t length) {
          if (errorCode) {
            LogConnectionDebug([&]() {
              return String("ASIO Error: %1\n").Arg(errorCode.message());
            });

            self->SocketError();
          } else {
            // Adjust the size of the packet.
            (void)self->mReceivedPacket.Direct(self->mReceivedPacket.Size() +
                                               static_cast<uint32_t>(length));
            self->mReceivedPacket.Rewind();

            // It's up to this callback to remove the data from the
            // packet either by calling std::move() or packet.Clear().
            self->PacketReceived(self->mReceivedPacket);

            if (0 < self->mReceivedPacket.Size()) {
              LogConnectionDebug([&]() {
                return String(
                           "TcpConnection::PacketReceived() was called and it "
                           "left %1 bytes in the buffer.\n")
                    .Arg(self->mReceivedPacket.Size());
              });
            }
          }
        });

    // Success.
    result = true;
  }

  return result;
}

TcpConnection::Role_t TcpConnection::GetRole() const { return mRole; }

TcpConnection::ConnectionStatus_t TcpConnection::GetStatus() const {
  return mStatus;
}

String TcpConnection::GetRemoteAddress() const { return mRemoteAddress; }

void TcpConnection::Connect(const asio::ip::tcp::endpoint& endpoint,
                            bool async) {
  mStatus = STATUS_CONNECTING;

  // Make sure we remove any remote address cache.
  mRemoteAddress = "0.0.0.0";

  if (async) {
    // Get a shared pointer to the connection so it outlives the callback.
    auto self = shared_from_this();

    mSocket.async_connect(endpoint, [self](const asio::error_code errorCode) {
      self->HandleConnection(errorCode);
    });
  } else {
    asio::error_code errorCode;
    HandleConnection(mSocket.connect(endpoint, errorCode));
  }
}

void TcpConnection::HandleConnection(asio::error_code errorCode) {
  if (errorCode) {
    mStatus = STATUS_NOT_CONNECTED;

    ConnectionFailed();
  } else {
    mStatus = STATUS_CONNECTED;

    // Cache the remote address.
    try {
      mRemoteAddress = mSocket.remote_endpoint().address().to_string();
    } catch (...) {
      // Just use the cache.
    }

    ConnectionSuccess();
  }
}

void TcpConnection::FlushOutgoing(bool closeConnection) {
  std::list<ReadOnlyPacket> packets = GetCombinedPackets();

  if (!packets.empty()) {
    PreparePackets(packets);

    mOutgoing.Rewind();

    FlushOutgoingInside(closeConnection);
  }
}

void TcpConnection::FlushOutgoingInside(bool closeConnection) {
  // Don't send anything if we are not connected.
  if (STATUS_NOT_CONNECTED == mStatus) {
    return;
  }

  // Get a shared pointer to the connection so it outlives the callback.
  auto self = shared_from_this();

  mSocket.async_send(
      asio::buffer(mOutgoing.ConstData() + mOutgoing.Tell(), mOutgoing.Left()),
      0,
      [closeConnection, self](asio::error_code errorCode, std::size_t length) {
        bool sendSame = false;
        bool sendAnother = false;
        bool packetOk = false;

        ReadOnlyPacket readOnlyPacket;

        // Ignore errors and everything else, just close the connection.
        if (closeConnection && self->mOutgoing.Left() == length) {
          LogConnectionDebugMsg("Closing connection after sending packet.\n");

          std::lock_guard<std::mutex> outgoingGuard(self->mOutgoingMutex);

          self->mSendingPacket = false;

          self->SocketError();
          return;
        }

        if (errorCode) {
          std::lock_guard<std::mutex> outgoingGuard(self->mOutgoingMutex);

          self->mSendingPacket = false;

          self->SocketError();
        } else {
          std::lock_guard<std::mutex> outgoingGuard(self->mOutgoingMutex);

          uint32_t outgoingSize = self->mOutgoing.Size();

          if (0 == outgoingSize || length > self->mOutgoing.Left()) {
            self->SocketError();
          } else {
            self->mOutgoing.Skip((uint32_t)length);

            if (0 != self->mOutgoing.Left()) {
              sendSame = true;
            } else {
              self->mOutgoing.Rewind();

              readOnlyPacket = self->mOutgoing;
              sendAnother = !self->mOutgoingPackets.empty();
              packetOk = true;
            }
          }

          self->mSendingPacket = sendSame;
        }

        if (sendSame) {
          self->FlushOutgoingInside(closeConnection);
        } else if (packetOk) {
          self->PacketSent(readOnlyPacket);

          if (sendAnother) {
            self->FlushOutgoing();
          }
        }
      });
}

void TcpConnection::SocketError(const String& errorMessage) {
  if (!errorMessage.IsEmpty()) {
    LogConnectionError([&]() {
      return String("Socket error for client '%1' from %2:  %3\n")
          .Arg(GetName())
          .Arg(GetRemoteAddress())
          .Arg(errorMessage);
    });
  }

  Close();
}

void TcpConnection::ConnectionFailed() {}

void TcpConnection::ConnectionSuccess() {
  LogConnectionDebug([&]() {
    return String(
        String("Connection '%1' is now connected to remote\n").Arg(GetName()));
  });
}

void TcpConnection::PacketSent(ReadOnlyPacket& packet) { (void)packet; }

void TcpConnection::PacketReceived(Packet& packet) { packet.Clear(); }

void TcpConnection::SetEncryptionKey(const std::vector<char>& data) {
  SetEncryptionKey(&data[0], data.size());
}

void TcpConnection::SetEncryptionKey(const void* pData, size_t dataSize) {
  if (nullptr != pData && BF_NET_KEY_BYTE_SIZE <= dataSize) {
    mEncryptionKey.SetKey(pData, BF_NET_KEY_BYTE_SIZE);
  }
}

String TcpConnection::GetDiffieHellmanPrime(
    const std::shared_ptr<Crypto::DiffieHellman>& diffieHellman) {
  return diffieHellman->GetPrime();
}

String TcpConnection::GenerateDiffieHellmanPublic(
    const std::shared_ptr<Crypto::DiffieHellman>& diffieHellman) {
  return diffieHellman->GeneratePublic();
}

std::vector<char> TcpConnection::GenerateDiffieHellmanSharedData(
    const std::shared_ptr<Crypto::DiffieHellman>& diffieHellman,
    const String& otherPublic) {
  return diffieHellman->GenerateSecret(otherPublic);
}

void TcpConnection::BroadcastPacket(
    const std::list<std::shared_ptr<TcpConnection>>& connections,
    Packet& packet) {
  ReadOnlyPacket copy(std::move(packet));

  BroadcastPacket(connections, copy);
}

void TcpConnection::BroadcastPacket(
    const std::list<std::shared_ptr<TcpConnection>>& connections,
    ReadOnlyPacket& packet) {
  for (auto connection : connections) {
    if (connection) {
      connection->SendPacket(packet);
    }
  }
}

void TcpConnection::PreparePackets(std::list<ReadOnlyPacket>& packets) {
  // There should only be one!
  if (packets.size() != 1) {
    LogConnectionCriticalMsg("Critical packet error.\n");
  }

  ReadOnlyPacket finalPacket(packets.front());

  mOutgoing = finalPacket;
}

std::list<ReadOnlyPacket> TcpConnection::GetCombinedPackets() {
  std::list<ReadOnlyPacket> packets;

  std::lock_guard<std::mutex> guard(mOutgoingMutex);

  if (!mSendingPacket && !mOutgoingPackets.empty()) {
    packets.push_back(mOutgoingPackets.front());
    mOutgoingPackets.pop_front();

    mSendingPacket = true;
  }

  return packets;
}

String TcpConnection::GetName() const { return mName; }

void TcpConnection::SetName(const String& name) { mName = name; }
