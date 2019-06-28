/**
 * @file libcomp/src/Worker.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Base worker class to process messages for a thread.
 *
 * This file is part of the COMP_hack Library (libcomp).
 *
 * Copyright (C) 2012-2018 COMP_hack Team <compomega@tutanota.com>
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

#include "Worker.h"

// libcomp Includes
#include "Exception.h"
#include "Log.h"
#include "MessageShutdown.h"

// Standard C++11 Includes
#include <thread>

using namespace libcomp;

Worker::Worker() : mRunning(false), mMessageQueue(new MessageQueue<
    Message::Message*>()), mThread(nullptr)
{
}

Worker::~Worker()
{
    Cleanup();
}

void Worker::AddManager(const std::shared_ptr<Manager>& manager)
{
    for(auto messageType : manager->GetSupportedTypes())
    {
        mManagers.insert(std::make_pair(messageType, manager));
    }
}

void Worker::Start(const libcomp::String& name, bool blocking)
{
    mWorkerName = name;

    if(blocking)
    {
        mRunning = true;
        Run(mMessageQueue.get());
        mRunning = false;
    }
    else
    {
        mThread = new std::thread([this](std::shared_ptr<MessageQueue<
            Message::Message*>> messageQueue, const libcomp::String& _name)
        {
            (void)_name;

#if !defined(_WIN32)
            pthread_setname_np(pthread_self(), _name.C());
#endif // !defined(_WIN32)

            libcomp::Exception::RegisterSignalHandler();

            mRunning = true;
            Run(messageQueue.get());
            mRunning = false;
        }, mMessageQueue, name);
    }
}

void Worker::Run(MessageQueue<Message::Message*> *pMessageQueue)
{
    while(mRunning)
    {
        std::list<libcomp::Message::Message*> msgs;
        pMessageQueue->DequeueAll(msgs);

        for(auto pMessage : msgs)
        {
            HandleMessage(pMessage);
        }
    }
}

void Worker::HandleMessage(libcomp::Message::Message *pMessage)
{
    // Check for a shutdown message.
    libcomp::Message::Shutdown *pShutdown = dynamic_cast<
        libcomp::Message::Shutdown*>(pMessage);

    // Check for an execute message.
    libcomp::Message::Execute *pExecute = dynamic_cast<
        libcomp::Message::Execute*>(pMessage);

    // Do not handle any more messages if a shutdown was sent.
    if(nullptr != pShutdown || !mRunning)
    {
        mRunning = false;
    }
    else if(nullptr != pExecute)
    {
        // Run the code now.
        pExecute->Run();
    }
    else
    {
        bool didProcess = false;

        // Attempt to find a manager to process this message.
        auto range = mManagers.equal_range(pMessage->GetType());

        // Process the message with the list of managers.
        for(auto it = range.first; it != range.second; ++it)
        {
            auto manager = it->second;

            if(!manager)
            {
                LOG_ERROR("Manager is null!\n");
            }
            else if(manager->ProcessMessage(pMessage))
            {
                didProcess = true;
            }
        }

        if(!didProcess)
        {
            LOG_ERROR(libcomp::String("Failed to process message in worker "
                "'%1':\n%2\n").Arg(mWorkerName).Arg(pMessage->Dump()));
        }
    }

    // Grab the next worker.
    auto nextWorker = mNextWorker.lock();

    // Either forward the message to the next worker or free it.
    if(nextWorker)
    {
        nextWorker->GetMessageQueue()->Enqueue(pMessage);
    }
    else
    {
        delete pMessage;
    }
}

void Worker::Shutdown()
{
    mMessageQueue->Enqueue(new libcomp::Message::Shutdown());
}

void Worker::Join()
{
    if(nullptr != mThread)
    {
        mThread->join();
    }
}

void Worker::Cleanup()
{
    // Delete the main thread (if it exists).
    if(nullptr != mThread)
    {
        delete mThread;
        mThread = nullptr;
    }

    if(nullptr != mMessageQueue)
    {
        // Empty the message queue.
        std::list<libcomp::Message::Message*> msgs;
        mMessageQueue->DequeueAny(msgs);

        for(auto pMessage : msgs)
        {
            delete pMessage;
        }

        mMessageQueue.reset();
    }
}

bool Worker::IsRunning() const
{
    return mRunning;
}

String Worker::GetWorkerName() const
{
    return mWorkerName;
}

void Worker::SetNetWorker(const std::weak_ptr<Worker>& nextWorker)
{
    mNextWorker = nextWorker;
}

std::shared_ptr<MessageQueue<Message::Message*>> Worker::GetMessageQueue() const
{
    return mMessageQueue;
}

long Worker::AssignmentCount() const
{
    return mMessageQueue.use_count();
}
