//
// Copyright (C) 2004 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_TCPMESSAGESENDQUEUEFORYT_H
#define __INET_TCPMESSAGESENDQUEUEFORYT_H

#include <list>
#include <map>
#include "TCPSendQueue.h"

using namespace std;


/**
 * Send queue that manages messages.
 *
 * @see TCPMsgBasedRcvQueue
 */
class INET_API TCPMsgBasedSendQueue_forYT : public TCPSendQueue
{
  protected:
    struct Payload
    {
        unsigned int endSequenceNo;
        cPacket *msg;
    };
    typedef std::list<Payload> PayloadQueue;
    PayloadQueue payloadQueue;

    uint32 begin;  // 1st sequence number stored
    uint32 end;    // last sequence number stored + 1
    long int SendBufferDimension;

  public:
    static std::map<int,bool> semaforo;

    /**
     * Ctor
     */
    TCPMsgBasedSendQueue_forYT();

    /**
     * Virtual dtor.
     */
    virtual ~TCPMsgBasedSendQueue_forYT();

    /**
     *
     */
    virtual void init(uint32 startSeq);

    /**
     * Returns a string with the region stored.
     */
    virtual std::string info() const;

    /**
     *
     */
    virtual void enqueueAppData(cPacket *msg);

    /**
     *
     */
    virtual uint32 getBufferStartSeq();

    /**
     *
     */
    virtual uint32 getBufferEndSeq();

    /**
     *
     */
    virtual TCPSegment *createSegmentWithBytes(uint32 fromSeq, ulong numBytes);

    /**
     *
     */
    virtual void discardUpTo(uint32 seqNum);
};

#endif
