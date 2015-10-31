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


#include "TCPMsgBasedSendQueue_forYT.h"

#include "TCPSegment.h"
#include "TCP_YT_request_App.h"
#include "Control_block_forYT_m.h"
#include <csimplemodule.h>


Register_Class(TCPMsgBasedSendQueue_forYT);

using namespace std;
map<int,bool> TCPMsgBasedSendQueue_forYT::semaforo;

TCPMsgBasedSendQueue_forYT::TCPMsgBasedSendQueue_forYT() : TCPSendQueue()
{
    begin = end = 0;
}

TCPMsgBasedSendQueue_forYT::~TCPMsgBasedSendQueue_forYT()
{
    for (PayloadQueue::iterator it = payloadQueue.begin(); it != payloadQueue.end(); ++it)
        delete it->msg;
}

void TCPMsgBasedSendQueue_forYT::init(uint32 startSeq)
{
    begin = startSeq;
    end = startSeq;
    bool found = false;
    int l = 0;
    cModule *mod = this->conn->getTcpMain();
    cModule *dest;
    while(!found)
    {
        dest = mod->gate("appOut", l)->getNextGate()->getOwnerModule();
        if (dest->par("localPort").operator unsigned int() == this->conn->localPort)
            found = true;
        l++;
    }
    SendBufferDimension = dest->par("BufferDimension_forTCP");
}

std::string TCPMsgBasedSendQueue_forYT::info() const
{
    std::stringstream out;
    out << "[" << begin << ".." << end << "), " << payloadQueue.size() << " packets";
    return out.str();
}

void TCPMsgBasedSendQueue_forYT::enqueueAppData(cPacket *msg)
{
    //tcpEV << "sendQ: " << info() << " enqueueAppData(bytes=" << msg->getByteLength() << ")\n";
    end += msg->getByteLength();
    if (seqLess(end, begin))
        throw cRuntimeError("Send queue is full");

    Payload payload;
    payload.endSequenceNo = end;
    payload.msg = msg;
    payloadQueue.push_back(payload);

    ulong dim = getBytesAvailable(conn->getState()->snd_nxt);
    if (dim > SendBufferDimension)
    {
        int IDconn = conn->connId;
        semaforo[IDconn]=true;
        Control_block_forYT *action = new Control_block_forYT("BlockApp");
        action->setConnID(IDconn);
        action->setState(true);
        cModule *mod = msg->getArrivalModule();
        bool found = false;
        int l = 0;
        cModule *dest;
        while(!found)
        {
            dest = mod->gate("appOut", l)->getNextGate()->getOwnerModule();
            if (dest->par("localPort").operator unsigned int() == this->conn->localPort)
                found = true;
            l++;
        }
        TCP *tcp = check_and_cast<TCP *>(mod);
        tcp->sendDirect(action, dest, "blockManager");
    }
}

uint32 TCPMsgBasedSendQueue_forYT::getBufferStartSeq()
{
    return begin;
}

uint32 TCPMsgBasedSendQueue_forYT::getBufferEndSeq()
{
    return end;
}

TCPSegment *TCPMsgBasedSendQueue_forYT::createSegmentWithBytes(uint32 fromSeq, ulong numBytes)
{
    //tcpEV << "sendQ: " << info() << " createSeg(seq=" << fromSeq << " len=" << numBytes << ")\n";
    ASSERT(seqLE(begin, fromSeq) && seqLE(fromSeq + numBytes, end));

    TCPSegment *tcpseg = new TCPSegment(NULL);

    tcpseg->setSequenceNo(fromSeq);
    tcpseg->setPayloadLength(numBytes);

    // add payload messages whose endSequenceNo is between fromSeq and fromSeq + numBytes
    PayloadQueue::iterator i = payloadQueue.begin();

    while (i != payloadQueue.end() && seqLE(i->endSequenceNo, fromSeq))
        ++i;

    uint32 toSeq = fromSeq + numBytes;
    const char *payloadName = NULL;

    while (i != payloadQueue.end() && seqLE(i->endSequenceNo, toSeq))
    {
        if (!payloadName)
            payloadName = i->msg->getName();

        tcpseg->addPayloadMessage(i->msg->dup(), i->endSequenceNo);
        ++i;
    }

    // give segment a name
    char msgname[80];
    if (!payloadName)
        sprintf(msgname, "tcpseg(l=%lu,%dmsg)", numBytes, tcpseg->getPayloadArraySize());
    else
        sprintf(msgname, "%.10s(l=%lu,%dmsg)", payloadName, numBytes, tcpseg->getPayloadArraySize());
    tcpseg->setName(msgname);

    return tcpseg;
}

void TCPMsgBasedSendQueue_forYT::discardUpTo(uint32 seqNum)
{
    //tcpEV << "sendQ: " << info() << " discardUpTo(seq=" << seqNum << ")\n";
    ASSERT(seqLE(begin, seqNum) && seqLE(seqNum, end));

    begin = seqNum;
    int IDconn = conn->connId;

    // remove payload messages whose endSequenceNo is below seqNum
    while (!payloadQueue.empty() && seqLE(payloadQueue.front().endSequenceNo, seqNum))
    {
        delete payloadQueue.front().msg;
        payloadQueue.pop_front();
    }

    ulong dim = getBytesAvailable(conn->getState()->snd_nxt);
    if ( (dim < (SendBufferDimension - 204800)) && (semaforo[IDconn]) )
    {
        semaforo[IDconn]=false;
        Control_block_forYT *action = new Control_block_forYT("ResumeApp");
        action->setConnID(IDconn);
        action->setState(false);
        bool found = false;
        int l = 0;
        cModule *mod = this->conn->getTcpMain();
        cModule *dest;
        while(!found)
        {
            dest = mod->gate("appOut", l)->getNextGate()->getOwnerModule();
            if (dest->par("localPort").operator unsigned int() == this->conn->localPort)
                found = true;
            l++;
        }
        TCP *tcp = check_and_cast<TCP *>(mod);
        tcp->sendDirect(action, dest, "blockManager");
    }
}
