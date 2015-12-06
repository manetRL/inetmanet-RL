//
// Copyright 2004 Andras Varga
//
// This library is free software, you can redistribute it and/or modify
// it under  the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation;
// either version 2 of the License, or any later version.
// The library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
//


#include "TCP_YT_traffic_gen.h"

#include "ByteArrayMessage.h"
#include "TCPCommand_m.h"
#include "ModuleAccess.h"
#include "NodeOperations.h"
#include "YTRequestMsg_m.h"
#include "YTVideoPacketMsg_m.h"
#include "Control_block_forYT_m.h"



Define_Module(TCP_YT_traffic_gen);

simsignal_t TCP_YT_traffic_gen::rcvdPkSignal = registerSignal("rcvdPk");
simsignal_t TCP_YT_traffic_gen::sentPkSignal = registerSignal("sentPk");
simsignal_t TCP_YT_traffic_gen::reqStreamBytesSignal = registerSignal("reqStreamBytes");

inline std::ostream& operator<<(std::ostream& out, const TCP_YT_traffic_gen::VideoStreamData& d)
{
    out << "client="
        << "  size=" << d.videoSize << "  pksent=" << d.numPkSent << "  bytesleft=" << d.bytesLeft;
    return out;
}

TCP_YT_traffic_gen::~TCP_YT_traffic_gen()
{
    for(VideoStreamMap::iterator it = streams.begin(); it  != streams.end(); ++it)
        cancelAndDelete(it->second.timer);
}

void TCP_YT_traffic_gen::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == 0)
    {
        delay = par("echoDelay");
//        echoFactor = par("echoFactor");
//        videoBitrate = par("videoBitrate");
//        videoSize = par("videoSize");

        bytesRcvd = bytesSent = 0;
        numStreams = 0;

        WATCH(bytesRcvd);
        WATCH(bytesSent);

        socket.setOutputGate(gate("tcpOut"));
        socket.readDataTransferModePar(*this);

        nodeStatus = dynamic_cast<NodeStatus *>(findContainingNode(this)->getSubmodule("status"));

        WATCH_MAP(streams);
        chunk = par("throttling_chunk");
        multiplier = par("throttling_multiplier");

    }
    else if (stage == 3)
    {
        if (isNodeUp())
            startListening();
    }
}

bool TCP_YT_traffic_gen::isNodeUp()
{
    return !nodeStatus || nodeStatus->getState() == NodeStatus::UP;
}

void TCP_YT_traffic_gen::startListening()
{
    const char *localAddress = par("localAddress");
    int localPort = par("localPort");
    socket.renewSocket();
    socket.bind(localAddress[0] ? IPvXAddress(localAddress) : IPvXAddress(), localPort);
    socket.listen();
}

void TCP_YT_traffic_gen::stopListening()
{
    socket.close();
}

void TCP_YT_traffic_gen::sendDown(cMessage *msg)
{
    if (msg->isPacket())
    {
        bytesSent += ((cPacket *)msg)->getByteLength();
        emit(sentPkSignal, (cPacket *)msg);
    }

    send(msg, "tcpOut");
}

void TCP_YT_traffic_gen::handleMessage(cMessage *msg)
{
    if (!isNodeUp())
        throw cRuntimeError("Application is not running");
    if (msg->isSelfMessage())
    {
        firstPacket = 0;
        sendStreamData(msg);
    }
    else if(dynamic_cast<Control_block_forYT *>(msg) != NULL)
    {
        Control_block_forYT *control = (Control_block_forYT *)msg;
        int IDconnection = control->getConnID();
        VideoStreamMap::iterator it;
        for (it = streams.begin(); it != streams.end(); ++it)
        {
            VideoStreamData *d = &(it->second);
            if (d->cmd->getConnId() == IDconnection)
            {
                d->blocked = control->getState();
                break;
            }
        }
//        if (it == streams.end())
//            throw cRuntimeError("Model error: Stream not found for timer");

        delete msg;

    }
    else if (msg->getKind() == TCP_I_PEER_CLOSED)
    {
        // we'll close too
        msg->setName("close");
        msg->setKind(TCP_C_CLOSE);

        if (delay == 0)
            sendDown(msg);
        else
            scheduleAt(simTime() + delay, msg); // send after a delay
    }
    else if (msg->getKind() == TCP_I_DATA || msg->getKind() == TCP_I_URGENT_DATA)
    {
        YTRequestMsg *pkt = check_and_cast<YTRequestMsg *>(msg);
        emit(rcvdPkSignal, pkt);

        int dur = pkt->getDur();
        int itag = pkt->getItag();

        switch (itag)
        {
        case (5):
                videoBitrate = 400;
        break;
        case (17):
                videoBitrate = 200;
        break;
        case (18):
                videoBitrate = 750;
        break;
        case (22):
                videoBitrate = 2500;
        break;
        case (34):
                videoBitrate = 750;
        break;
        case (35):
                videoBitrate = 1000;
        break;
        case (36):
                videoBitrate = 400;
        break;
        case (37):
                videoBitrate = 4500;
        break;
        }

        videoSize = (dur*videoBitrate*1024)/8;

        cMessage *timer = new cMessage("VideoStreamTmr");
        VideoStreamData *d = &streams[timer->getId()];
        d->timer = timer;
        d->videoSize = videoSize;
        d->bytesLeft = d->videoSize;
        d->numPkSent = 0;
        ASSERT(d->videoSize > 0);
        d->vidBitrt = videoBitrate;
        d->durata = dur;

        TCPCommand *ind = check_and_cast<TCPCommand *>(pkt->removeControlInfo());
        d->cmd = new TCPSendCommand();
        d->cmd->setConnId(ind->getConnId());

        delete ind;
        delete msg;

        numStreams++;
        emit(reqStreamBytesSignal, d->videoSize);

        firstPacket = 1;
        // ... then transmit first packet right away
        sendStreamData(timer);
    }

    else if (msg->getKind() == TCP_I_CONNECTION_RESET)
    {
        TCPCommand *aaa = (TCPCommand *)msg->getControlInfo();
        int connectID = aaa->getConnId();
        VideoStreamMap::iterator it;
        for (it = streams.begin(); it != streams.end(); ++it)
        {
            if (it->second.cmd->getConnId() == connectID)
            {
                delete cancelEvent(it->second.timer);
                streams.erase(it);
                delete msg;
                break;
            }
        }
//        msg->setName("close");
//        msg->setKind(TCP_C_CLOSE);
//        sendDown(msg);
    }
    else
    {
        // some indication -- ignore
        delete msg;
    }

    if (ev.isGUI())
    {
        char buf[80];
        sprintf(buf, "rcvd: %ld bytes\nsent: %ld bytes", bytesRcvd, bytesSent);
        getDisplayString().setTagArg("t", 0, buf);
    }
}

void TCP_YT_traffic_gen::sendStreamData(cMessage *timer)
{
    VideoStreamMap::iterator it = streams.find(timer->getId());
    if (it == streams.end())
        throw cRuntimeError("Model error: Stream not found for timer");

    VideoStreamData *d = &(it->second);

    if (firstPacket == 1)                        //Invia il primo pacchetto con i metatag e successivamente il burst iniziale.
    {
        // generate and send a packet
        YTVideoPacketMsg *pkt = new YTVideoPacketMsg("VideoStrmPk");
        pkt->setKind(TCP_C_SEND);
        TCPSendCommand *attach = new TCPSendCommand();
        *attach = *d->cmd;
        pkt->setControlInfo(attach);
        long byteLen = 500;                         //Grandezza del pacchetto con i metatag
        pkt->setByteLength(byteLen);
        pkt->setMetaTag_bitrate(d->vidBitrt);
        pkt->setMetaTag_durata(d->durata);
        pkt->setMetaTag_videoSize(d->videoSize);

        emit(sentPkSignal, pkt);
        d->bytesLeft -= byteLen;
        d->numPkSent++;
        numPkSent++;

        sendDown(pkt);

        //Qui invia il burst iniziale

        cPacket *pkt2 = new cPacket("VideoStrmPk");
        pkt2->setKind(TCP_C_SEND);
        TCPSendCommand *attach2 = new TCPSendCommand();
        *attach2 = *d->cmd;
        pkt2->setControlInfo(attach2);
        byteLen = (d->vidBitrt*40*1000)/8;
        if (byteLen > d->videoSize)
            byteLen=d->videoSize;
        pkt2->setByteLength(byteLen);
        emit(sentPkSignal, pkt2);
        d->bytesLeft -= byteLen;
        d->numPkSent++;
        numPkSent++;

        sendDown(pkt2);

    }
    else
    {
        if (!d->blocked)
        {
            // generate and send a packet
            cPacket *pkt = new cPacket("VideoStrmPk");
            pkt->setKind(TCP_C_SEND);
            TCPSendCommand *attach = new TCPSendCommand();
            *attach = *d->cmd;
            pkt->setControlInfo(attach);
            long byteLen = chunk;
            if (byteLen > d->bytesLeft)
                byteLen = d->bytesLeft;

            pkt->setByteLength(byteLen);

            emit(sentPkSignal, pkt);
            d->bytesLeft -= byteLen;
            d->numPkSent++;
            numPkSent++;

            sendDown(pkt);
        }

    }

    // reschedule timer if there's bytes left to send
    if (d->bytesLeft > 0)
    {
        simtime_t interval = ((chunk/1024)*8)/(multiplier*d->vidBitrt);
        scheduleAt(simTime()+interval, timer);
    }
    else
    {
        streams.erase(it);
        delete timer;
    }
}

bool TCP_YT_traffic_gen::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent();
    if (dynamic_cast<NodeStartOperation *>(operation)) {
        if (stage == NodeStartOperation::STAGE_APPLICATION_LAYER)
            startListening();
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation)) {
        if (stage == NodeShutdownOperation::STAGE_APPLICATION_LAYER)
            // TODO: wait until socket is closed
            stopListening();
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation)) ;
    else throw cRuntimeError("Unsupported lifecycle operation '%s'", operation->getClassName());
    return true;
}

void TCP_YT_traffic_gen::finish()
{
    recordScalar("bytesRcvd", bytesRcvd);
    recordScalar("bytesSent", bytesSent);
}

void TCP_YT_traffic_gen::clearStreams()
{
    for(VideoStreamMap::iterator it = streams.begin(); it  != streams.end(); ++it)
        cancelAndDelete(it->second.timer);
    streams.clear();
}
