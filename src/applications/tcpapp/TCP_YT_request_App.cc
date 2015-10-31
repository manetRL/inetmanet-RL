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

#include "TCP_YT_request_App.h"

#include "NodeOperations.h"
#include "ModuleAccess.h"
#include "GenericAppMsg_m.h"
#include "YTRequestMsg_m.h"
#include "DNSRequest_m.h"
#include "IPv4ControlInfo.h"
#include "FrontendServer.h"
#include "DNSReply_m.h"
#include "DNS.h"


#define MSGKIND_CONNECT  0
#define MSGKIND_SEND     1
#define MSGKIND_ABORT    2
#define MSGKIND_FRONTEND 50
#define MSGKIND_DNS      100

Define_Module(TCP_YT_request_App);

using namespace std;

TCP_YT_request_App::TCP_YT_request_App()
{
    timeoutMsg = NULL;
}

TCP_YT_request_App::~TCP_YT_request_App()
{
    cancelAndDelete(timeoutMsg);
}

void TCP_YT_request_App::initialize(int stage)
{
    TCPAppBase_forYT::initialize(stage);
    if (stage == 0)
    {
        numRequestsToSend = 0;
        earlySend = false;  // TBD make it parameter
        WATCH(numRequestsToSend);
        WATCH(earlySend);

        startTime = par("startTime");
        stopTime = par("stopTime");
        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            error("Invalid startTime/stopTime parameters");
    }
    else if (stage == 3)
    {
        timeoutMsg = new cMessage("timer");
        nodeStatus = dynamic_cast<NodeStatus *>(findContainingNode(this)->getSubmodule("status"));

        if (isNodeUp()) {
            timeoutMsg->setKind(MSGKIND_DNS);
            timeoutMsg->addPar("address") = "youtube.com";
            scheduleAt(startTime, timeoutMsg);
        }
    }
}

bool TCP_YT_request_App::isNodeUp()
{
    return !nodeStatus || nodeStatus->getState() == NodeStatus::UP;
}

bool TCP_YT_request_App::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent();
    if (dynamic_cast<NodeStartOperation *>(operation)) {
        if (stage == NodeStartOperation::STAGE_APPLICATION_LAYER) {
            simtime_t now = simTime();
            simtime_t start = std::max(startTime, now);
            if (timeoutMsg && ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)))
            {
                timeoutMsg->setKind(MSGKIND_CONNECT);
                scheduleAt(start, timeoutMsg);
            }
        }
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation)) {
        if (stage == NodeShutdownOperation::STAGE_APPLICATION_LAYER) {
            cancelEvent(timeoutMsg);
            if (socket.getState() == TCPSocket::CONNECTED || socket.getState() == TCPSocket::CONNECTING || socket.getState() == TCPSocket::PEER_CLOSED)
                close();
            // TODO: wait until socket is closed
        }
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation)) {
        if (stage == NodeCrashOperation::STAGE_CRASH)
            cancelEvent(timeoutMsg);
    }
    else throw cRuntimeError("Unsupported lifecycle operation '%s'", operation->getClassName());
    return true;
}

void TCP_YT_request_App::startDNS(cMessage *msg)
{
    cMessage *startDNS = new cMessage("startDNS");
    startDNS->setKind(MSGKIND_DNS);
    startDNS->addPar("locAdd") = par("localAddress").stringValue();
    startDNS->addPar("address") = msg->par("address");
    startDNS->addPar("tcpAppID") = msg->getArrivalModuleId();

    cModule *dnsModule = getParentModule()->getSubmodule("DNS");
    DNS *dns = check_and_cast<DNS *>(dnsModule);

    if (!msg->isSelfMessage())
        delete(msg);

    sendDirect(startDNS,dns,"fromApp");

}

void TCP_YT_request_App::requestPage(cMessage *msg)
{
    const char *destAddress = msg->par("resolvedAddress");

    cMessage *tofrontendApp = new cMessage("RequestPage");
    tofrontendApp->setKind(MSGKIND_FRONTEND);
    tofrontendApp->addPar("locAdd") = par("localAddress").stringValue();
    tofrontendApp->addPar("destinationAddress") = destAddress;
    tofrontendApp->addPar("tcpAppID") = msg->getArrivalModuleId();

    cPar param = this->par("videoServerAddress");                                               //
    if (!param.isExpression())                                                                  //
        tofrontendApp->addPar("videoServer") = par("videoServerAddress").stringValue();         // WORKAROUND per aggirare problema della lettura dell'indirizzo assegnato da scenarioManager
    else                                                                                        //
        tofrontendApp->addPar("videoServer") = par("videoServerAddress").str().c_str();         //

    cModule *frontendServerModule = getParentModule()->getSubmodule("FrontendApp");
    FrontendServer *frontendServer = check_and_cast<FrontendServer *>(frontendServerModule);

    if (!msg->isSelfMessage())
        delete(msg);

    sendDirect(tofrontendApp,frontendServer,"fromApp");

}

void TCP_YT_request_App::sendRequest()
{
     EV << "sending request, " << numRequestsToSend-1 << " more to go\n";

     long requestLength = par("requestLength");
     const char *itag = par("itag");
     itagType itag_num = convertStringToItag(itag);
     const char *btr = par("itag");
     videoBitrate bitrate = convertStringToBitrate(btr);
     int dur = par("dur");
     if (requestLength < 1)
         requestLength = 1;
     videoSize = (dur*bitrate*1024)/8;

     EV << "sending " << requestLength << " bytes " << endl;

     YTRequestMsg *msg = new YTRequestMsg("VideoRequest");
     msg->setByteLength(requestLength);
     msg->setItag(itag_num);
     msg->setDur(dur);

     sendPacket(msg);
}

void TCP_YT_request_App::handleTimer(cMessage *msg)
{
    switch (msg->getKind())
    {
        case MSGKIND_CONNECT:
        {
            EV << "starting session\n";
            const char *connectAddress = msg->par("resolvedAddress");
            connect(connectAddress); // active OPEN

            // significance of earlySend: if true, data will be sent already
            // in the ACK of SYN, otherwise only in a separate packet (but still
            // immediately)
            delete(msg);
            if (earlySend)
                sendRequest();
            break;
        }

        case MSGKIND_SEND:
           sendRequest();
           numRequestsToSend--;
           // no scheduleAt(): next request will be sent when reply to this one
           // arrives (see socketDataArrived())
           break;

        case MSGKIND_FRONTEND:
        {
            requestPage(msg);
            break;
        }

        default:
            throw cRuntimeError("Invalid timer msg: kind=%d", msg->getKind());
    }
}

void TCP_YT_request_App::socketEstablished(int connId, void *ptr)
{
    TCPAppBase_forYT::socketEstablished(connId, ptr);

    // determine number of requests in this session
    numRequestsToSend = (long) par("numRequestsPerSession");
    if (numRequestsToSend < 1)
        numRequestsToSend = 1;
    bytesRcvd_inSession = 0;
    bytesRcvd_now = 0;

    // perform first request if not already done (next one will be sent when reply arrives)
    if (!earlySend)
        sendRequest();

    numRequestsToSend--;
}

void TCP_YT_request_App::rescheduleOrDeleteTimer(simtime_t d, short int msgKind)
{
    cancelEvent(timeoutMsg);

    if (stopTime < SIMTIME_ZERO || d < stopTime)
    {
        timeoutMsg->setKind(msgKind);
        scheduleAt(d, timeoutMsg);
    }
    else
    {
        delete timeoutMsg;
        timeoutMsg = NULL;
    }
}

void TCP_YT_request_App::socketDataArrived(int connId, void *ptr, cPacket *msg, bool urgent)
{
    TCPAppBase_forYT::socketDataArrived(connId, ptr, msg, urgent);
    bytesRcvd_inSession = bytesRcvd_now%videoSize;//mod(VIDEOSIZE)

    if (numRequestsToSend > 0)
    {
        EV << "reply arrived\n";

        if (timeoutMsg)
        {
            simtime_t d = simTime() + (simtime_t) par("thinkTime");
            rescheduleOrDeleteTimer(d, MSGKIND_SEND);
        }
    }
    else if (socket.getState() != TCPSocket::LOCALLY_CLOSED && bytesRcvd_inSession == 0)
    {
        EV << "reply to last request arrived, closing session\n";
        close();
    }

//    if (socket.getState() != TCPSocket::LOCALLY_CLOSED && par("sendAbort"))
//    {
//        socket.abort();
//        rescheduleTimer();
//    }
}

void TCP_YT_request_App::socketClosed(int connId, void *ptr)
{
    TCPAppBase_forYT::socketClosed(connId, ptr);

    // start another session after a delay
    if (timeoutMsg)
    {
        simtime_t d = simTime() + (simtime_t) par("idleInterval");
        rescheduleOrDeleteTimer(d, MSGKIND_DNS);
    }
}

void TCP_YT_request_App::socketFailure(int connId, void *ptr, int code)
{
    TCPAppBase_forYT::socketFailure(connId, ptr, code);

    // reconnect after a delay
    if (timeoutMsg)
    {
        simtime_t d = simTime() + (simtime_t) par("reconnectInterval");
        rescheduleOrDeleteTimer(d, MSGKIND_CONNECT);
    }
}

void TCP_YT_request_App::rescheduleTimer()
{
    if (timeoutMsg)
        {
            simtime_t d = simTime() + (simtime_t) par("idleInterval");
            rescheduleOrDeleteTimer(d, MSGKIND_DNS);
        }
}

itagType TCP_YT_request_App::convertStringToItag(const char * itag)
{
    if (0 == strcmp(itag, "FLV_360p"))
        return FLV_360p;

    if (0 == strcmp(itag, "FLV_240p"))
            return FLV_240p;

    if (0 == strcmp(itag, "ThreeGP_144p"))
            return ThreeGP_144p;

    if (0 == strcmp(itag, "MP4_720p"))
            return MP4_720p;

    if (0 == strcmp(itag, "FLV_480p"))
            return FLV_480p;

    if (0 == strcmp(itag, "ThreeGP_240p"))
            return ThreeGP_240p;

    if (0 == strcmp(itag, "MP4_1080p"))
            return MP4_1080p;


    throw cRuntimeError("Invalid '%s' itag parameter at %s.", itag);
    return FLV_360p;
}

TCP_YT_request_App::videoBitrate TCP_YT_request_App::convertStringToBitrate(const char * btr)
{
    if (0 == strcmp(btr, "FLV_360p"))
        return FLV_360p_br;

    if (0 == strcmp(btr, "FLV_240p"))
            return FLV_240p_br;

    if (0 == strcmp(btr, "ThreeGP_144p"))
            return ThreeGP_144p_br;

    if (0 == strcmp(btr, "MP4_720p"))
            return MP4_720p_br;

    if (0 == strcmp(btr, "FLV_480p"))
            return FLV_480p_br;

    if (0 == strcmp(btr, "ThreeGP_240p"))
            return ThreeGP_240p_br;

    if (0 == strcmp(btr, "MP4_1080p"))
            return MP4_1080p_br;


    throw cRuntimeError("Invalid '%s' itag parameter at %s.", btr);
    return FLV_360p_br;
}

