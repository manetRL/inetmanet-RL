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



#include <stdlib.h>
#include <string.h>

#include "FrontendServer.h"
#include "IPv4.h"
#include "IPSocket.h"
#include "IPv4ControlInfo.h"
#include "IPvXAddressResolver.h"
#include "FrontEndMessages_m.h"
#include "TCP_YT_request_App.h"

Define_Module(FrontendServer);

void FrontendServer::initialize(int stage)
{
    if (stage == 0)
    {
        IPSocket ipSocket(gate("ipOut"));
        ipSocket.registerProtocol(IP_PROT_FRONTEND);
    }
}

void FrontendServer::handleMessage(cMessage *msg)
{
    if (msg->arrivedOn("fromApp"))
        sendRequestPage(msg);
    else if (dynamic_cast<RequestPage *>(msg) != NULL)
        sendReplyPage(msg);
    else if (dynamic_cast<ReplyPage *>(msg) != NULL)
        processReplyPage(msg);

}

void FrontendServer::sendRequestPage(cMessage *msg)
{
    RequestPage *requestPage = new RequestPage("HTTP Get");
    requestPage->setByteLength(200);
    requestPage->setVideoServerToReply(msg->par("videoServer").stringValue());

    IPvXAddress srcAddr = IPvXAddressResolver().resolve(msg->par("locAdd"));
    IPvXAddress destAddr = IPvXAddressResolver().resolve(msg->par("destinationAddress"));
    IPv4ControlInfo *ctrl = new IPv4ControlInfo();
    ctrl->setSrcAddr(srcAddr.get4());
    ctrl->setDestAddr(destAddr.get4());
    ctrl->setProtocol(IP_PROT_FRONTEND);

    requestPage->setControlInfo(ctrl);

    delete(msg);

    send(requestPage,"ipOut");

}

void FrontendServer::sendReplyPage(cMessage *msg)
{
    RequestPage *request = (RequestPage *)msg;
    long requestLength = par("replyLength");
    ReplyPage *reply = new ReplyPage("HTTP 200 OK");
    reply->setByteLength(requestLength);
    reply->setVideoServerURL(request->getVideoServerToReply());

    IPvXAddress src, dest;
    IPv4ControlInfo *ctrl = (IPv4ControlInfo *)request->getControlInfo();
    dest = ctrl->getSrcAddr();
    src = ctrl->getDestAddr();

    IPv4ControlInfo *ctrl2 = new IPv4ControlInfo();
    ctrl2->setSrcAddr(src.get4());
    ctrl2->setDestAddr(dest.get4());
    ctrl2->setProtocol(IP_PROT_FRONTEND);
    reply->setControlInfo(ctrl2);

    delete(request);

    send(reply,"ipOut");

}

void FrontendServer::processReplyPage(cMessage *msg)
{
    ReplyPage *reply =(ReplyPage *)msg;
    cMessage *return_control = new cMessage("FrontEndResponse");
    return_control->setKind(100);
    return_control->addPar("address") = reply->getVideoServerURL();

    cModule *tcpAppModule = getParentModule()->getSubmodule("tcpApp",0);
    TCP_YT_request_App *TCP_request_App = check_and_cast<TCP_YT_request_App *>(tcpAppModule);

    delete(msg);

    sendDirect(return_control,TCP_request_App,"fromDNS");
}



