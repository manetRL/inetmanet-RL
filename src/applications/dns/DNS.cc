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
#include <map>

#include "IPv4.h"
#include "DNS.h"
#include "DNSReply_m.h"
#include "IPSocket.h"
#include "IPv4ControlInfo.h"
#include "IPvXAddressResolver.h"
#include "TCP_YT_request_App.h"

using namespace std;

Define_Module(DNS);

void DNS::initialize(int stage)
{
    if (stage == 0)
    {
        IPSocket ipSocket(gate("ipOut"));
        ipSocket.registerProtocol(IP_PROT_DNS);
        WATCH_MAP(DNSTable);
        WATCH_MAP(resolved);
    }
    else if (stage == 3)
    {
        response_disabled = par("disable_response").boolValue();
        ttlDNS = par("cancelDNSEntry");

        DNSconfiguration = par("config_address");
        cXMLElementList interfaceElements = DNSconfiguration->getChildrenByTagName("DNS_address");

        for (int i = 0; i < (int)interfaceElements.size(); i++)
        {
            cXMLElement *interfaceElement = interfaceElements[i];

            string URL = (string )interfaceElement->getAttribute("URL");
            const char *addr = interfaceElement->getAttribute("address");
            IPvXAddress resolved_add = IPvXAddressResolver().resolve(addr);
            resolved[URL] = resolved_add;    //Dentro resolved ci sono le entry del server dns per permettergli di associare gli URL agli indirizzi IP. Appartiene al server DNS
        }
    }
}

void DNS::handleMessage(cMessage *msg)
{
    if (msg->getKind() == 100)
        startRequestDNS(msg);
    else if (dynamic_cast<DNSRequest *>(msg) != NULL)
    {
        if (response_disabled)
            delete(msg);
        else
            sendDNSReply(msg);
    }
    else if (dynamic_cast<DNSReply *>(msg) != NULL)
        processDNSReply(msg);
    else if (msg->isSelfMessage())
        deleteEntryDNS(msg);

}

void DNS::startRequestDNS(cMessage *msg)
{
    DNSRequest *dns = new DNSRequest("DNS_Request");
    dns->setUrl(msg->par("address"));

    IPvXAddress srcAddr = IPvXAddressResolver().resolve(msg->par("locAdd"));
    IPvXAddress destAddr = IPvXAddressResolver().resolve(par("DNS_Address"));

    IPv4ControlInfo *ctrl = new IPv4ControlInfo();
    ctrl->setSrcAddr(srcAddr.get4());
    ctrl->setDestAddr(destAddr.get4());
    ctrl->setProtocol(IP_PROT_DNS);
    dns->setControlInfo(ctrl);

    delete(msg);

    send(dns,"ipOut");

}

void DNS::sendDNSReply(cMessage *msg)
{
    DNSRequest *request = (DNSRequest *)msg;

    DNSReply *ReplyDNS = new DNSReply("DNSReply");
    ReplyDNS->setURL(request->getUrl());

    for (it = resolved.begin(); it != resolved.end(); ++it)
    {
        if (strcmp(request->getUrl(), it->first.c_str()) == 0)
        {
            ReplyDNS->setDest_adress(it->second);
            break;
        }
    }
    IPvXAddress src, dest;
    IPv4ControlInfo *ctrl = (IPv4ControlInfo *)request->getControlInfo();
    dest = ctrl->getSrcAddr();
    src = ctrl->getDestAddr();

    IPv4ControlInfo *ctrl2 = new IPv4ControlInfo();
    ctrl2->setSrcAddr(src.get4());
    ctrl2->setDestAddr(dest.get4());
    ctrl2->setProtocol(IP_PROT_DNS);
    ReplyDNS->setControlInfo(ctrl2);

    delete(request);

    send(ReplyDNS,"ipOut");

}

void DNS::processDNSReply(cMessage *msg)
{
    DNSReply *reply = (DNSReply *)msg;

    DNSTable[reply->getURL()] = reply->getDest_adress();
    cMessage *deleteDnsEntry = new cMessage("deleteDnsEntry");
    deleteDnsEntry->addPar("URL") = reply->getURL();
    simtime_t d = simTime() + (simtime_t) ttlDNS;
    scheduleAt(d, deleteDnsEntry);

    cMessage *return_control = new cMessage("DNSResponse");
    if (strcmp(reply->getURL(), "youtube.com") == 0)
    {
        return_control->setKind(50);
        return_control->addPar("resolvedAddress") = reply->getDest_adress().str().c_str();
    }
    else
    {
        return_control->setKind(0);
        return_control->addPar("resolvedAddress") = reply->getDest_adress().str().c_str();
    }

    cModule *tcpAppModule = getParentModule()->getSubmodule("tcpApp",0);
    TCP_YT_request_App *TCP_request_App = check_and_cast<TCP_YT_request_App *>(tcpAppModule);

    delete(reply);

    sendDirect(return_control,TCP_request_App,"fromDNS");
}

std::string DNS::findAddress(const char *url)
{
    std::string addr = "";
    for (it_table = DNSTable.begin(); it_table != DNSTable.end(); ++it_table)
    {
        if (strcmp(url, it_table->first.c_str()) == 0)
            addr = it_table->second.str();
    }
    return addr;
}

void DNS::deleteEntryDNS(cMessage *msg)
{
    const char *url = msg->par("URL");
    for (it_table = DNSTable.begin(); it_table != DNSTable.end(); ++it_table)
        {
            if (strcmp(url, it_table->first.c_str()) == 0)
            {
                DNSTable.erase(it_table);
                break;
            }
        }

    delete msg;
}
