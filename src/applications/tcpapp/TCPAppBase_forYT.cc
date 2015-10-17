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


#include "TCPAppBase_forYT.h"
#include "DNS.h"

#include "IPvXAddressResolver.h"

using namespace std;

simsignal_t TCPAppBase_forYT::connectSignal = registerSignal("connect");
simsignal_t TCPAppBase_forYT::rcvdPkSignal = registerSignal("rcvdPk");
simsignal_t TCPAppBase_forYT::sentPkSignal = registerSignal("sentPk");


void TCPAppBase_forYT::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == 0)
    {
        numSessions = numBroken = packetsSent = packetsRcvd = bytesSent = bytesRcvd = 0;

        WATCH(numSessions);
        WATCH(numBroken);
        WATCH(packetsSent);
        WATCH(packetsRcvd);
        WATCH(bytesSent);
        WATCH(bytesRcvd);
    }
    else if (stage == 3)
    {
        // parameters
        const char *localAddress = par("localAddress");
        int localPort = par("localPort");
        socket.readDataTransferModePar(*this);
        socket.bind(*localAddress ? IPvXAddressResolver().resolve(localAddress) : IPvXAddress(), localPort);

        socket.setCallbackObject(this);
        socket.setOutputGate(gate("tcpOut"));

        setStatusString("waiting");
    }
}

void TCPAppBase_forYT::handleMessage(cMessage *msg)
{
    if (msg->getKind() == 100)    //Se il messaggio è per la verifica di un URL in tabella DNS
    {
        const char *address = msg->par("address");
        cModule *dnsModule = getParentModule()->getSubmodule("DNS");
        DNS *dns = check_and_cast<DNS *>(dnsModule);
        std::string resolved = dns->findAddress(address);

        if (resolved != "")                                   //Se l'indirizzo è in tabella
        {
            if (strcmp(address, "youtube.com") == 0)            //Se l'indirizzo è youtube.com
            {
                msg->addPar("resolvedAddress") = resolved.c_str();
                msg->setKind(50);                               //fai partire la richiesta al front-end server (HTTP Request)
            }
            else                                                //altrimenti se è l'indirizzo del video server
            {
                msg->addPar("resolvedAddress") = resolved.c_str();
                msg->setKind(0);                                //fai partire la richiesta del video (HTTP Videoplayback)
            }
            handleTimer(msg);
        }
        else                                      //Altrimenti se l'indirizzo per l'URL richiesto non è in tabella DNS
            startDNS(msg);                        //fai partire la risoluzione DNS
    }
//    else if (msg->isSelfMessage() && msg->getKind() == 2)
//    {
//        socket.abort();
//        delete msg;
//        rescheduleTimer();
//    }

    else if (msg->isSelfMessage() || msg->getKind() == 0 || msg->getKind() == 50)    //Altrimenti se è la risposta ad una richiesta DNS
        handleTimer(msg);                                                            //fa partire o la richiesta al front-end server o al video server

    else
    {
        socket.processMessage(msg);

        if (par("sendAbort"))
        {
            socket.abort();
            rescheduleTimer();
        }
    }

}

void TCPAppBase_forYT::connect(const char *connectAdd)
{
    // we need a new connId if this is not the first connection
    socket.renewSocket();

    // connect
    const char *connectAddress = connectAdd;
    int connectPort = par("connectPort");

    EV << "issuing OPEN command\n";
    setStatusString("connecting");

    IPvXAddress destination;
    IPvXAddressResolver().tryResolve(connectAddress, destination);
    if (destination.isUnspecified())
        EV << "cannot resolve destination address: " << connectAddress << endl;
    else {
        socket.connect(destination, connectPort);

        numSessions++;
        emit(connectSignal, 1L);
    }
}

void TCPAppBase_forYT::close()
{
    setStatusString("closing");
    EV << "issuing CLOSE command\n";
    socket.close();
    emit(connectSignal, -1L);
}

void TCPAppBase_forYT::sendPacket(cPacket *msg)
{
    int numBytes = msg->getByteLength();
    emit(sentPkSignal, msg);
    socket.send(msg);

    packetsSent++;
    bytesSent += numBytes;
}

void TCPAppBase_forYT::setStatusString(const char *s)
{
    if (ev.isGUI())
        getDisplayString().setTagArg("t", 0, s);
}

void TCPAppBase_forYT::socketEstablished(int, void *)
{
    // *redefine* to perform or schedule first sending
    EV << "connected\n";
    setStatusString("connected");
}

void TCPAppBase_forYT::socketDataArrived(int, void *, cPacket *msg, bool)
{
    // *redefine* to perform or schedule next sending
    packetsRcvd++;
    bytesRcvd += msg->getByteLength();
    emit(rcvdPkSignal, msg);
    delete msg;
}

void TCPAppBase_forYT::socketPeerClosed(int, void *)
{
    // close the connection (if not already closed)
    if (socket.getState() == TCPSocket::PEER_CLOSED)
    {
        EV << "remote TCP closed, closing here as well\n";
        close();
    }
}

void TCPAppBase_forYT::socketClosed(int, void *)
{
    // *redefine* to start another session etc.
    EV << "connection closed\n";
    setStatusString("closed");
}

void TCPAppBase_forYT::socketFailure(int, void *, int code)
{
    // subclasses may override this function, and add code try to reconnect after a delay.
    EV << "connection broken\n";
    setStatusString("broken");

    numBroken++;
}

void TCPAppBase_forYT::finish()
{
    std::string modulePath = getFullPath();

    EV << modulePath << ": opened " << numSessions << " sessions\n";
    EV << modulePath << ": sent " << bytesSent << " bytes in " << packetsSent << " packets\n";
    EV << modulePath << ": received " << bytesRcvd << " bytes in " << packetsRcvd << " packets\n";
}

