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

#ifndef __INET_TCP_YT_traffic_gen_H
#define __INET_TCP_YT_traffic_gen_H

#include "INETDefs.h"
#include "ILifecycle.h"
#include "NodeStatus.h"
#include "TCPSocket.h"

/**
 * Accepts any number of incoming connections, and sends back whatever
 * arrives on them.
 */
class INET_API TCP_YT_traffic_gen : public cSimpleModule, public ILifecycle
{
public:
    struct VideoStreamData
    {
        cMessage *timer;          ///< self timer msg
//        TCPSendCommand *cmd = new TCPSendCommand();       ///< Comando da applicare per il reinvio dei pacchetti
        TCPSendCommand* cmd;
        long videoSize;           ///< total size of video
        long bytesLeft;           ///< bytes left to transmit
        long numPkSent;           ///< number of packets sent
        int vidBitrt;
        int durata;
        bool blocked;
        VideoStreamData() { timer = NULL; cmd = NULL; videoSize = bytesLeft = 0; numPkSent = 0; vidBitrt = 0; durata=0; blocked = false; }
    };

    bool firstPacket;
    long chunk;

  protected:
    typedef std::map<long int, VideoStreamData> VideoStreamMap;
    VideoStreamMap streams;

    simtime_t delay;
//    double echoFactor;
    int videoBitrate;
    long videoSize;

    TCPSocket socket;
    NodeStatus *nodeStatus;

    long bytesRcvd;
    long bytesSent;

    unsigned int numStreams;  // number of video streams served
    unsigned long numPkSent;  // total number of packets sent

//    cPar *videoSize;

    static simsignal_t rcvdPkSignal;
    static simsignal_t sentPkSignal;
    static simsignal_t reqStreamBytesSignal;  // length of video streams served


  public:
    virtual bool handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback);
//    TCP_YT_traffic_gen();
    virtual ~TCP_YT_traffic_gen();

  protected:
    virtual bool isNodeUp();
    virtual void sendDown(cMessage *msg);

    // send a packet of the given video stream
    virtual void sendStreamData(cMessage *timer);
    virtual void startListening();
    virtual void stopListening();

  protected:
    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);
    virtual void finish();
    virtual void clearStreams();

};

#endif


