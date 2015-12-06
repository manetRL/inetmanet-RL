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

#ifndef __INET_TCP_YT_REQUEST_APP_H
#define __INET_TCP_YT_REQUEST_APP_H

#include "INETDefs.h"


#include "TCPAppBase_forYT.h"
#include "NodeStatus.h"
#include "ILifecycle.h"
#include "YTRequestMsg_m.h"
#include "IPvXAddressResolver.h"




/**
 * An example request-reply based client application.
 */
class INET_API TCP_YT_request_App : public TCPAppBase_forYT, public ILifecycle
{
  protected:
    cMessage *abortMsg;
    cMessage *timeoutMsg;
    NodeStatus *nodeStatus;
    bool earlySend;  // if true, don't wait with sendRequest() until established()
    int numRequestsToSend; // requests to send in this session
    int videoSize;
    simtime_t startTime;
    simtime_t stopTime;


    /** Utility: sends a request to the server */
    virtual void sendRequest();

    /** Utility: cancel msgTimer and if d is smaller than stopTime, then schedule it to d,
     * otherwise delete msgTimer */
    virtual void rescheduleOrDeleteTimer(simtime_t d, short int msgKind);

  public:

    enum videoBitrate
        {
            FLV_240p_br = 400,    // 'Low Quality, 240p, FLV, 400x240';
            ThreeGP_144p_br = 150,   // 'Low Quality, 144p, 3GP, 0x0';
            MP4_360p_br = 750,   // 'Medium Quality, 360p, MP4, 480x360';
            MP4_720p_br = 2500,   // 'High Quality, 720p, MP4, 1280x720';
            FLV_360p_br = 750,   // 'Medium Quality, 360p, FLV, 640x360';
            FLV_480p_br = 1000,   // 'Standard Definition, 480p, FLV, 854x480';
            ThreeGP_240p_br = 400,   // 'Low Quality, 240p, 3GP, 0x0';
            MP4_1080p_br = 4500  // 'Full High Quality, 1080p, MP4, 1920x1080';
        };

    TCP_YT_request_App();
    virtual ~TCP_YT_request_App();
    virtual bool handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback);
    static itagType convertStringToItag(const char * itag);
    TCP_YT_request_App::videoBitrate convertStringToBitrate(const char * btr);


  protected:
    virtual void requestPage(cMessage *msg);

    virtual void startDNS(cMessage *msg);

    virtual int numInitStages() const { return 4; }

    /** Redefined . */
    virtual void initialize(int stage);

    /** Redefined. */
    virtual void handleTimer(cMessage *msg);

    /** Redefined. */
    virtual void socketEstablished(int connId, void *yourPtr);

    /** Redefined. */
    virtual void socketDataArrived(int connId, void *yourPtr, cPacket *msg, bool urgent);

    /** Redefined to start another session after a delay. */
    virtual void socketClosed(int connId, void *yourPtr);

    /** Redefined to reconnect after a delay. */
    virtual void socketFailure(int connId, void *yourPtr, int code);

    virtual bool isNodeUp();

    virtual void rescheduleTimer();
};

#endif

