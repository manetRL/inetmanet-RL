#include "INETDefs.h"
#include <stdlib.h>
#include <string.h>
#include "QueueBase.h"
#include "IPv4Datagram.h"



class YT_traffic_analyzer : public QueueBase
{
    //Metodi
    public:
    YT_traffic_analyzer() {}
    virtual ~YT_traffic_analyzer() {}

    //Metodi
        protected:
        virtual void initialize();

        virtual void handleMessage(cMessage *msg);

        /**
         * Processing datagrams. Called when a datagram reaches the front
         * of the queue.
         */
        virtual void endService(cPacket *packet);

        /**
         * Handle IPv4Datagram messages arriving from lower layer.
         */
        virtual void handleIncomingDatagram(IPv4Datagram *datagram);

};
