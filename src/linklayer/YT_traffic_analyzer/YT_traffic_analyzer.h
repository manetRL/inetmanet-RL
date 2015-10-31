#include "INETDefs.h"
#include <stdlib.h>
#include <string.h>
#include "QueueBase.h"
#include "IPv4Datagram.h"
#include "IPvXAddressResolver.h"



class YT_traffic_analyzer : public QueueBase
{
    //Attributi
    private:
    double theta0;
    double theta1;
    int numAckToJump;
    int MaxStreamCaptured;
    bool AlgActive;
    double timeOff;
    cMessage *AlgOff;

    //Attributi
    public:
    double interval;

    struct RebufferingEvent
    {
        double time;
        double duration;
        RebufferingEvent() { time = 0; duration = 0;}
    };

    struct StreamingStats
    {
        cMessage *timer;
        int tcpAppID;
        int numAck;              //Porta il conto degli ack saltati dal controllo
        IPvXAddress clientAddr;
        IPvXAddress serverAddr;
        int dur;                // in secondi
        int itag;
        int bitrate;            // in kbps
        int videoSize;          // in Byte
        double tInit;        // tempo assoluto di simulazione in cui inizia il download del video
        double ti;           // istante di osservazione dell'ack, in secondi
        bool RSTfound;
        bool requestFound;
        bool MetaTagReceived;
        bool firstAck;
        bool psi;                              // stato del player (stallo = 0, esecuzione = 1)
        int Di;                                // Byte scaricati fino all'istante di osservazione dell'ack
        int Di_base;                           // E' il valore da epurare da ogni misura (valore da cui si comincia ad osservare)
        double beta;                           // livello di riempimento del buffer
        double tau;                            // Secondi di video scaricati all'istante ti
        double rho;                            // tempo di riproduzione all'istante ti
        double rebufferingTime;                // durata dello stallo attuale
        int NumEventRebuf;                     // Numero di eventi di rebuffering
        std::vector<RebufferingEvent> events;  // Vettore contenente gli eventi di rebuffering
        StreamingStats() { numAck = 0; tcpAppID = 0; clientAddr.set("0.0.0.0"); serverAddr.set("0.0.0.0"); dur = 0; itag = 0; bitrate = 0; videoSize = 0; tInit = 0; ti = 0; RSTfound = false; requestFound = false; MetaTagReceived = false; firstAck = false; psi = false; Di = 0; beta = 0; tau = 0; rho = 0; rebufferingTime = 0; NumEventRebuf = 0;
                           RebufferingEvent *eve = new RebufferingEvent;
                           events.push_back(*eve); }
    };
    std::vector<StreamingStats> container;       //vettore che contiene tutte le coppie client-server i cui flussi devono essere esaminati
    std::vector<StreamingStats>::iterator it;

    std::vector<StreamingStats> record;



    //Metodi
    public:
    YT_traffic_analyzer() {}
    virtual ~YT_traffic_analyzer() {cancelEvent(AlgOff); delete(AlgOff);}

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

        /**
         * Funzione per decapsulare i pacchetti IPv4
         */
        virtual cPacket *IPv4decapsulate(IPv4Datagram *datagram);

        virtual void analyzeCtoS(cPacket *packet, StreamingStats *stream);

        virtual void analyzeStoC(cPacket *packet, StreamingStats *stream);

        /**
         * Funzione per cancellare le statistiche di un flusso di cui non sono stati catturati i metatag.
         */
        virtual void deleteStats(cMessage *msg);

        virtual void rescheduleTimerOff();

};
