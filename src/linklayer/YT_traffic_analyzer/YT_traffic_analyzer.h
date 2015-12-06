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
    simsignal_t timeSignal;
    simsignal_t durationSignal;
    simsignal_t NumRebufSignal;
    simsignal_t FreqRebuffSignal;

    simsignal_t flowsMeasuredSignal;
    simsignal_t totalQoESignal;
    simsignal_t QoE144pSignal;
    simsignal_t QoE240pSignal;
    simsignal_t QoE360pSignal;
    simsignal_t QoE480pSignal;
    simsignal_t QoE720pSignal;
    simsignal_t QoE1080pSignal;

    double QoEMax;
    double theta0;
    double theta1;
    int numAckToJump;
    int MaxStreamCaptured;
    bool AlgActive;
    double timeOff;
    cMessage *AlgOff;

    enum itag {
        FLV_240p = 5,
        ThreeGP_144p = 17,
        MP4_360p = 18,
        MP4_720p = 22,
        FLV_360p = 34,
        FLV_480p = 35,
        ThreeGP_240p = 36,
        MP4_1080p = 37
    };

    //Attributi
    public:
    double interval;

    struct RebufferingEvent
    {
        double time;
        double timeInVideo;
        double duration;
        RebufferingEvent() { time = 0; timeInVideo = 0; duration = 0;}
    };

    struct StreamingStats
    {
        double QoE1;
        double QoE2A;
        double QoE2B;
        double QoE2C;
        double QoE3A;
        double QoE3B;
        double QoE3C;
        double QoEln;
        cMessage *timer;
        int tcpAppID;
        int numAck;               //Porta il conto degli ack saltati dal controllo
        IPvXAddress clientAddr;
        IPvXAddress serverAddr;
        int TCPServerPort;
        double dur;               // in secondi
        int itag;
        int bitrate;              // in kbps
        double videoSize;         // in Byte
        double tInit;             // tempo assoluto di simulazione in cui inizia il download del video
        double ti;                // istante di osservazione dell'ack, in secondi
        double endDownloadTime;   // tempo di fine download (rispetto al tempo di simulazione)
        bool RSTfound;
        bool requestFound;
        bool MetaTagReceived;
        bool firstAck;
        bool firstRebuf;
        bool psi;                              // stato del player (stallo = 0, esecuzione = 1)
        double Di;                                // Byte scaricati fino all'istante di osservazione dell'ack
        double Di_base;                           // E' il valore da epurare da ogni misura (valore da cui si comincia ad osservare)
        double beta;                           // livello di riempimento del buffer
        double tau;                            // Secondi di video scaricati all'istante ti
        double rho;                            // tempo di riproduzione all'istante ti
        double rebufferingTime;                // durata dello stallo attuale
        int NumEventRebuf;                     // Numero di eventi di rebuffering
        std::vector<RebufferingEvent> events;  // Vettore contenente gli eventi di rebuffering
        StreamingStats() { QoE1 = 0; QoE2A = 0; QoE2B = 0; QoE2C = 0; QoE3A = 0; QoE3B = 0; QoE3C = 0; QoEln = 0; numAck = 0; tcpAppID = 0; clientAddr.set("0.0.0.0"); serverAddr.set("0.0.0.0"); TCPServerPort = 0; dur = 0; itag = 0; bitrate = 0; videoSize = 0; tInit = 0; ti = 0; endDownloadTime = 0; RSTfound = false; requestFound = false; MetaTagReceived = false; firstAck = false; firstRebuf = false; psi = false; Di = 0; beta = 0; tau = 0; rho = 0; rebufferingTime = 0; NumEventRebuf = 0;
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

        virtual void computeQoE(StreamingStats *stream);

        virtual void writeResults(StreamingStats *stream);

        virtual void finish();

};
