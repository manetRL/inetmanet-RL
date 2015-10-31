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

#include "INETDefs.h"
#include <stdlib.h>
#include <string.h>
#include "YT_traffic_analyzer.h"
#include "EtherFrame.h"
#include "Ieee802Ctrl_m.h"
#include "IPv4ControlInfo.h"
#include "DNSRequest_m.h"
#include "DNSReply_m.h"
#include "YTRequestMsg_m.h"
#include "TCPSegment.h"
#include "YTVideoPacketMsg_m.h"

#define TIMER_STREAM_NOT_FOUND 1
#define TIMER_ALG_OFF          2

using namespace std;

Define_Module(YT_traffic_analyzer);

void YT_traffic_analyzer::initialize()
{
    theta0 = 2.2;
    theta1 = 0.4;
    numAckToJump = par("numAckToJump");
    interval = par("DataNotFound");
    MaxStreamCaptured = par("MaxStreamCaptured");
    timeOff = par("timeOff");
    AlgOff = new cMessage("timer");
    AlgActive = true;
}

void YT_traffic_analyzer::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage() && msg->getKind() == TIMER_STREAM_NOT_FOUND)
        deleteStats(msg);
    else if (msg->isSelfMessage() && msg->getKind() == TIMER_ALG_OFF)
        AlgActive = true;
    else if (AlgActive || container.size() != 0)
        QueueBase::handleMessage(msg);
    else
        delete msg;
}

void YT_traffic_analyzer::endService(cPacket *packet)
{
    EtherFrame *frame = dynamic_cast<EtherFrame *>(packet);
    cPacket *higherlayermsg = frame->decapsulate();

    // add Ieee802Ctrl to packet
    Ieee802Ctrl *etherctrl = new Ieee802Ctrl();
    etherctrl->setSrc(frame->getSrc());
    etherctrl->setDest(frame->getDest());
    if (dynamic_cast<EthernetIIFrame *>(frame) != NULL)
        etherctrl->setEtherType(((EthernetIIFrame *)frame)->getEtherType());
    higherlayermsg->setControlInfo(etherctrl);

    delete frame;

    if (dynamic_cast<IPv4Datagram *>(higherlayermsg))
        handleIncomingDatagram((IPv4Datagram *)higherlayermsg);
    else
        delete higherlayermsg;

}

void YT_traffic_analyzer::handleIncomingDatagram(IPv4Datagram *datagram)   //Qui mi arriva il pacchetto IPv4 da esaminare
{
    if (datagram->hasBitError())
    {
        delete datagram;
        return;
    }

    cPacket *packet = IPv4decapsulate(datagram);

    if (dynamic_cast<DNSReply *>(packet) != NULL && AlgActive)
    {
        if (container.size() < MaxStreamCaptured)
        {
            if(strcmp(((DNSReply *)packet)->getURL(), "googlevideo1.com") == 0 || strcmp(((DNSReply *)packet)->getURL(), "googlevideo2.com") == 0 || strcmp(((DNSReply *)packet)->getURL(), "googlevideo3.com") == 0)
            {
                for (it = container.begin(); it != container.end(); ++it)                                                            //
                {                                                                                                                    //
                    if (it->clientAddr == datagram->getDestAddress() && it->serverAddr == ((DNSReply *)packet)->getDest_adress())    // QUESTO PEZZO NON PERMETTE DI AVERE DUE FLUSSI CONTEMPORANEI
                    {                                                                                                                // PER LO STESSO CLIENT.
                        cancelEvent(it->timer);                                                                                      //
                        container.erase(it);                                                                                         //
                        break;                                                                                                       //
                    }                                                                                                                //
                }                                                                                                                    //
                StreamingStats *stream = new StreamingStats();
                stream->clientAddr = datagram->getDestAddress();
                stream->serverAddr = ((DNSReply *)packet)->getDest_adress();
                cMessage *stopTimer = new cMessage("Data_not_found");
                stopTimer->setContextPointer(stream);
                stopTimer->setKind(TIMER_STREAM_NOT_FOUND);
                scheduleAt(simTime() + interval, stopTimer);
                stream->timer = stopTimer;
                container.push_back(*stream);
            }
        }
    }
    else
    {
        for (it = container.begin(); it != container.end(); ++it)
        {
            if (it->clientAddr == datagram->getSrcAddress() && it->serverAddr == datagram->getDestAddress())
            {
                analyzeCtoS(packet, &*it);         //i pacchetti vanno dal client al server
                break;
            }
            else if (it->serverAddr == datagram->getSrcAddress() && it->clientAddr == datagram->getDestAddress() && it->requestFound)
            {
                analyzeStoC(packet, &*it);        //i pacchetti vanno dal server al client
                break;
            }
        }
    }

    delete packet;
    delete datagram;
}

void YT_traffic_analyzer::analyzeCtoS(cPacket *packet, StreamingStats *stream)      //Possono passare VideoRequest, SYN/FIN o gli ACK (importanti, ricordare che il primo è da ignorare perchè non ancora arrivano i metatag e quindi ancora parte lo streaming. In generale si ignorano tutti quelli prima dei metatag)
{
    ASSERT(stream->beta >= 0);

    if (dynamic_cast<TCPSegment *>(packet) != NULL)         //Verifico che sia un segmento TCP
    {
        TCPSegment *tcpseg = dynamic_cast<TCPSegment *>(packet);
        //Per prima cosa vedo se è una VideoRequest

        int i = (tcpseg->getPayloadArraySize());
        if (i>0)
        {
            cPacket *pack = tcpseg->getPayload(0).msg;
            if (dynamic_cast<YTRequestMsg *>(pack) != NULL)              //Conosco quindi itag e durata del video, inoltre setto una variabile per segnalare che ho intercettato la richiesta video e sta per iniziare lo streaming
            {
                stream->dur = ((YTRequestMsg *)pack)->getDur();
                stream->itag = ((YTRequestMsg *)pack)->getItag();
                stream->requestFound = true;
            }
        }
        else if (tcpseg->getAckBit() && !tcpseg->getFinBit() && stream->MetaTagReceived)    // verifica ACK ignorando quelli prima dei metatag e quelli col FIN settato  ( FORSE ANCHE QUELLI COL RST!!! )
        {
            if (!stream->firstAck)         //Condizione per il controllo del primo ACK
            {
                stream->Di = tcpseg->getAckNo();
                stream->Di_base = tcpseg->getAckNo();
                stream->ti = simTime().dbl();
                stream->tInit = simTime().dbl();
                stream->firstAck = true;
                return;
            }

            if (stream->numAck < numAckToJump)     //Condizione per saltare il controllo per un certo numero di ACK
            {
                stream->numAck = stream->numAck + 1;
                return;
            }
            else
                stream->numAck = 0;

            // Cuore dell'algoritmo: devo verificare a quale dei 4 casi appartengo e fare le azioni appropriate.

            //Devo calcolare tau nuovo e poi tau_dt
            int D_deltat = tcpseg->getAckNo() - stream->Di;
            stream->Di = tcpseg->getAckNo();
            double newTau = (double)(stream->dur * (stream->Di - stream->Di_base))/stream->videoSize;
            double tau_dt = newTau - stream->tau;   // quantità di secondi di video scaricati negli ultimi dt secondi
            stream->tau = newTau;
            double deltat = simTime().dbl() - stream->ti;
            stream->ti = simTime().dbl();

            if (!stream->psi && (stream->beta + tau_dt) >= theta0)      //Caso STALLO -> PLAY
            {
                stream->psi = true;
                stream->rho = stream->rho + deltat;
                stream->beta = stream->beta + tau_dt - deltat;
                if (stream->beta < 0.4)                         //ENTRA IN PLAY - STALLO
                {
                    stream->rho = stream->rho - (0.4 - stream->beta);    //Tale istruzione corregge la quantità di video riprodotta dovuta al fatto di essere scesi al di sotto di 0.4 secondi di video nel buffer
                    stream->beta = 0.4;
                    stream->psi = false;
                    stream->NumEventRebuf = stream->NumEventRebuf + 1;
                    stream->rebufferingTime = 0;                             //Faccio in modo da avere un elemento del vettore "events" per ogni evento di rebuffering che riporta istante di blocco e durata.
                    RebufferingEvent *eve = new RebufferingEvent;
                    eve->time = simTime().dbl() - stream->tInit;;
                    stream->events.push_back(*eve);
                    return;
                }
            }
            else if (!stream->psi && (stream->beta + tau_dt) < theta0)  //Caso STALLO -> STALLO
            {
                stream->rebufferingTime = stream->rebufferingTime + deltat;
                stream->beta = stream->beta + tau_dt;
                stream->events.back().duration = stream->rebufferingTime;
            }
            else if (stream->psi && (stream->beta + tau_dt) > theta1)   //Caso PLAY -> PLAY
            {
                stream->rho = stream->rho + deltat;
                stream->beta = stream->beta + tau_dt - deltat;
                if (stream->beta < 0.4)                         //ENTRA IN PLAY - STALLO
                {
                    stream->rho = stream->rho - (0.4 - stream->beta);
                    stream->beta = 0.4;
                    stream->psi = false;
                    stream->NumEventRebuf = stream->NumEventRebuf + 1;
                    stream->rebufferingTime = 0;                             //Faccio in modo da avere un elemento del vettore "events" per ogni evento di rebuffering che riporta istante di blocco e durata.
                    RebufferingEvent *eve = new RebufferingEvent;
                    eve->time = simTime().dbl() - stream->tInit;
                    stream->events.push_back(*eve);
                    return;
                }

                float Vin = (D_deltat*8)/deltat;                  //Velocità di alimentazione del buffer (in bit/s)
                float Vout = (stream->videoSize*8)/stream->dur;   //Velocità di riproduzione del video (in bit/s)

                simtime_t Teb;
                if (Vout > Vin)
                {
                    Teb = ((stream->beta - theta1)*stream->videoSize*8/stream->dur)/(Vout - Vin);
                    if (Teb < 5)
                        numAckToJump = 0;
                }
                else
                    numAckToJump = par("numAckToJump");

            }

        }
        else if (tcpseg->getFinBit())    //Quando trova il bit FIN settato significa che il video ha finito di essere scaricato
        {
            record.push_back(*stream);
            for (it = container.begin(); it != container.end(); ++it)
            {
                IPv4ControlInfo *contr = (IPv4ControlInfo *)tcpseg->getControlInfo();
                if (it->clientAddr == contr->getSrcAddr() && it->serverAddr == contr->getDestAddr())
                {
                    container.erase(it);
                    break;
                }
            }
            if (container.size() == 0)
                rescheduleTimerOff();
        }
        else if (tcpseg->getRstBit())     //Vi si entra quando si trova il RST settato: ciò significa che il video è stato interrotto dall'utente per cui si termina la raccolta di statistiche per tale flusso
        {
            stream->RSTfound = true;
            record.push_back(*stream);
            for (it = container.begin(); it != container.end(); ++it)
            {
                IPv4ControlInfo *contr = (IPv4ControlInfo *)tcpseg->getControlInfo();
                if (it->clientAddr == contr->getSrcAddr() && it->serverAddr == contr->getDestAddr())
                {
                    container.erase(it);
                    break;
                }
            }
            if (container.size() == 0)
                rescheduleTimerOff();
        }
    }
    else
        return;

}

void YT_traffic_analyzer::analyzeStoC(cPacket *packet, StreamingStats *stream)
{
    if (dynamic_cast<TCPSegment *>(packet) != NULL)
    {
        int i = ((TCPSegment *)packet)->getPayloadArraySize();
        if (i>0)
        {
            cPacket *pack = ((TCPSegment *)packet)->getPayload(0).msg;
            if (dynamic_cast<YTVideoPacketMsg *>(pack) != NULL)
            {
                stream->bitrate = ((YTVideoPacketMsg *)pack)->getMetaTag_bitrate();
                stream->videoSize = ((YTVideoPacketMsg *)pack)->getMetaTag_videoSize();
                stream->MetaTagReceived = true;
            }
        }
    }
    else
        return;

}

void YT_traffic_analyzer::deleteStats(cMessage *msg)
{
    StreamingStats *flusso = (StreamingStats *)msg->getContextPointer();

    for (it = container.begin(); it != container.end(); ++it)
    {
        if (it->clientAddr == flusso->clientAddr && it->serverAddr == flusso->serverAddr && !it->MetaTagReceived)
        {
            container.erase(it);
            break;
        }
    }
//    if (container.size() == 0)
//        rescheduleTimerOff();
    delete msg;
}

void YT_traffic_analyzer::rescheduleTimerOff()
{
    AlgActive = false;
    AlgOff->setKind(TIMER_ALG_OFF);
    scheduleAt(simTime() + timeOff, AlgOff);

}

cPacket *YT_traffic_analyzer::IPv4decapsulate(IPv4Datagram *datagram)
{
    cPacket *packet = datagram->decapsulate();

    // create and fill in control info
    IPv4ControlInfo *controlInfo = new IPv4ControlInfo();
    controlInfo->setProtocol(datagram->getTransportProtocol());
    controlInfo->setSrcAddr(datagram->getSrcAddress());
    controlInfo->setDestAddr(datagram->getDestAddress());
    controlInfo->setTypeOfService(datagram->getTypeOfService());
    controlInfo->setTimeToLive(datagram->getTimeToLive());

    // attach control info
    packet->setControlInfo(controlInfo);

    return packet;
}


