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
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <math.h>
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
    timeSignal = registerSignal("time");
    durationSignal = registerSignal("duration");
    NumRebufSignal = registerSignal("NumRebuf");
    FreqRebuffSignal = registerSignal("FreqRebuff");
    flowsMeasuredSignal = registerSignal("flowsMeasured");
    totalQoESignal = registerSignal("totalQoE");
    QoE144pSignal = registerSignal("QoE144p");
    QoE240pSignal = registerSignal("QoE240p");
    QoE360pSignal = registerSignal("QoE360p");
    QoE480pSignal = registerSignal("QoE480p");
    QoE720pSignal = registerSignal("QoE720p");
    QoE1080pSignal = registerSignal("QoE1080p");

    theta0 = 2.2;
    theta1 = 0.4;
    QoEMax = par("QoEMax");
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
                for (it = container.begin(); it != container.end(); ++it)
                {
                    if (it->clientAddr == datagram->getDestAddress()) // && it->serverAddr == ((DNSReply *)packet)->getDest_adress())
                    {
                        delete(packet);
                        delete(datagram);
                        return;
                    }
                }
                StreamingStats *stream = new StreamingStats();
                stream->clientAddr = datagram->getDestAddress();
                stream->serverAddr = ((DNSReply *)packet)->getDest_adress();
                stream->tcpAppID = ((DNSReply *)packet)->getTcpAppID();
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
            if (dynamic_cast<YTRequestMsg *>(pack) != NULL && pack->getSenderModuleId() == stream->tcpAppID)      //Conosco quindi itag e durata del video, inoltre setto una variabile per segnalare che ho intercettato la richiesta video e sta per iniziare lo streaming
            {
                stream->dur = ((YTRequestMsg *)pack)->getDur();
                stream->itag = ((YTRequestMsg *)pack)->getItag();
                stream->TCPServerPort = tcpseg->getDestPort();
                stream->requestFound = true;
            }
        }
        else if (tcpseg->getDestPort() == stream->TCPServerPort)    //Verifica che il segmento tcp appartiene a questo flusso dati
        {
            if (tcpseg->getAckBit() && !tcpseg->getFinBit() && stream->MetaTagReceived)    // verifica ACK ignorando quelli prima dei metatag e quelli col FIN settato  ( FORSE ANCHE QUELLI COL RST!!! )
            {
                if (!stream->firstAck)         //Condizione per il controllo del primo ACK
                {
                    stream->Di = tcpseg->getAckNo();
                    stream->Di_base = tcpseg->getAckNo();
                    stream->ti = simTime().dbl();
                    stream->tInit = simTime().dbl();
                    stream->firstAck = true;
                    stream->firstRebuf = true;
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
                double newTau = (stream->dur * (stream->Di - stream->Di_base))/stream->videoSize;
                double tau_dt = newTau - stream->tau;   // quantità di secondi di video scaricati negli ultimi dt secondi
                stream->tau = newTau;
                double deltat = simTime().dbl() - stream->ti;
                stream->ti = simTime().dbl();

                if (!stream->psi && (stream->beta + tau_dt) >= theta0 && !stream->firstRebuf)      //Caso STALLO -> PLAY NORMALE
                {
                    //stream->firstRebuf = false;
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
                        eve->timeInVideo = stream->rho;
                        stream->events.push_back(*eve);
                        return;
                    }
                }
                else if (!stream->psi && (stream->beta + tau_dt) >= 10 && stream->firstRebuf)      //Caso STALLO -> PLAY Primo Buffering
                {
                    stream->firstRebuf = false;
                    stream->psi = true;
                    stream->rho = stream->rho + deltat;
                    stream->beta = stream->beta + tau_dt - deltat;
                }
                else if (!stream->psi && (stream->beta + tau_dt) < theta0 && !stream->firstRebuf)  //Caso STALLO -> STALLO NORMALE
                {
                    stream->rebufferingTime = stream->rebufferingTime + deltat;
                    stream->beta = stream->beta + tau_dt;
                    stream->events.back().duration = stream->rebufferingTime;
                }
                else if (!stream->psi && (stream->beta + tau_dt) < 10 && stream->firstRebuf)  //Caso STALLO -> STALLO Primo Buffering
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
                        eve->timeInVideo = stream->rho;
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
                computeQoE(stream);
                writeResults(stream);
                emit(flowsMeasuredSignal,stream);
                emit(totalQoESignal,stream->QoE3C);
                emit(FreqRebuffSignal, stream->NumEventRebuf/stream->dur);
                stream->endDownloadTime = simTime().dbl();

                record.push_back(*stream);
                std::vector<RebufferingEvent>::iterator reb;
                for (reb = stream->events.begin()+1; reb != stream->events.end(); ++reb)
                {
                    emit(timeSignal, reb->timeInVideo);
                    emit(durationSignal, reb->duration);
                }
                emit(NumRebufSignal, stream->NumEventRebuf);

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
            if (dynamic_cast<YTVideoPacketMsg *>(pack) != NULL && stream->TCPServerPort == ((TCPSegment *)packet)->getSrcPort())
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

    delete msg;
}

void YT_traffic_analyzer::computeQoE(StreamingStats *stream)
{
    double sommaIstantiStallo = 0;
//    double sumForQoE3 = 0;
    double stalloTot = 0;            //Somma della durata di tutti gli stalli
    double stalloMedio = 0;          //Durata media degli stalli
    double istanteStalloMedio = 0;   //Istante di tempo medio degli avvenimenti di stallo
    double istanteStalloMedio_norm = 0;  //Utilizzato per il calcolo della QoE con varianza
    double QoERif = 0;
    double QoEcl = 0;
    double QoERif_Var = 0;
    double QoEdevstd = 0;
    double devstd_norm = 0;
    std::vector<RebufferingEvent>::iterator reb;

    if (stream->NumEventRebuf > 0)
    {
        for (reb = stream->events.begin()+1; reb != stream->events.end(); ++reb)
        {
            stalloTot = stalloTot + reb->duration;
            sommaIstantiStallo = sommaIstantiStallo + reb->timeInVideo;
//          sumForQoE3 = sumForQoE3 + (reb->timeInVideo/stream->rho - 0.5)*reb->duration + reb->duration;
        }

        istanteStalloMedio = sommaIstantiStallo/stream->NumEventRebuf;
        istanteStalloMedio_norm = istanteStalloMedio/stream->dur;
        stalloMedio = stalloTot/stream->NumEventRebuf;


        if(istanteStalloMedio <= stream->rho/4)
            QoERif = 3.25;
        else if (istanteStalloMedio > stream->rho/4 && istanteStalloMedio <= stream->rho/2)
            QoERif = 3;
        else if (istanteStalloMedio > stream->rho/2 && istanteStalloMedio <= stream->rho/4*3)
            QoERif = 2.75;
        else if (istanteStalloMedio > stream->rho/4*3)
            QoERif = 2.5;
        else throw cRuntimeError(this, "Problemi con calcolo QoE");

        if(istanteStalloMedio_norm <= 0.25)
            QoEcl = 2.5;
        else if (istanteStalloMedio_norm > 0.25 && istanteStalloMedio_norm <= 0.5)
            QoEcl = 2.75;
        else if (istanteStalloMedio_norm > 0.5 && istanteStalloMedio_norm <= 0.75)
            QoEcl = 3;
        else if (istanteStalloMedio_norm > 0.75)
            QoEcl = 3.25;
        else throw cRuntimeError(this, "Problemi con calcolo QoE");

        double tempvar = 0;
        for (reb = stream->events.begin()+1; reb != stream->events.end(); ++reb)
            tempvar = tempvar + (reb->timeInVideo - istanteStalloMedio)*(reb->timeInVideo - istanteStalloMedio);
        devstd_norm = sqrt(tempvar/stream->NumEventRebuf)/stream->dur;

        if(QoEcl == 2.5 && istanteStalloMedio_norm + devstd_norm <= 0.25)
            QoERif_Var = QoEcl;
        else if (QoEcl == 2.75 && istanteStalloMedio_norm + devstd_norm > 0.25 && istanteStalloMedio_norm + devstd_norm <= 0.5)
            QoERif_Var = QoEcl;
        else if (QoEcl == 3 && istanteStalloMedio_norm + devstd_norm > 0.5 && istanteStalloMedio_norm + devstd_norm <= 0.75)
            QoERif_Var = QoEcl - 0.25;
        else if (QoEcl == 3.25 && istanteStalloMedio_norm + devstd_norm > 0.75 && istanteStalloMedio_norm + devstd_norm <= 1)
            QoERif_Var = QoEcl - 0.5;
        else
        {
            QoERif_Var = QoEcl + 0.25*(devstd_norm/0.125);
            if (QoERif_Var > 3.25)
                QoERif_Var = 3.25;
        }

        if (devstd_norm < 0.1)
            QoEdevstd = QoERif;
        else if (devstd_norm >= 0.1 && devstd_norm < 0.2)
            QoEdevstd = 3;
        else if (devstd_norm >= 0.2)
            QoEdevstd = 3.25;

        double rebufFreq = stream->NumEventRebuf/stream->dur;

        stream->QoE1 = (1 - stream->NumEventRebuf*stalloMedio/stream->rho)*QoEMax;
        if(stream->QoE1 < 0)
            stream->QoE1 = 0;

        stream->QoE2A = (1 - stream->NumEventRebuf*stalloMedio/stream->rho)*QoERif;
        if(stream->QoE2A < 0)
            stream->QoE2A = 0;

        if (stream->NumEventRebuf > 1)
        {
            stream->QoE2B = (1 - stream->NumEventRebuf*stalloMedio/stream->rho)*QoERif_Var;
            if(stream->QoE2B < 0)
                stream->QoE2B = 0;

            stream->QoE2C = (1 - stream->NumEventRebuf*stalloMedio/stream->rho)*QoEdevstd;
            if(stream->QoE2C < 0)
                stream->QoE2C = 0;
        }
        else
        {
            stream->QoE2B = (1 - stream->NumEventRebuf*stalloMedio/stream->rho)*QoERif;
            if(stream->QoE2B < 0)
                stream->QoE2B = 0;

            stream->QoE2C = (1 - stream->NumEventRebuf*stalloMedio/stream->rho)*QoERif;
            if(stream->QoE2C < 0)
                stream->QoE2C = 0;
        }

        stream->QoE3A = (1 - (stream->NumEventRebuf/stream->rho) * ((istanteStalloMedio/stream->rho - 0.5) * stalloMedio + stalloMedio))*QoERif;
        if(stream->QoE3A < 0)
            stream->QoE3A = 0;

        if (stream->NumEventRebuf > 1)
        {
            stream->QoE3B = (1 - (stream->NumEventRebuf/stream->rho) * ((istanteStalloMedio/stream->rho - 0.5) * stalloMedio + stalloMedio))*QoERif_Var;
            if(stream->QoE3B < 0)
                stream->QoE3B = 0;

            stream->QoE3C = (1 - (stream->NumEventRebuf/stream->rho) * ((istanteStalloMedio/stream->rho - 0.5) * stalloMedio + stalloMedio))*QoEdevstd;
            if(stream->QoE3C < 0)
                stream->QoE3C = 0;
        }
        else
        {
            stream->QoE3B = (1 - (stream->NumEventRebuf/stream->rho) * ((istanteStalloMedio/stream->rho - 0.5) * stalloMedio + stalloMedio))*QoERif;
            if(stream->QoE3B < 0)
                stream->QoE3B = 0;

            stream->QoE3C = (1 - (stream->NumEventRebuf/stream->rho) * ((istanteStalloMedio/stream->rho - 0.5) * stalloMedio + stalloMedio))*QoERif;
            if(stream->QoE3C < 0)
                stream->QoE3C = 0;
        }

        stream->QoEln = -log(60*rebufFreq)+2;
        if (60*rebufFreq > 3)
            stream->QoEln = 0;
        else if (60*rebufFreq < 0.1)
            stream->QoEln = 3.25;

        if (stream->QoEln > 3.25)
            stream->QoEln = 3.25;
        else if (stream->QoEln < 0)
            stream->QoEln = 0;
    }
    else
    {
        stream->QoE1 = 3.25;
        stream->QoE2A = 3.25;
        stream->QoE2B = 3.25;
        stream->QoE2C = 3.25;
        stream->QoE3A = 3.25;
        stream->QoE3B = 3.25;
        stream->QoE3C = 3.25;
        stream->QoEln = 3.25;
    }

//    if(istanteStalloMedio <= stream->rho/4)
//        QoERif = 4;
//    else if (istanteStalloMedio > stream->rho/4 && istanteStalloMedio <= stream->rho/2)
//        QoERif = 3.5;
//    else if (istanteStalloMedio > stream->rho/2 && istanteStalloMedio <= stream->rho/4*3)
//        QoERif = 3;
//    else if (istanteStalloMedio > stream->rho/4*3)
//        QoERif = 2.5;
//    else throw cRuntimeError(this, "Problemi con calcolo QoE");
//
//    if(istanteStalloMedio_norm <= 0.25)
//        QoERif1 = 2.5;
//    else if (istanteStalloMedio_norm > 0.25 && istanteStalloMedio_norm <= 0.5)
//        QoERif1 = 3;
//    else if (istanteStalloMedio_norm > 0.5 && istanteStalloMedio_norm <= 0.75)
//        QoERif1 = 3.5;
//    else if (istanteStalloMedio_norm > 0.75)
//        QoERif1 = 4;
//    else throw cRuntimeError(this, "Problemi con calcolo QoE");
//
//    double tempvar = 0;
//    for (reb = stream->events.begin()+1; reb != stream->events.end(); ++reb)
//        tempvar = tempvar + (reb->timeInVideo - istanteStalloMedio)*(reb->timeInVideo - istanteStalloMedio);
//    dev_std_norm = sqrt(tempvar/stream->NumEventRebuf)/stream->dur;
//    QoERif_Var = QoERif1 + 0.5*floor(dev_std_norm/0.125);

//    stream->QoE1 = (1 - stalloTot/stream->rho)*QoEMax;
//
//    stream->QoE2 = (1 - stream->NumEventRebuf*(stalloTot/stream->rho))*QoEMax;
//
//    stream->QoE_conMax = (1 - (stream->NumEventRebuf/stream->rho)*sumForQoE3)*QoEMax;
//
//    if (stream->NumEventRebuf > 1)
//    {
//        stream->QoE_conRif = (1 - (stream->NumEventRebuf/stream->rho)*sumForQoE3)*QoERif;
//        stream->QoE_conVar = (1 - (stream->NumEventRebuf/stream->rho)*sumForQoE3)*QoERif_Var;
//    }
//    else
//    {
//        stream->QoE_conRif = (1 - (stream->NumEventRebuf/stream->rho)*sumForQoE3)*QoERif;
//        stream->QoE_conVar = (1 - (stream->NumEventRebuf/stream->rho)*sumForQoE3)*QoERif;;
//    }

}

void YT_traffic_analyzer::writeResults(StreamingStats *stream)
{
    switch (stream->itag)
    {
        case ThreeGP_144p:
            emit(QoE144pSignal,stream->QoE3C);
            break;
        case ThreeGP_240p:
            emit(QoE240pSignal,stream->QoE3C);
            break;
        case FLV_240p:
            emit(QoE240pSignal,stream->QoE3C);
            break;
        case FLV_360p:
            emit(QoE360pSignal,stream->QoE3C);
            break;
        case MP4_360p:
            emit(QoE360pSignal,stream->QoE3C);
            break;
        case FLV_480p:
            emit(QoE480pSignal,stream->QoE3C);
            break;
        case MP4_720p:
            emit(QoE720pSignal,stream->QoE3C);
            break;
        case MP4_1080p:
            emit(QoE1080pSignal,stream->QoE3C);
            break;
    }
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

void YT_traffic_analyzer::finish()
{
    if (record.size() == 0)
        return;


    const char *fileResults = par("fileNameResults");
    const char *fileSummary = par("fileNameSummary");
    ofstream results (fileResults);
    ofstream summary (fileSummary);

    results << "timeReproduction" << ',' << "simTime" << ',' << "clientIP" << ',' << "serverIP" << ',' << "videoQuality" << ',' << "videoDuration" << ',' << "PlayerStatus" << endl;
    summary << "simTime" << ',' << "clientIP" << ',' << "serverIP" << ',' << "videoQuality" << ',' << "videoDuration" << ',' << "QoE1" << ',' << "QoE2A" << ',' << "QoE2B" << ',' << "QoE2C" << ',' << "QoE3A" << ',' << "QoE3B" << ',' << "QoE3C" << ',' << "QoEln" << ',' << "NumOfRebuffer" << ',' << "totalRebufferDuration" << ',' << "meanRebufferPosition" << ',' << "stddevRebufferPosition" << ',' << "RebufferFreq" << endl;

    std::vector<StreamingStats>::iterator iter;
    for (iter = record.begin(); iter != record.end(); ++iter)
    {
        double stalloTot = 0;
        double sommaIstantiStallo = 0;
        double istanteStalloMedio = 0;
        double stddev = 0;
        double rebufFreq = 0;
        std::vector<RebufferingEvent>::iterator eve;
        results << endl;
        for (eve = iter->events.begin()+1; eve != iter->events.end(); eve++)   //Non viene considerato il tempo di primo buffering all'inizio del video.
        {
            stalloTot = stalloTot + eve->duration;
            sommaIstantiStallo = sommaIstantiStallo + eve->timeInVideo;

            results << eve->timeInVideo << ',' << eve->time << ',' << iter->clientAddr.str() << ',' << iter->serverAddr.str() << ',' << iter->itag << ',' << iter->dur << ',' << "0" <<  endl;
            results << eve->timeInVideo << ',' << eve->time+eve->duration << ',' << iter->clientAddr.str() << ',' << iter->serverAddr.str() << ',' << iter->itag << ',' << iter->dur << ',' << "1" <<  endl;
        }
        if (iter->NumEventRebuf > 0)
        {
            istanteStalloMedio = sommaIstantiStallo/iter->NumEventRebuf;
            double temp = 0;
            for (eve = iter->events.begin()+1; eve != iter->events.end(); eve++)
                temp = temp + (eve->timeInVideo - istanteStalloMedio)*(eve->timeInVideo - istanteStalloMedio);
            stddev = sqrt(temp/iter->NumEventRebuf);
            rebufFreq = iter->NumEventRebuf/iter->dur;
        }

        summary << iter->endDownloadTime << ',' << iter->clientAddr.str() << ',' << iter->serverAddr.str() << ',' << iter->itag << ',' << iter->dur << ',' << iter->QoE1 << ',' << iter->QoE2A << ',' << iter->QoE2B << ',' << iter->QoE2C << ',' << iter->QoE3A << ',' << iter->QoE3B << ',' << iter->QoE3C << ',' << iter->QoEln << ',' << iter->NumEventRebuf << ',' << stalloTot << ',' << istanteStalloMedio << ',' << stddev << ',' << rebufFreq << endl;
    }
    results.close();
    summary.close();
}
