/***************************************************************************
 *   Copyright (C) 2013 by Nunzio Torto                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <omnetpp.h>
#include <map>

#include "IPv4ControlInfo.h"
#include "IPv4.h"
#include "ICMPMessage_m.h"
#include "Coll_ManetRouting.h"
#include "IPv4ControlInfo.h"
#include "IPv4Datagram.h"
#include "IPv4InterfaceData.h"
#include "UDPPacket_m.h"
#include "dsr-pkt_omnet.h"
#include "DSDVhello_m.h"

using namespace std;

Define_Module(Coll_ManetRouting);

void Coll_ManetRouting::initialize(){

    //Inizializzazione in MAP del numero porte UDP (assegnati da IANA, tranne batman)
    protocol[698] = "OLSR";
    protocol[254] = "Batman";
    protocol[654] = "AODVUU";
    protocol[653] = "DYMO";

    //Inizializzazione vettore per confronto sui messaggi di ControlManetRouting.
    name.push_back("AODVUU");
    name.push_back("DYMO");
    name.push_back("DYMOUM");
    name.push_back("DSRUU");

}

void Coll_ManetRouting::handleMessage(cMessage *msg) {

    if (msg->getArrivalGate()->isName("receive_fromManet"))   //Se il pacchetto arriva da un protocollo manet lo inoltra al modulo networkLayer
    {
        send(msg, "forward_toIp");
    }
    else if (dynamic_cast<UDPPacket *>(msg) != NULL)     //altrimenti il pacchetto arriva dal modulo ip e vengono fatti tutti i check per capire a quale protocollo
         {                                               //di routing manet deve essere inviato il pacchetto
             UDPPacket *pack = (UDPPacket *)msg;

             for (it = protocol.begin(); it != protocol.end(); ++it)
             {
                 if (pack->getDestinationPort() == it->first)
                 {
                     prot_name = it->second;

                     if (strcmp(pack->getName(), "OLSR_ETX pkt") == 0)      //Controllo inserito poichè OLSR_ETX ha stesso numero di porta udp di OLSR
                         prot_name = "OLSR_ETX";
                     SendToManet(msg, prot_name);
                     return;
                 }
             }
         }
    else if (dynamic_cast<ControlManetRouting *>(msg) != NULL)       //check sui pacchetti di controllo per i protocolli reattivi
         {
             ControlManetRouting *control = (ControlManetRouting *)msg;
             int size = gate("forward_toManet", 0)->getVectorSize();       //size è la grandezza del vettore dei gate verso i protocolli manetrouting
             for (int j=0; j<size; j++)      //j è l'indice dei gate e tale ciclo scorre i gate
             {
                 for (it2 = name.begin(); it2 != name.end(); ++it2)   //tale ciclo scorre il vettore di nomi con cui deve venire confrontato il nome del modulo
                 {
                     cModule *mod = gate("forward_toManet", j)->getNextGate()->getOwnerModule();  //mod è il puntatore al modulo manetrouting[i]
                     string nam = *it2;
                     if (strcmp(mod->getClassName(), nam.c_str()) == 0)     //confronto del nome del modulo puntato da mod e i nomi all'interno del vettore name
                     {                                                      //se tale condizione è vera è stata trovata una corrispondenza e i pacchetti di controllo vengono inviati sul rispettivo gate
                         ControlManetRouting *copy = control->dup();
                         send (copy, "forward_toManet", j);
                     }
                 }
             }
             delete msg;             //elimina il messagio originale
         }
    else if (dynamic_cast<DSRPkt *>(msg) != NULL)         //check sui pacchetti del protocollo DSR
         {
             prot_name = "DSRUU";
             SendToManet (msg, prot_name);
         }
    else if (dynamic_cast<DSDV_HelloMessage *>(msg) != NULL)         //check sui pacchetti del protocollo DSDV
         {
             prot_name = "DSDV_2";
             SendToManet (msg, prot_name);
         }
    else if (dynamic_cast<ICMPMessage *>(msg) != NULL)               //check sui pacchetti ICMP
         {
             ICMPMessage *mess = (ICMPMessage *)msg;
             UDPPacket *pack = check_and_cast<UDPPacket *>(mess->getEncapsulatedPacket()->getEncapsulatedPacket());

             for (it = protocol.begin(); it != protocol.end(); ++it)
             {
                  if (pack->getDestinationPort() == it->first)
                  {
                      prot_name = it->second;

                      if (strcmp(pack->getName(), "OLSR_ETX pkt") == 0)
                          prot_name = "OLSR_ETX";

                      SendToManet(msg, prot_name);
                      return;
                  }
             }
         }
}


void Coll_ManetRouting::SendToManet(cMessage *msg, string prot_name)      //Trova il gate appropriato del modulo a cui deve essere inviato il pacchetto e lo invia.
{
    int size = gate("forward_toManet", 0)->getVectorSize();

    for (int i=0; i<size; i++)
    {
        cModule *owner = gate("forward_toManet", i)->getNextGate()->getOwnerModule();
        if(strcmp(owner->getClassName(), prot_name.c_str()) == 0)
        {
            send(msg, "forward_toManet", i);
            return;
        }
        else if(strcmp(prot_name.c_str(), "DYMO") == 0 && strcmp(owner->getClassName(), "DYMOUM") == 0)
        {
            send(msg, "forward_toManet", i);
            return;
        }
    }
    delete msg;            //Viene eseguita solo quando il modulo a cui è indirizzato il pacchetto non è presente

}
