#include <stdlib.h>
#include <string.h>
#include <omnetpp.h>
#include <map>

#include "Coll_ManetRouting.h"
#include "IPv4ControlInfo.h"
#include "IPv4Datagram.h"
#include "IPv4InterfaceData.h"
#include "UDPPacket_m.h"
#include "dsr-pkt_omnet.h"

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
}


void Coll_ManetRouting::SendToManet(cMessage *msg, string prot_name)      //Trova il gate appropriato del modulo a cui deve essere inviato il pacchetto e lo invia.
{
    int i=0;
    cModule *owner = gate("forward_toManet", 0)->getNextGate()->getOwnerModule();
    while(strcmp(owner->getClassName(), prot_name.c_str()) != 0)
    {
         i++;
         owner = gate("forward_toManet", i)->getNextGate()->getOwnerModule();
    }
    send(msg, "forward_toManet", i);
}
