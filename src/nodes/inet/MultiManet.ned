//
//   Copyright (C) 2013 by Nunzio Torto
//   Università degli studi L'Aquila
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

 
package inet.nodes.inet;

import inet.networklayer.IManetRouting;
import inet.networklayer.manetrouting.Coll_ManetRouting;

// Tale modulo svolge le stesse funzioni del modulo AdhocHost con l'aggiunta
// del supporto di poter utilizzare più protocolli di routing manet.

// This module has the same functions of AdhocHost but also support the use
// of multiple manet routing protocols.


module MultiManet extends WirelessHost
{
    parameters:
        @manet;
        @display("i=device/cellphone");
        wlan[*].mgmtType = default("Ieee80211MgmtAdhoc");  // use adhoc management
        IPForward = default(true);
        bool hasManet = default(false); //Le typename possono essere: "AODVUU","DYMO","DSRUU","OLSR","OLSR_ETX","Batman","DSDV_2" (E' DYMOUM poiche' e' una vecchia versione di DYMO)
                                        //E' ALTAMENTE SCONSIGLIATO INSERIRE PIU' ISTANZE DELLO STESSO PROTOCOLLO COME ANCHE OLSR E OLSR_ETX CONTEMPORANEAMENTE.
        int numManet = default(0);


    submodules:
        Coll_ManetRouting: Coll_ManetRouting if hasManet{
            @display("p=464,287");
        }
        manetrouting[numManet]: <> like IManetRouting if hasManet {
            @display("p=612,287,column,70");
        }

    connections allowunconnected:
        networkLayer.manetOut --> Coll_ManetRouting.receive_fromIp if hasManet;
        networkLayer.manetIn <-- Coll_ManetRouting.forward_toIp if hasManet;

        for i=0..numManet-1 {
            Coll_ManetRouting.forward_toManet++ --> manetrouting[i].from_ip if hasManet;
            Coll_ManetRouting.receive_fromManet++ <-- manetrouting[i].to_ip if hasManet;
        }

}
