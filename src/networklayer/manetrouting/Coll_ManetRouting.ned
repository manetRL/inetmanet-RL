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

package inet.networklayer.manetrouting;

// Tale modulo serve a consegnare i messaggi dei vari protocolli di routing manet
// ai moduli appropriati.

// This module delivers the messages of the various manet routing protocols 
// to the appropriate modules. 

simple Coll_ManetRouting
{
    @display("i=block/routing");
    gates:
       input receive_fromIp;
       output forward_toIp;
       
       input receive_fromManet[];
       output forward_toManet[];          
}