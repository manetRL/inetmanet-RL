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

package inet.linklayer.YT_traffic_analyzer;

//
// TODO auto-generated type
//
simple YT_traffic_analyzer
{
    parameters:
        int numAckToJump = default(0);
        double DataNotFound @unit(s) = default(15s);  //Secondi dopo i quali, non avendo trovato i metatag del video, vengono eliminate le statistiche
        int MaxStreamCaptured = default(10);     //Numero massimo di flussi contemporanei di cui è possibile raccogliere statistiche.
        volatile double timeOff @unit(s) = default(0s);  //Tempo in cui l'algoritmo rimane spento e non cattura NULLA
    gates:
        input traffic_In @directIn;
    
}
