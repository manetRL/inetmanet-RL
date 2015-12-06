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

package inet.applications.tcpapp;


simple FrontendServer
{
    parameters:
        int replyLength @unit(B) = default(200B);  //PER ORA E CONSENTITA SOLO QUESTA DIMENSIONE. VEDERE SE MODIFICARE
        
    gates:
        input ipIn;
        output ipOut;
        
        input fromApp @directIn;
}
