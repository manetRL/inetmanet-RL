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

package inet.applications.dns;

//
// TODO auto-generated type
//
simple DNS
{
    parameters:
        string DNS_Address = default(""); // Indirizzo del server DNS
        xml config_address = default(xml("<config><DNS_address URL='**' address='0.0.0.0' /></config>")); // Configurazione tra URL e relativo indirizzo IP
        bool disable_response =default(true); //disabilita il funzionamento da server. Permette unicamente di mandare e ricevere richieste DNS ma non di rispondere a tali richieste
                
    gates:
    input ipIn;
    output ipOut;
    
    input fromApp @directIn;
}
