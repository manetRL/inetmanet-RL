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

Define_Module(YT_traffic_analyzer);

void YT_traffic_analyzer::initialize()
{

}

void YT_traffic_analyzer::handleMessage(cMessage *msg)
{
    QueueBase::handleMessage(msg);
}

void YT_traffic_analyzer::endService(cPacket *packet)
{

    if (dynamic_cast<IPv4Datagram *>(packet))
        handleIncomingDatagram((IPv4Datagram *)packet);
    else
        delete packet;

}

void YT_traffic_analyzer::handleIncomingDatagram(IPv4Datagram *datagram)
{
    delete datagram;

}
