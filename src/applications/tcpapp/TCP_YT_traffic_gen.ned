//
// Copyright (C) 2004 Andras Varga
//
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


package inet.applications.tcpapp;

import inet.applications.ITCPApp;


//

//
simple TCP_YT_traffic_gen like ITCPApp
{
    parameters:
        string localAddress = default(""); // local address; may be left empty ("")
        int localPort; // port number to listen on
//        int videoBitrate @unit(kbps);  //Bitrate del video da scaricare
//        volatile int videoSize @unit(B);  // length of full a video stream in bytes
        double echoDelay @unit(s) = default(0s);
        string dataTransferMode @enum("bytecount","object","bytestream") = default("object");
        int BufferDimension_forTCP @unit(B) = default(2 MiB);
        int throttling_chunk @unit(B) = default(64 KiB);
        double throttling_multiplier = default(1.25);
        @display("i=block/app");
        @signal[sentPk](type=cPacket);
        @signal[rcvdPk](type=cPacket);
        @statistic[rcvdPk](title="packets received"; source=rcvdPk; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[sentPk](title="packets sent"; source=sentPk; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[endToEndDelay](title="end-to-end delay"; source="messageAge(rcvdPk)"; unit=s; record=histogram,vector; interpolationmode=none);
    gates:
        input tcpIn @labels(TCPCommand/up);
        output tcpOut @labels(TCPCommand/down);
        
        input blockManager @directIn;  //Porta per la ricezione dello stato della coda di tx da parte del TCP
}

