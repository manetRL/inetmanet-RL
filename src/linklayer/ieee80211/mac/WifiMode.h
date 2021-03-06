#ifndef __WIFI_MODULATION_TYPE_H__
#define __WIFI_MODULATION_TYPE_H__
/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2005,2006 INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
#include "INETDefs.h"
#include "WifiPreambleType.h"
#include "ModulationType.h"

class WifiModulationType
{
    public:
        static ModulationType GetDsssRate1Mbps();
        static ModulationType GetDsssRate2Mbps();
        static ModulationType GetDsssRate5_5Mbps();
        static ModulationType GetDsssRate11Mbps();
        static ModulationType GetErpOfdmRate6Mbps();
        static ModulationType GetErpOfdmRate9Mbps();
        static ModulationType GetErpOfdmRate12Mbps();
        static ModulationType GetErpOfdmRate18Mbps();
        static ModulationType GetErpOfdmRate24Mbps();
        static ModulationType GetErpOfdmRate36Mbps();
        static ModulationType GetErpOfdmRate48Mbps();
        static ModulationType GetErpOfdmRate54Mbps();
        static ModulationType GetOfdmRate6Mbps();
        static ModulationType GetOfdmRate9Mbps();
        static ModulationType GetOfdmRate12Mbps();
        static ModulationType GetOfdmRate18Mbps();
        static ModulationType GetOfdmRate24Mbps();
        static ModulationType GetOfdmRate36Mbps();
        static ModulationType GetOfdmRate48Mbps();
        static ModulationType GetOfdmRate54Mbps();
        static ModulationType GetOfdmRate3MbpsBW10MHz();
        static ModulationType GetOfdmRate4_5MbpsBW10MHz();
        static ModulationType GetOfdmRate6MbpsBW10MHz();
        static ModulationType GetOfdmRate9MbpsBW10MHz();
        static ModulationType GetOfdmRate12MbpsBW10MHz();
        static ModulationType GetOfdmRate18MbpsBW10MHz();
        static ModulationType GetOfdmRate24MbpsBW10MHz();
        static ModulationType GetOfdmRate27MbpsBW10MHz();
        static ModulationType GetOfdmRate1_5MbpsBW5MHz();
        static ModulationType GetOfdmRate2_25MbpsBW5MHz();
        static ModulationType GetOfdmRate3MbpsBW5MHz();
        static ModulationType GetOfdmRate4_5MbpsBW5MHz();
        static ModulationType GetOfdmRate6MbpsBW5MHz();
        static ModulationType GetOfdmRate9MbpsBW5MHz();
        static ModulationType GetOfdmRate12MbpsBW5MHz();
        static ModulationType GetOfdmRate13_5MbpsBW5MHz();

        static ModulationType GetOfdmRate6_5MbpsBW20MHz();
        static ModulationType GetOfdmRate13MbpsBW20MHz();
        static ModulationType GetOfdmRate19_5MbpsBW20MHz();
        static ModulationType GetOfdmRate26MbpsBW20MHz();
        static ModulationType GetOfdmRate39MbpsBW20MHz();
        static ModulationType GetOfdmRate52MbpsBW20MHz();
        static ModulationType GetOfdmRate58_5MbpsBW20MHz();
        static ModulationType GetOfdmRate65MbpsBW20MHz();
        static ModulationType GetOfdmRate13_5MbpsBW40MHz();
        static ModulationType GetOfdmRate27MbpsBW40MHz();
        static ModulationType GetOfdmRate40_5MbpsBW40MHz();
        static ModulationType GetOfdmRate54MbpsBW40MHz();
        static ModulationType GetOfdmRate81MbpsBW40MHz();
        static ModulationType GetOfdmRate108MbpsBW40MHz();
        static ModulationType GetOfdmRate121_5MbpsBW40MHz();
        static ModulationType GetOfdmRate135MbpsBW40MHz();

        //Rates for clause 20 with short guard interval
        static ModulationType GetOfdmRate7_2MbpsBW20MHz();
        static ModulationType GetOfdmRate14_4MbpsBW20MHz();
        static ModulationType GetOfdmRate21_7MbpsBW20MHz();
        static ModulationType GetOfdmRate28_9MbpsBW20MHz();
        static ModulationType GetOfdmRate43_3MbpsBW20MHz();
        static ModulationType GetOfdmRate57_8MbpsBW20MHz();
        static ModulationType GetOfdmRate65MbpsBW20MHzShGi();
        static ModulationType GetOfdmRate72_2MbpsBW20MHz();
        static ModulationType GetOfdmRate15MbpsBW40MHz();
        static ModulationType GetOfdmRate30MbpsBW40MHz();
        static ModulationType GetOfdmRate45MbpsBW40MHz();
        static ModulationType GetOfdmRate60MbpsBW40MHz();
        static ModulationType GetOfdmRate90MbpsBW40MHz();
        static ModulationType GetOfdmRate120MbpsBW40MHz();
        static ModulationType GetOfdmRate135MbpsBW40MHzShGi();
        static ModulationType GetOfdmRate150MbpsBW40MHz();

        static ModulationType getModulationType(char mode, double bitrate);

        static void setHTFrequency11n5Gh(ModulationType &t)
        {
            if (t.getModulationClass() == MOD_CLASS_HT)
                t.setFrequency(5000);
        }

        static void setHTFrequency11n2_4Gh(ModulationType &t)
        {
            if (t.getModulationClass() == MOD_CLASS_HT)
                t.setFrequency(2400);
        }

        static simtime_t getPlcpHeaderDuration(ModulationType payloadMode, WifiPreamble preamble);
        static simtime_t getPlcpPreambleDuration(ModulationType payloadMode, WifiPreamble preamble);
        static simtime_t getPreambleAndHeader(ModulationType payloadMode, WifiPreamble preamble);
        static simtime_t getPayloadDuration(uint64_t size, ModulationType payloadMode, const uint32_t & nss = 1, bool = false);
        static simtime_t calculateTxDuration(uint64_t size, ModulationType payloadMode, WifiPreamble preamble,const uint32_t & nss = 1, const uint32_t & ness = 0, bool isStbc = false);
        static simtime_t getSlotDuration(ModulationType payloadMode, WifiPreamble preamble);
        static simtime_t getSifsTime(ModulationType payloadMode, WifiPreamble preamble);
        static simtime_t get_aPHY_RX_START_Delay(ModulationType payloadMode, WifiPreamble preamble);
        static ModulationType getPlcpHeaderMode(ModulationType payloadMode, WifiPreamble preamble);
        static ModulationType getMFPlcpHeaderMode(ModulationType payloadMode, WifiPreamble preamble);
        static simtime_t getPlcpHtTrainingSymbolDuration(ModulationType payloadMode, WifiPreamble preamble,
                const uint32_t & nss = 1, const uint32_t & ness = 0);
        static simtime_t getPlcpHtSigHeaderDuration(ModulationType payloadMode, WifiPreamble preamble);
};
#endif

