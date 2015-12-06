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
        double QoEMax = default(3.25); 
        string fileNameResults = default("results.csv");   //Nome dei file dove salvare i risultati: specificare come "nome".csv
        string fileNameSummary = default("summary.csv");
        
        @signal[time](type="double");
        @signal[duration](type="double");
        @signal[NumRebuf](type="int");
        
        @signal[flowsMeasured](type="StreamingStats");
        @signal[totalQoE];
        @signal[QoE144p];
        @signal[QoE240p];
        @signal[QoE360p];
        @signal[QoE480p];
        @signal[QoE720p];
        @signal[QoE1080p];
        
        @statistic[time](title="time"; source="time",constant1; record=vector; );
        @statistic[duration](title="duration"; source="duration"; record=vector,mean; );
        @statistic[NumRebuf](title="NumRebuf"; source="NumRebuf"; record=vector,mean; );
        @statistic[FreqRebuff](title="FreqRebuff"; source="FreqRebuff"; record=vector,mean; );
        
        @statistic[flowsMeasured](title="flowsMeasured"; record=count;);
        @statistic[totalQoE](title="totalQoE"; record=mean,vector;);
        @statistic[QoE144p](title="QoE144p"; record=mean,vector;);
        @statistic[QoE240p](title="QoE240p"; record=mean,vector;);
        @statistic[QoE360p](title="QoE360p"; record=mean,vector;);
        @statistic[QoE480p](title="QoE480p"; record=mean,vector;);
        @statistic[QoE720p](title="QoE720p"; record=mean,vector;);
        @statistic[QoE1080p](title="QoE1080p"; record=mean,vector;);
        
        
    gates:
        input traffic_In @directIn;
    
}
