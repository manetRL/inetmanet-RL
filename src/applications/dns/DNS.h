#include "INETDefs.h"
#include <stdlib.h>
#include <string.h>
#include <map>
#include "IPvXAddressResolver.h"
#include "DNSRequest_m.h"


using namespace std;

class DNS : public cSimpleModule
{
    //Metodi
    public:
    DNS() {}
    virtual ~DNS() {}
    std::string findAddress(const char *url);

    //Attributi
    public:
    std::map<string, IPvXAddress> DNSTable;           //Tabella DNS degli host
    std::map<string, IPvXAddress>::iterator it_table;

    //Attributi
    protected:
    bool response_disabled;
    int ttlDNS;

    cXMLElement *DNSconfiguration;
    std::map<string, IPvXAddress> resolved;         //Tabella DNS del server in cui sono presenti tutte le risoluzioni degli indirizzi
    std::map<string, IPvXAddress>::iterator it;

    //Metodi
    protected:
    virtual void initialize(int stage);

    virtual int numInitStages() const { return 4; }

    virtual void handleMessage(cMessage *msg);

    virtual void startRequestDNS(cMessage *msg);

    virtual void sendDNSReply(cMessage *msg);

    virtual void processDNSReply(cMessage *msg);

    virtual void deleteEntryDNS(cMessage *msg);




};
