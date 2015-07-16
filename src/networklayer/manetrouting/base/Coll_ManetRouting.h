#include "INETDefs.h"
#include <stdlib.h>
#include <string.h>
#include <omnetpp.h>
#include <map>

#include "ControlManetRouting_m.h"
#include "IPv4Datagram.h"

using namespace std;

class IPv4Datagram;

class Coll_ManetRouting : public cSimpleModule
{
protected:

    std::map<unsigned short, string> protocol;
    std::vector<string> name;
    std::map<unsigned short, string>::iterator it;
    std::vector<string>::iterator it2;

  public:
    Coll_ManetRouting() {}
    virtual ~Coll_ManetRouting() {}
    std::string prot_name;

  protected:
      virtual void initialize();

      virtual void handleMessage(cMessage *msg);

      virtual void SendToManet(cMessage *msg, string prot_name);

};
