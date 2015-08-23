#include "INETDefs.h"
#include <stdlib.h>
#include <string.h>
#include "IPvXAddressResolver.h"


class FrontendServer : public cSimpleModule
{
    public:
    FrontendServer() {}
    virtual ~FrontendServer() {}

    protected:

    virtual void initialize(int stage);

    virtual int numInitStages() const { return 1; }

    virtual void handleMessage(cMessage *msg);

    virtual void sendRequestPage(cMessage *msg);

    virtual void sendReplyPage(cMessage *msg);

    virtual void processReplyPage(cMessage *msg);


};
