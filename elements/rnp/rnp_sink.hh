#ifndef RNPSINK_HH
#define RNPSINK_HH
#include <click/element.hh>


CLICK_DECLS



class RNPSink : public Element 
{
  public:

    RNPSink();
    ~RNPSink();

    const char *class_name() const	{ return "RNPSink"; }
    const char *port_count() const	{ return "1/2"; }
    const char *processing() const	{ return PUSH; }
    RNPSink *clone() const	{ return new RNPSink; }

    Packet * removeRROPT( Packet *packet);
    int configure(Vector<String> &, ErrorHandler *);

    virtual void push (int, Packet *);

    IPAddress m_myIP;
    uint32_t m_sinkReceivedPackets;
};

CLICK_ENDDECLS
#endif

