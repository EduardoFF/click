#ifndef FLOWMONITOR_HH
#define FLOWMONITOR_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/string.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <click/timestamp.hh>

#include <click/ipaddress.hh>
#include <click/timer.hh>
#include <map>

#include "lcm/lcm-cpp.hpp"
CLICK_DECLS



class FlowMonitor : public Element 
{
  public: 
      struct FlowEntry
      {
	/// rate estimation component
	Timestamp last_time;
	uint32_t total_byte_count;
	uint32_t total_packet_count;
	/// ema
	bool has_ema;
	uint32_t ema_packet_len_sum;
	uint32_t ema_bytes_sent_sum;
	uint32_t ema_packet_count;
	/// 
	double ema_rate;
	FlowEntry(){
	  total_byte_count=0;
	  total_packet_count=0;
	  ema_bytes_sent_sum = 0;
	}
      };
      struct IPAddressPairCompare
      {
	bool operator() (const std::pair< IPAddress, IPAddress> & lhs, 
			 const std::pair< IPAddress, IPAddress> & rhs)
	{
	  if( lhs.first.addr() == rhs.first.addr() )
	    return lhs.second.addr() < rhs.second.addr();
	  else
	  return lhs.first.addr() < rhs.first.addr();
	}
      };
      /// MAC flows
    std::map< std::pair< EtherAddress, EtherAddress > , FlowEntry> m_flows;

    /// IP flows
    std::map< std::pair< IPAddress, IPAddress > , FlowEntry, IPAddressPairCompare> m_flows_IP;

    Timer* m_estimationTimer; /// 

    bool     m_doIp;
    bool     m_doEth;
    uint32_t m_estimation_interval; /// param (in milliseconds)
    double   m_alpha;
    String m_lcmChan;
    //std::string m_lcmIflowChan;

    /// lcm channel for report
    static lcm::LCM *g_lcm;
    FlowMonitor();
    ~FlowMonitor();

    const char *class_name() const	{ return "FlowMonitor"; }
    const char *port_count() const	{ return "1/1"; }
    const char *processing() const	{ return AGNOSTIC; }
    FlowMonitor *clone() const	{ return new FlowMonitor; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    virtual Packet *simple_action(Packet *p);
    //virtual void push (int, Packet *);
    void estimationTimer(Timer* timer);
    static void handleEstimationTimer(Timer* timer, void * data);

    void reportLcm();
    IPAddress m_myIP;
    EtherAddress m_myEth;
};

CLICK_ENDDECLS
#endif

