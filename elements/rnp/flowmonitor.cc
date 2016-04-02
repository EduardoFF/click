/*
 * FlowMonitor.{cc,hh} -- measures flow's data rates
 * Eduardo Feo
 *
 */

// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip.h>

#include <click/args.hh>
#include "flowmonitor.hh"
#include "flow_list_t.hpp"
CLICK_DECLS

/// use the built-in click chatter, or directly to stderr
#ifndef USE_CHATTER_FOR_DEBUG
#define USE_CHATTER_FOR_DEBUG 1
#endif

/// to handle debug and report macros
#ifndef STR_EXPAND
#define STR_EXPAND(tok) #tok
#endif
#ifndef STR
#define STR(tok) STR_EXPAND(tok)
#endif

#define FOREACH(i,c) for(__typeof((c).begin()) i=(c).begin();i!=(c).end();++i)

#define USE_DEBUG_FLOWMON 0
#if USE_DEBUG_FLOWMON
#if USE_CHATTER_FOR_DEBUG
#define DEBUGFLOWMON(m, ...) \
{\
  click_chatter("DEBUG_FLOWMON[%s] %s " m,\
		m_myIP.unparse().c_str(), \
		Timestamp::now().unparse().c_str(), ## __VA_ARGS__);\
}
#else
#define DEBUGFLOWMON(m, ...) \
{\
  fprintf(stderr, "DEBUG_FLOWMON[%s] at %s - %s %d: ",\
	  m_myIP.unparse().c_str(), Timestamp::now().unparse().c_str(),\
	  __FILE__, __LINE__);\
  fprintf(stderr,m, ## __VA_ARGS__);\
  fflush(stderr);\
}
#endif
#else
#define DEBUGFLOWMON(m, ...) 
#endif

lcm::LCM *FlowMonitor::g_lcm = new lcm::LCM("udpm://239.255.76.67:7667?ttl=1,transmit_only=true");

FlowMonitor::FlowMonitor()
{
  m_estimation_interval = 1000;
  m_alpha = 0.8;


  m_lcmChan = "FLOWMON";
  m_doIp = false;
  m_doEth = true;
  click_chatter("FlowMon OK");

}

FlowMonitor::~FlowMonitor()
{
}


  int
FlowMonitor::configure(Vector<String> &conf, ErrorHandler *errh)
{
  click_chatter("FlowMon configure");
  IPAddress my_mask;
  if( Args(conf, this, errh)
      .read_mp("ADDR", IPPrefixArg(true),m_myIP, my_mask)
      .read_mp("ETHERADDR", EtherAddressArg(),m_myEth)
      .read_p("LCMCHAN", StringArg(), m_lcmChan)
      .read_p("DO_ETH", m_doEth)
      .read_p("DO_IP", m_doIp)
      .read_p("INTERVAL", m_estimation_interval)
      .read_p("ALPHA", m_alpha)
      .complete() < 0)
    return -1;
  click_chatter("FlowMon configure OK");
  return 0;
}

int 
FlowMonitor::initialize(ErrorHandler *)
{
  click_chatter("FlowMon init");
  /// initialize rate estimation timer
  m_estimationTimer  = 
    new Timer(&FlowMonitor::handleEstimationTimer,this); 
  /// run handletask when timer goes off
  m_estimationTimer->initialize(this);
  /// schedule after one second

  uint32_t random_jitter = click_random(1, 1000 );
  m_estimationTimer->schedule_after_msec(random_jitter);
  click_chatter("FlowMon init ok");
  DEBUGFLOWMON("Flowmon on channel $s DEBUGGING\n", m_lcmChan.c_str());
  assert( !m_doEth || !m_doIp );
}
  Packet *
FlowMonitor::simple_action (Packet * packet)
{
  assert(packet);
  Timestamp currentTime = Timestamp::now();
  /// length includes headers starting from MAC 
  /// what about PHY header?
  int32_t length = 0;
  if( packet->has_mac_header())
    {
      length = packet->mac_length();
    }
  else
    {
      if( packet->has_network_header() )
	{
	  length = packet->network_length() + sizeof(click_ether);
	}
    }
  assert(length > 0);
  Timestamp ctime = Timestamp::now();
  if( m_doEth )
  {
    const click_ether *ethHeader= packet->ether_header();
    EtherAddress eth_dst(ethHeader->ether_dhost);
    EtherAddress eth_src(ethHeader->ether_shost);
    // DEBUGFLOWMON("%s flow %s -> %s packet length %d" ,
    // 		 m_lcmChan.c_str(),
    // 		 eth_src.unparse().c_str(),
    // 		 eth_dst.unparse().c_str(),
    // 		 length);

    /// get flow entry
    FlowEntry &flow =
      m_flows[std::make_pair(eth_src, eth_dst)];
    /// globals
    flow.total_byte_count += length;
    flow.total_packet_count += 1;
    flow.last_time = ctime;
    /// this is used for the rate estimation
    flow.ema_bytes_sent_sum += length;
    flow.ema_packet_len_sum += length;
    flow.ema_packet_count += 1; 
  }
  if( m_doIp )
  {

    const click_ip * ipHeader = packet->ip_header();
    IPAddress ip_src = IPAddress(ipHeader->ip_src);
    IPAddress ip_dst = IPAddress(ipHeader->ip_dst);

    // DEBUGFLOWMON("%s flow %s -> %s packet length %d" ,
    // 		 m_lcmChan.c_str(),
    // 		 ip_src.unparse().c_str(),
    // 		 ip_dst.unparse().c_str(),
    // 		 length);

    /// get flow entry
    FlowEntry &flow =
      m_flows_IP[std::make_pair(ip_src, ip_dst)];
    /// globals
    flow.total_byte_count += length;
    flow.total_packet_count += 1;
    flow.last_time = ctime;
    /// this is used for the rate estimation
    flow.ema_bytes_sent_sum += length;
    flow.ema_packet_len_sum += length;
    flow.ema_packet_count += 1; 
  }

  return (packet);
  
  //else
  //{
    //if( m_doEth )
    //{
      //const click_ether *ethHeader= packet->ether_header();
      //EtherAddress eth_src(ethHeader->ether_shost);
      //EtherAddress eth_dst(ethHeader->ether_dhost);
      //DEBUGFLOWMON("Incoming flow: packet length %d src %s" , 
		   //length, eth_src.unparse().c_str());

      ///// get flow entry
      //FlowEntry &iflow =
	//m_iflows[eth_src];
      ///// globals
      //iflow.total_byte_count += length;
      //iflow.total_packet_count += 1;
      //iflow.last_time = ctime;
      ///// this is used for the rate estimation
      //iflow.ema_bytes_sent_sum += length;
      //iflow.ema_packet_len_sum += length;
      //iflow.ema_packet_count += 1; 
    //}
    //output(1).push(packet);
  //}
}

void 
FlowMonitor::handleEstimationTimer(Timer* timer, void * data)
{
  FlowMonitor* ptr = (FlowMonitor*) data;
  ptr->estimationTimer(timer);
}

void
FlowMonitor::reportLcm()
{
  DEBUGFLOWMON("Reporting lcm to %s  eth_flows %d ip_flows %d", 
	       m_lcmChan.c_str(), m_flows.size(), m_flows_IP.size());
  if( m_flows.size() && m_doEth )
  {
    DEBUGFLOWMON("Reporting %d Ethernet flows to %s", 
	       m_flows.size(), m_lcmChan.c_str());
    flow_list_t mymsg;
    mymsg.addr = m_myIP.unparse().c_str();
    mymsg.timestamp = Timestamp::now().msecval();;
    mymsg.n = m_flows.size();
    mymsg.flows.resize(mymsg.n);
    int ix=0;
    for(std::map< std::pair< EtherAddress, EtherAddress> , FlowEntry >::iterator it=
	m_flows.begin(); it != m_flows.end(); it++)
    {
      const std::pair< EtherAddress, EtherAddress> &addr_pair 
	= it->first;
      FlowEntry &oflow = it->second;
      flow_entry_t fentry;
      fentry.src_addr = addr_pair.first.unparse().c_str();
      fentry.dst_addr = addr_pair.second.unparse().c_str();
      fentry.pkt_count = oflow.total_packet_count;
      fentry.byte_count = oflow.total_byte_count;
      fentry.data_rate = oflow.ema_rate;
      fentry.last_activity = oflow.last_time.msecval();
      mymsg.flows[ix++]=fentry;
    }
    g_lcm->publish(m_lcmChan.c_str(), &mymsg);
    DEBUGFLOWMON("Reporting to %s", m_lcmChan.c_str());
  }

  if( m_flows_IP.size() && m_doIp )
  {
    DEBUGFLOWMON("Reporting %d ip flows to %s", 
	       m_flows_IP.size(), m_lcmChan.c_str());
    flow_list_t mymsg;
    mymsg.addr = m_myIP.unparse().c_str();
    mymsg.timestamp = Timestamp::now().msecval();
    mymsg.n = m_flows_IP.size();
    mymsg.flows.resize(mymsg.n);
    int ix=0;
    FOREACH(it, m_flows_IP)
    {
      const std::pair< IPAddress, IPAddress> &addr_pair 
	= it->first;
      DEBUGFLOWMON("attaching %s -> %s", 
		   addr_pair.first.unparse().c_str(),
		   addr_pair.second.unparse().c_str());
      FlowEntry &flow = it->second;
      flow_entry_t fentry;
      fentry.src_addr = std::string(addr_pair.first.unparse().c_str());
      fentry.dst_addr = std::string(addr_pair.second.unparse().c_str());
      fentry.pkt_count = flow.total_packet_count;
      fentry.byte_count = flow.total_byte_count;
      fentry.data_rate = flow.ema_rate;
      fentry.last_activity = flow.last_time.msecval();
      mymsg.flows[ix++]=fentry;
    }
    g_lcm->publish(m_lcmChan.c_str(), &mymsg);
    DEBUGFLOWMON("Reporting %d IP flows to %s", 
		 mymsg.n, m_lcmChan.c_str());
  }

}
///Eduardo's Implemention for RateEstimationTimer
void 
FlowMonitor::estimationTimer(Timer* timer)
{
  DEBUGFLOWMON("EstimationTimer enter\n");
  double factor = 1000.0 / m_estimation_interval;   
  Timestamp ctime = Timestamp::now();

  if( m_doEth )
  {
    for(std::map< std::pair< EtherAddress, EtherAddress> , FlowEntry >::iterator it=
	m_flows.begin(); it != m_flows.end(); it++)
    {

      const std::pair< EtherAddress, EtherAddress>  &addr_pair = it->first;
      FlowEntry &oflow = it->second;
      double current_rate = factor * oflow.ema_bytes_sent_sum;   
      DEBUGFLOWMON("current stationary rate is %f\n", 
		   current_rate);
      double old_rate = oflow.ema_rate;
      if (oflow.has_ema == 0)
      {
	oflow.ema_rate = current_rate;
	oflow.has_ema = 1;
      }
      else
      {
	oflow.ema_rate = 
	  (1.0 - m_alpha) * oflow.ema_rate
	  + (1.0*(m_alpha)*current_rate);
      }
      DEBUGFLOWMON("Estimator: [%s -> %s] byte_count %d \
		   previous_estimated_rate %f \
		   new rate %f", 
		   addr_pair.first.unparse().c_str(),
		   addr_pair.second.unparse().c_str(),
		   oflow.ema_bytes_sent_sum, 
		   old_rate,
		   oflow.ema_rate);
      /// clean records
      //TODO Estimate packet lengths and intervals
      oflow.ema_bytes_sent_sum = 0;
    }
  
  }
  if( m_doIp )
  {
    for(std::map< std::pair< IPAddress, IPAddress> , FlowEntry >::iterator it=
	m_flows_IP.begin(); it != m_flows_IP.end(); it++)
    {

      const std::pair< IPAddress, IPAddress>  &addr_pair = it->first;
      FlowEntry &flow = it->second;
      double current_rate = factor * flow.ema_bytes_sent_sum;   
      DEBUGFLOWMON("current stationary rate is %f\n", 
		   current_rate);
      double old_rate = flow.ema_rate;
      if (flow.has_ema == 0)
      {
	flow.ema_rate = current_rate;
	flow.has_ema = 1;
      }
      else
      {
	flow.ema_rate = 
	  (1.0 - m_alpha) * flow.ema_rate
	  + (1.0*(m_alpha)*current_rate);
      }
      DEBUGFLOWMON("Estimator: [%s -> %s] byte_count %d \
		   previous_estimated_rate %f \
		   new rate %f", 
		   addr_pair.first.unparse().c_str(),
		   addr_pair.second.unparse().c_str(),
		   flow.ema_bytes_sent_sum, 
		   old_rate,
		   flow.ema_rate);
      /// clean records
      //TODO Estimate packet lengths and intervals
      flow.ema_bytes_sent_sum = 0;
    }
  }
  reportLcm();
  
  timer->reschedule_after_msec(m_estimation_interval);	 
}



CLICK_ENDDECLS

EXPORT_ELEMENT(FlowMonitor)
ELEMENT_LIBS(-llcm)
  //ELEMENT_LIBS(-llcm -I/home/eduardo/Dropbox_idsia/Dropbox/click_ns3/elements/rnp/)

