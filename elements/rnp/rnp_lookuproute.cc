/*
 * RNPLookUpRoute.{cc,hh} -- determine the route of a packet
 * Eduardo Feo
 *
 */

// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip.h>
#include "rnp_const.hh"
#include "rnp_lookuproute.hh"
//#include "route_tree_t.hpp"
#include "route_tree_t.hpp"
#include "route2_tree_t.hpp"
CLICK_DECLS

/// added output 3 to directly discard packets (DUMP)
/// output 1 is when we do not have a route
///TODO: In bidirectional mode we need to identify
///packets for the sink using some specific address
#if RNP_SIM
lcm::LCM *RNPLookUpRoute::g_lcm = NULL;
#else
lcm::LCM *RNPLookUpRoute::g_lcm = new lcm::LCM("udpm://239.255.76.67:7667?ttl=1");
#endif

class LcmHandler 
{
  public:
    RNPLookUpRoute *m_rnp;
    LcmHandler(RNPLookUpRoute *rnp):
      m_rnp(rnp)
  {}
    ~LcmHandler() {}
    void handleRouteMessage(const lcm::ReceiveBuffer* rbuf,
		       const std::string& chan, 
		       const route_tree_t* msg)
    {
      int i,j;
      bool verbose = true;
      if( verbose )
      {
	printf("Received message on channel \"%s\":\n", chan.c_str());
	printf("  timestamp   = %lld\n", (long long)msg->timestamp);
	printf("  route_tables [%d]:\n",msg->n);
	printf("hello\n");
	fflush(stdout);
      }
      /// if I got rnp message, we reset our routing table
      /// in order to avoid inconsistencies
      /// if we dont get a table, then we do not forward anything
      m_rnp->lockRT();
      m_rnp->resetRT();
      m_rnp->unlockRT();
      std::string myIP(m_rnp->m_myIP.unparse().c_str());
      for(i = 0; i < msg->n; i++)
      {
	const route_table_t &rt = msg->rtable[i];
	if(  myIP.compare(rt.node.c_str()) == 0)
	{
	  if( verbose )
	  {
	    click_chatter("FOUND MY TABLE [%s] with %d entries",
			  myIP.c_str(), rt.n);
	    //printf("Table #%d: %s\n",i,rt.node.c_str());
	    //printf("Entries (%d):",rt.n);
	    //fflush(stdout);
	  }
	  /// but first, lock that shit
	  m_rnp->lockRT();
	  m_rnp->resetRT();
	  for(j=0;j<rt.n;j++)
	  {
	    const route_entry_t &re = rt.entries[j];
	    if( verbose )
	      click_chatter(" %s %d",re.node.c_str(), re.weight);
	    if( strcmp(re.node.c_str(),"SINK") == 0)
	      {
		if( verbose )
		  click_chatter("%s I'M SINK\n",myIP.c_str());
		m_rnp->setSink(true);
	      }
	    else if( strcmp(re.node.c_str(), "DUMP") == 0)
	      {
		click_chatter("DUMP FOR NODE %s w %d", myIP.c_str(), re.weight);
		m_rnp->addRTEntry("*", "0.0.0.0", re.weight);
	      }
	    else 
	      {
		m_rnp->addRTEntry("*", re.node.c_str(), re.weight);
	      }
	  }
	  /// at the end, call init to initialize the RT
	  m_rnp->initRT();
	  /// and free willy
	  m_rnp->unlockRT();
	  //if( verbose )
	    //printf("\n");
	}
	else
	{
	  if( verbose )
	  {
	    //printf("IP NOT MATCH %s <> %s:\n",
		   //myIP.c_str(),
		   //rt.node.c_str());
	  }
	}
	if( verbose )
	{
	  click_chatter("-------------------");
	}
      }
    }

  
  void
  handleRoute2Message(const lcm::ReceiveBuffer* rbuf,
		       const std::string& chan, 
		       const route2_tree_t* msg)
    {
      int i,j;
      bool verbose = true;
      if( verbose )
      {
	printf("Received message on channel \"%s\":\n", chan.c_str());
	printf("  timestamp   = %lld\n", (long long)msg->timestamp);
	printf("  route_tables [%d]:\n",msg->n);
	printf("hello\n");
	fflush(stdout);
      }
      /// if I got rnp message, we reset our routing table
      /// in order to avoid inconsistencies
      /// if we dont get a table, then we do not forward anything
      m_rnp->lockRT();
      m_rnp->resetRT();
      m_rnp->unlockRT();
      std::string myIP(m_rnp->m_myIP.unparse().c_str());
      for(i = 0; i < msg->n; i++)
      {
	const route2_table_t &rt = msg->rtable[i];
	if(  myIP.compare(rt.node.c_str()) == 0)
	{
	  if( verbose )
	  {
	    click_chatter("FOUND MY TABLE [%s] with %d entries",
			  myIP.c_str(), rt.n);
	    //printf("Table #%d: %s\n",i,rt.node.c_str());
	    //printf("Entries (%d):",rt.n);
	    //fflush(stdout);
	  }
	  /// but first, lock that shit
	  m_rnp->lockRT();
	  m_rnp->resetRT();
	  for(j=0;j<rt.n;j++)
	  {
	    const route2_entry_t &re = rt.entries[j];
	    if( verbose )
	      click_chatter(" %s %d",re.node.c_str(), re.weight);
	    if( strcmp(re.node.c_str(),"SINK") == 0)
	      {
		if( verbose )
		  click_chatter("%s I'M SINK\n",myIP.c_str());
		m_rnp->setSink(true);
	      }
	    else if( strcmp(re.node.c_str(), "DUMP") == 0)
	      {
		click_chatter("DUMP FOR NODE %s w %d", myIP.c_str(), re.weight);
		m_rnp->addRTEntry(re.dest.c_str(), "0.0.0.0", re.weight);
	      }
	    else 
	      {
		if( strcmp(re.dest.c_str(), "SINK") == 0)
		  {
		    click_chatter("SINK dest found for node %s %d\n", myIP.c_str(), re.weight);
		    m_rnp->addRTEntry("*", re.node.c_str(), re.weight);
		  }
		else
		  m_rnp->addRTEntry(re.dest.c_str(), re.node.c_str(), re.weight);
	      }
	  }
	  /// at the end, call init to initialize the RT
	  m_rnp->initRT();
	  /// and free willy
	  m_rnp->unlockRT();
	  //if( verbose )
	    //printf("\n");
	}
	else
	{
	  if( verbose )
	  {
	    //printf("IP NOT MATCH %s <> %s:\n",
		   //myIP.c_str(),
		   //rt.node.c_str());
	  }
	}
	if( verbose )
	{
	  click_chatter("-------------------");
	}
      }
    }
};


void *
LcmListener(void *ptr)
{

  RNPLookUpRoute *rnp = (RNPLookUpRoute*)ptr;
  LcmHandler handlerObject(rnp);
  rnp->g_lcm->subscribe("RNP", &LcmHandler::handleRouteMessage, &handlerObject);
  rnp->g_lcm->subscribe("RNP2", &LcmHandler::handleRoute2Message, &handlerObject);

  click_chatter("LCM listening @ channel RNP");
  click_chatter("LCM listening @ channel RNP2");
  while(0 == rnp->g_lcm->handle());
  pthread_exit(NULL);
}

RNPLookUpRoute::RNPLookUpRoute()
	//routingTable(0)
{
	//RNPTools::ANTHOCNETListInit(&currentConnectionsInfo);
  //  m_lcm = new lcm::LCM("udpm://239.255.76.67:7667?ttl=1");

  if( g_lcm == NULL )
    {
      g_lcm =  new lcm::LCM("udpm://239.255.76.67:7667?ttl=1");
      printf("Initialized LCM\n");
    }
  ///initialize stats
  m_sinkReceivedPackets=0;
  m_imsink = false;

  if (pthread_mutex_init(&tablelock, NULL) != 0)
  {
    RNP_FATALERROR("mutex init failed");
  }
  int rc = pthread_create(&m_lcmthread, NULL, LcmListener, (void *)this);
  if (rc)
  {
    RNP_FATALERROR("ERROR; return code from pthread_create() is %d", rc);
    exit(-1);
  }
}

RNPLookUpRoute::~RNPLookUpRoute()
{
  pthread_mutex_destroy(&tablelock);
}

void
RNPLookUpRoute::setSink(bool msink)
{
  m_imsink = msink;
}
void
RNPLookUpRoute::lockRT()
{
  pthread_mutex_lock(&tablelock);
}

void
RNPLookUpRoute::addRTEntry(const char * ip_dst_addr_str, const char *ip_nh_addr_str, int w)
{
  if( strcmp(ip_dst_addr_str, "*") == 0 )
    {
      IPAddress ip_nh_addr( ip_nh_addr_str );
      m_defaultRoute.nexthops.push_back( std::make_pair(ip_nh_addr, w) );
    }
  else
    {
      IPAddress ip_dst_addr( ip_dst_addr_str );
      IPAddress ip_nh_addr( ip_nh_addr_str );
      m_rTable[ip_dst_addr].nexthops.push_back( std::make_pair(ip_nh_addr, w) );
    }
}
void
RNPLookUpRoute::unlockRT()
{
  pthread_mutex_unlock(&tablelock);
}

bool
RNPLookUpRoute::hasNextHop(IPAddress &ip_dst)
{
  if( m_rTable.find( ip_dst) != m_rTable.end() )
    return (m_rTable[ip_dst].nexthops.size() > 0);
  else
    {
      /// check for default route
      return (m_defaultRoute.nexthops.size() > 0);
    }
}

IPAddress 
RNPLookUpRoute::nextHop(IPAddress &ip_dst)
{
  /// lock the table for thread safety
  lockRT();
  if( m_rTable.find( ip_dst) != m_rTable.end() )
    {
      /// if we only have a route
      HopList &nexthops = m_rTable[ip_dst].nexthops;
      if( nexthops.size() == 1)
	{
	  unlockRT();
	  return nexthops[0].first;
	}
      if( !nexthops.size() )
	{
	  RNP_REPORT("WARNING: No next hop");
	  unlockRT();
	  return m_myIP;
	}
      uint32_t r = click_random(0, RNP_MAX_NEIGHBORS-1);
      int rix =  m_rTable[ip_dst].nh_slots[r];
      if( rix < nexthops.size())
	{
	  unlockRT();
	  return nexthops[rix].first;
	}
      else
	{
	  RNP_REPORT("WARNING: Invalid index for slot %d (%d) n_neighbors %d",
		     r, rix, nexthops.size());
	  unlockRT();
	  return m_myIP;
	}
    }
  else
    {
      /// if we only have a default route
      /// if we only have a route
      HopList &nexthops = m_defaultRoute.nexthops;
      if( nexthops.size() == 1)
	{
	  unlockRT();
	  return nexthops[0].first;
	}
      if( !nexthops.size() )
	{
	  RNP_REPORT("WARNING: No next hop");
	  unlockRT();
	  return m_myIP;
	}
      uint32_t r = click_random(0, RNP_MAX_NEIGHBORS-1);
      int rix =  m_defaultRoute.nh_slots[r];
      if( rix < nexthops.size())
	{
	  unlockRT();
	  return nexthops[rix].first;
	}
      else
	{
	  RNP_REPORT("WARNING: Invalid index for slot %d (%d) n_neighbors %d",
		     r, rix, nexthops.size());
	  unlockRT();
	  return m_myIP;
	}
    }  
  unlockRT();
}

void
RNPLookUpRoute::resetRT()
{
  m_rTable.clear();
  m_imsink = false;
  m_defaultRoute.nexthops.clear();
  for(int i=0; i<RNP_MAX_NEIGHBORS; i++)
  {
    m_defaultRoute.nh_slots[i] = 0;
  }
}

void
RNPLookUpRoute::initRouteEntry(RouteTableEntry &r_entry)
{
  if( r_entry.nexthops.size() <= 1)
    return; /// nothing to do
  /// first, sum all w
  uint32_t sumw=0;
  uint32_t i;
  for(i=0; i< r_entry.nexthops.size(); i++)
  {
    sumw += r_entry.nexthops[i].second;
  }
  //printf("sumw = %d nh size %d\n", 
	 //sumw, m_nexthops.size());
  int cnt_slot = 0;
  if( sumw == 0 )
    {
      RNP_FATALERROR("sumw == 0");
    }
  for(i=0; i< r_entry.nexthops.size(); i++)
  {
    double w = 1.0*r_entry.nexthops[i].second / sumw;
    /// round up
    w*=100;
    int ns = RNP_CEIL(w);
    //printf("ns %d\n", ns);
    while(ns--)
    {
      if( cnt_slot < RNP_MAX_NEIGHBORS )
      {
	r_entry.nh_slots[cnt_slot] = i;
	cnt_slot++;
      } else
      {
	if( i < r_entry.nexthops.size()-1)
	{
	  RNP_REPORT("WARNING: error filling slots");
	}
      }
    }
  }
}


void
RNPLookUpRoute::initRT()
{
  for( RouteTable::iterator it = m_rTable.begin(); it != m_rTable.end(); it++)
    {
      initRouteEntry(it->second);
    }
  initRouteEntry(m_defaultRoute);
}

int
RNPLookUpRoute::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
			"ADDR", cpkP+cpkM, cpIPAddress, &m_myIP,
			cpEnd);
}

int 
RNPLookUpRoute::initialize(ErrorHandler *)
{
}


Packet *
RNPLookUpRoute::makeRROPT( Packet *packet)
{
  //  printf("makeRROPT\n");
  //  fflush(stdout);
  if( !packet->has_network_header())
  {
    RNP_ERROR("WARNING: Packet does not have IP header!");
    return packet;
  }
  if( packet->ip_header_length() != sizeof(click_ip))
  {
    RNP_ERROR("WARNING: Invalid packet IP header length (%d), should be %u !", 
	       packet->ip_header_length(), sizeof(click_ip));
    return packet;
  }
  /// options length depends on how many addr we want to store
  uint8_t opt_len = RNP_OPT_LEN;

  //  click_chatter("opt_len = %d",opt_len);
  /// after may trials, let's just copy the IP header
  click_ip ip_old;
  memcpy(&ip_old, packet->ip_header(), sizeof(click_ip));

  //printf("network_header %p data %p\n", 
	 //packet->network_header(), packet->data());

  packet->pull(packet->transport_header_offset());
  packet->clear_transport_header();
  packet = packet->shift_data(opt_len);

  //printf("network_header %p data %p\n", 
	 //packet->network_header(), packet->data());

  WritablePacket *wp = packet->push(opt_len+sizeof(click_ip));
  if( wp == 0)
  {
    
    RNP_ERROR("WARNING: Uniquefy failed!");
    return packet;
  }
  //click_chatter("uniquefy succeed");
	       //printf("network_header %p data %p network_header_offset\n", 
	 //wp->network_header(), wp->data(), wp->network_header_offset());

 
  //memcpy(wp->data(), &ip_old, sizeof(click_ip));
  wp->set_network_header(wp->data(), sizeof(click_ip)+opt_len);

  //printf("network_header_offset %d transport_header_offset %d\n",
	 //wp->network_header_offset(), wp->transport_header_offset());

  click_ip *ip = reinterpret_cast<click_ip *>(wp->ip_header());
  /// update length
  /// ===
  /// measured in 32-bit words

  //printf("current hl %d\n", ip->ip_hl);
  //fflush(stdout);
  uint16_t hlen = (uint16_t) ((sizeof(click_ip) + opt_len) >> 2);
  //  printf("hlen %d\n", hlen);
  //  fflush(stdout);
  ip->ip_hl = hlen;
  //printf("ip_hl %d\n",ip->ip_hl);
  //fflush(stdout);
  /// measured in bytes
  uint16_t tlen = (uint16_t) (wp->network_length());
  ip->ip_len =htons(tlen);

  //  printf("ip_len %d\n",ip->ip_len);
  //  printf("net_header %d len %d\n", wp->network_header(), wp->network_header_length());
  //wp->set_network_header(wp->network_header(), sizeof(click_ip)+opt_len);

  //printf("network_header_length\n");
  //fflush(stdout);
  /// write the IPOPT_RR
  /// now we should have the space of options
  memset(ip+sizeof(click_ip), 0x0, opt_len);
  ((char *) ip)[sizeof(click_ip)]=IPOPT_RR;
  ((char *) ip)[sizeof(click_ip)+1]=(uint8_t) (opt_len);
  ((char *) ip)[sizeof(click_ip)+2]=4;

  return wp;
  //packet->pull(packet->network_header_offset());

  /// now let's make space
  /// striptoethernet
  //printf("transport_header_offset %d\n",
	 //packet->transport_header_offset());
  //fflush(stdout);

  //printf("transport_header %p\n",
	 //packet->transport_header());
  //printf("udp first line %02x %02x %02x %02x\n",
	 //packet->transport_header()[0],
	 //packet->transport_header()[1],
	 //packet->transport_header()[2],
	 //packet->transport_header()[3]);
  //fflush(stdout);
  //packet->pull(packet->transport_header_offset());
  //packet->clear_transport_header();
  //packet = packet->shift_data(opt_len);

  //WritablePacket *wp = packet->push(opt_len);
  //if( wp == 0)
  //{
    //fprintf(stderr, "WARNING: Uniquefy failed!\n");
    //return packet;
  //}


  //printf("DATA SHIFTED\n");
  //fflush(stdout);
  
  ///// unstripip
  //ptrdiff_t offset = wp->network_header() - wp->data();
  //printf("offset %d\n", offset);

  //printf("net_offset %d\n", wp->network_header_offset());
  //if (offset < 0)
  //{
    //printf("push offset %d\n", offset);
    //fflush(stdout);
    //wp = wp->push(-offset);   // should never create a new packet
  //}
  //wp->set_network_header_length(sizeof(click_ip)+opt_len);
  //printf("transport_header_offset AFTER SHIFT %d\n",
	 //wp->transport_header_offset());
  //fflush(stdout);

  //printf("new_network_header_length AFTER SHIFT %d\n",
	 //wp->network_header_length());
  //fflush(stdout);
  //printf("transport_header AFTER SHIFT %p\n",
	 //wp->transport_header());
  //printf("udp first line AFTER SHIFT %02x %02x %02x %02x\n",
	 //wp->transport_header()[0],
	 //wp->transport_header()[1],
	 //wp->transport_header()[2],
	 //wp->transport_header()[3]);

  //fflush(stdout);


  //WritablePacket *wp = packet->uniqueify();
  //
  /*
  click_ip *ip = reinterpret_cast<click_ip *>(wp->ip_header());
  /// update length
  /// ===
  /// measured in 32-bit words

  printf("current hl %d\n", ip->ip_hl);
  fflush(stdout);
  uint16_t hlen = (uint16_t) ((sizeof(click_ip) + opt_len) >> 2);
  printf("hlen %d\n", hlen);
  fflush(stdout);
  ip->ip_hl = hlen;
  printf("ip_hl %d\n",ip->ip_hl);
  fflush(stdout);
  /// measured in bytes
  uint16_t tlen = (uint16_t) (wp->network_length() + opt_len);
  ip->ip_len =htons(tlen);

  printf("ip_len %d\n",ip->ip_len);
  printf("net_header %d len %d\n", wp->network_header(), wp->network_header_length());
  //wp->set_network_header(wp->network_header(), sizeof(click_ip)+opt_len);

  printf("network_header_length\n");
  fflush(stdout);
  /// write the IPOPT_RR
  /// now we should have the space of options
  //memset(ip+sizeof(click_ip), 0x0, opt_len);
  //ip[sizeof(click_ip)]=0x07;



  printf("killing packet\n");
  fflush(stdout);
  //packet->kill();

  printf("packet killed\n");
  fflush(stdout);
  return wp;

  */
}

void 
RNPLookUpRoute::push (int port, Packet * packet)
{
  assert(port == 0);
  assert(packet);
  //assert(PAINT_ANNO(packet) == 1 || PAINT_ANNO(packet) == 3);

  Timestamp currentTime = Timestamp::now();

  const click_ip * ipHeader1 = packet->ip_header();
  assert(ipHeader1);

  IPAddress destAddr = IPAddress(ipHeader1->ip_dst);	// or change to the version above...
  IPAddress srcAddr = IPAddress(ipHeader1->ip_src);
  if( destAddr == srcAddr )
  {
    /// loop message - report error
    RNP_ERROR("destAddr %s == srcAddr %s\n", 
	      destAddr.unparse().c_str(), 
	      srcAddr.unparse().c_str());

  }
  //assert(destAddr != srcAddr);

  /// I just found out that unparse().c_str() shares the data buffer
  /// therefore, the two pointers below are NOT what they are supposed to be
  //const char *srcAddrStr = srcAddr.unparse().c_str();
  //const char *destAddrStr = destAddr.unparse().c_str();
  bool verbose = false;

  IPAddress nexthop;
  if( verbose )
  {
    RNP_REPORT("Got Data Packet - from %s to %s",
	    srcAddr.unparse().c_str(),
	    destAddr.unparse().c_str());
  }
  if( m_imsink )
  {
    /// update stats
    m_sinkReceivedPackets++;
    //printf("SINK[%s] received %d\n",m_myIP.s().data(),m_sinkReceivedPackets);
    RNP_REPORT("SINK received %d\n",
	   m_sinkReceivedPackets);
    nexthop = m_myIP;
    packet->set_dst_ip_anno(nexthop);
    output(2).push(packet);
    return;
  }
#if RNP_BIDIRECTIONAL
  #if !RNP_BROADCAST_MODE
  if( destAddr == m_myIP && !m_imsink )
    {
      m_sinkReceivedPackets++;
      RNP_REPORT("RNP received %d\n",
	   m_sinkReceivedPackets);
      nexthop = m_myIP;
      packet->set_dst_ip_anno(nexthop);
      output(2).push(packet);
      return;
     
    }
  #endif
#endif
  if( hasNextHop(destAddr) )
  {
    nexthop = nextHop(destAddr);
    if( verbose )
    {
      RNP_REPORT("next hop is %s\n", 
	     nexthop.unparse().c_str());
    }
    /// test if net hop address is empty (= 0.0.0.0)
    /// in such case, the packet is dropped
    if( nexthop.empty() )
      {
	output(3).push(packet);
	return;
      }
    if( srcAddr == m_myIP )
    {
      //packet = makeRROPT(packet);
      //      click_chatter("packet with rropt has iph size %u\n",
      //		    packet->ip_header_length());
    }

#if RNP_BROADCAST_MODE
    /// set the anno anyway
    packet->set_dst_ip_anno(nexthop);
    if (WritablePacket *q = packet->uniqueify()) 
    {
      memcpy(q->data() + q->ip_header_offset() + 16, &nexthop, 4);
      q->set_dst_ip_anno(nexthop);
      output(0).push(q);
      return;
    } 
    else
    {
      RNP_ERROR("can't uniquefy RNP ERROR!!!! HELP!!!");
      return;
    }
#else
    packet->set_dst_ip_anno(nexthop);
    output(0).push(packet);
    return;
#endif
    //fprintf(stderr,"Data Packet - Chosen hop: %u\n",
  } 
  else
  {
    if( verbose )
    {
      RNP_REPORT("NO NEXT HOP :(");
      fflush(stdout);
    }
  ///ignore packets
    output(1).push(packet);
  }
  // UserCodeEndRouteDataPackets

}


CLICK_ENDDECLS

EXPORT_ELEMENT(RNPLookUpRoute)
//ELEMENT_LIBS(-llcm -I/home/eduardo/Dropbox_idsia/Dropbox/click_ns3/elements/rnp/)
ELEMENT_LIBS(-llcm -lpthread)
