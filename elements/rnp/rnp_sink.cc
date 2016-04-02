/*
 * RNPSink.{cc,hh} -- determine the route of a packet
 * Eduardo Feo
 *
 */

// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip.h>

#include "rnp_sink.hh"
#include "rnp_const.hh"
CLICK_DECLS


RNPSink::RNPSink()
{
  m_sinkReceivedPackets=0;
}

RNPSink::~RNPSink()
{
}

int
RNPSink::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return cp_va_kparse(conf, this, errh,
			"ADDR", cpkP+cpkM, cpIPAddress, &m_myIP,
			cpEnd);
}

#define RNP_SINK_MAKE_NEW_HEADER 1
Packet *
RNPSink::removeRROPT( Packet *packet)
{
  uint8_t opt_len = RNP_OPT_LEN;

  if( !packet->has_network_header())
  {
    fprintf(stderr, "WARNING: Packet does not have IP header!\n");
    return packet;
  }
  if( packet->ip_header_length() != (sizeof(click_ip)+opt_len))
  {
    RNP_ERROR("WARNING: Invalid packet IP header length (%d)!\n", 
	    packet->ip_header_length());
    return packet;
  }
#if RNP_SINK_MAKE_NEW_HEADER
  /// copy header f

  /// after may trials, let's just copy the IP header
  click_ip ip_orig;
  memcpy(&ip_orig, packet->ip_header(), sizeof(click_ip));

  packet->pull(packet->transport_header_offset());
  packet->clear_transport_header();
  packet->clear_network_header();
  WritablePacket *wp = packet->push(sizeof(click_ip));

  wp->set_network_header(wp->data(), sizeof(click_ip));
  memcpy(wp->data(), &ip_orig, sizeof(click_ip));

  click_ip *ip = reinterpret_cast<click_ip *>(wp->ip_header());
  /// update length
  /// ===
  /// measured in 32-bit words

  //printf("current hl %d\n", ip->ip_hl);
  //fflush(stdout);
  uint16_t hlen = (uint16_t) ((sizeof(click_ip)) >> 2);
  //printf("hlen %d\n", hlen);
  //fflush(stdout);
  ip->ip_hl = hlen;
  //printf("ip_hl %d\n",ip->ip_hl);
  //fflush(stdout);
  /// measured in bytes
  uint16_t tlen = (uint16_t) (wp->network_length());
  ip->ip_len =htons(tlen);
  //printf("ip_len %d\n",ip->ip_len);
  //fflush(stdout);


  return wp;
  //packet->pull(packet->network_header_offset());

#else
  //printf("makeRROPT\n");
  //fflush(stdout);

  //printf("network_header_len %d offset %d transport_offset %d\n",
	 //packet->network_header_length(), 
	 //packet->network_header_offset(), 
	 //packet->transport_header_offset());
  packet->pull(packet->transport_header_offset());
  packet->clear_transport_header();
  packet->clear_network_header();
  //printf("data before shift %p\n", packet->data());
  packet = packet->shift_data(-opt_len);
  //printf("data after shift %p\n", packet->data());

  WritablePacket *wp = packet->push(sizeof(click_ip));
  if( wp == 0)
  {
    fprintf(stderr, "WARNING: Uniquefy failed!\n");
    return packet;
  }
  wp->set_network_header(wp->data(), sizeof(click_ip));

  //printf("ip_len %d\n",ip->ip_len);
  //printf("net_header %d len %d\n", wp->network_header(), wp->network_header_length());
  //wp->set_network_header(wp->network_header(), sizeof(click_ip)+opt_len);
  click_ip *ip = reinterpret_cast<click_ip *>(wp->ip_header());
  /// update length
  /// ===
  /// measured in 32-bit words

  //printf("current hl %d\n", ip->ip_hl);
  //fflush(stdout);
  uint16_t hlen = (uint16_t) ((sizeof(click_ip)) >> 2);
  //printf("hlen %d\n", hlen);
  //fflush(stdout);
  ip->ip_hl = hlen;
  //printf("ip_hl %d\n",ip->ip_hl);
  //fflush(stdout);
  /// measured in bytes
  uint16_t tlen = (uint16_t) (wp->network_length());
  ip->ip_len =htons(tlen);
  //printf("ip_len %d\n",ip->ip_len);
  //fflush(stdout);


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
#endif
}

void 
RNPSink::push (int port, Packet * packet)
{
  bool verbose = false;
  assert(port == 0);
  assert(packet);
  Timestamp currentTime = Timestamp::now();

  const click_ip * ipHeader1 = packet->ip_header();
  assert(ipHeader1);

  IPAddress destAddr = IPAddress(ipHeader1->ip_dst);	// or change to the version above...
  IPAddress srcAddr = IPAddress(ipHeader1->ip_src);
  if( destAddr == srcAddr )
  {
    if( verbose)
      {
	RNP_ERROR("[%s] SINK Invalid Packet from %s to %s",
		  m_myIP.unparse().c_str(),
		  srcAddr.unparse().c_str(),
		  destAddr.unparse().c_str());
      }
    output(1).push(packet);
    return;

  }
  assert(destAddr != srcAddr);

  //const char *srcAddrStr = srcAddr.unparse().c_str();
  //const char *destAddrStr = destAddr.unparse().c_str();


  IPAddress nexthop;
  if( verbose )
  {
    click_chatter("[%s] SINK Data Packet - from %s to %s",
	    m_myIP.unparse().c_str(),
	    srcAddr.unparse().c_str(),
	    destAddr.unparse().c_str());

  }
  /// enable only if using extended IP options
  //packet = removeRROPT(packet);
  output(0).push(packet);

}


CLICK_ENDDECLS

EXPORT_ELEMENT(RNPSink)
//ELEMENT_LIBS(-llcm -I/home/eduardo/Dropbox_idsia/Dropbox/click_ns3/elements/rnp/)

