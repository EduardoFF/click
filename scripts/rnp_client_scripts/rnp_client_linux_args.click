// Classic RNP for linux
AddressInfo(me0	${ETHIP} ${ETHMAC});
AddressInfo(me1	192.168.168.2/24 00:00:00:00:00:00);
AddressInfo(adhocnet ${ADHOCIP} ${WLANMAC});
AddressInfo(multicast 224.0.0.0/4 00:00:00:00:00:00)


///NOTES: rnp elements must be compiled with RNP_BROADCAST 0
///       and RNP_BIDIRECTIONAL 1
/// 2016-01-26: added ARP for Ethernet to avoid hardcoded me1 addresses

/*****************************************************************************************
*
*			WLAN USER ELEMENTS
*
******************************************************************************************/


/// packets going out from click node to the network
/// we get IP packets, and encapsulate in broadcast ethernet
elementclass OutputWlan1 {
  input[0]
    -> q :: Queue($QSIZE)
    /// write headers  (extended ip_header -> 56 bytes)
    /// ethernet 14 + 20 (IP) + 8 (UDP)
    -> ToDump("wlan-out.dump", ENCAP ETHER, SNAPLEN 102, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
    -> ToDevice(${WLANINTERFACE}, METHOD LINUX);
}


// packets coming from the WIRELESS network, 
// and arriving to click node (before going up to upper layers)
// also: gets and handles TX feedbacks sent from the device driver...
//	output[0] Ethernet to this node (or broadcast)
//      output[1] Ethernet not for this node
//	output[2] TX feedback packets
//      set SNIFFER False to prevent linux from handling broadcasts
elementclass InputWlan1 {
	$myaddr_ethernet |
	FromDevice(${WLANINTERFACE}, PROMISC false, SNIFFER false, METHOD LINUX)
		-> ToDump("wlan-in.dump", ENCAP ETHER, SNAPLEN 102, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
		-> ftx::FilterTX;
	ftx[0]
		-> hostfilter :: HostEtherFilter($myaddr_ethernet, DROP_OWN false, DROP_OTHER true);
	hostfilter[0]
		-> ToDump("wlan-in_0.dump", ENCAP ETHER, SNAPLEN 102, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
		-> [0]output;
	hostfilter[1]
		-> ToDump("wlan-in_1.dump", ENCAP ETHER, SNAPLEN 102, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
		-> [1]output;
	ftx[1]
		-> ExtraDecap	
		-> [2]output;
}

/*****************************************************************************************
*
*			ETH0 USER ELEMENTS
*
******************************************************************************************/



/// packets going out from click node to the network
elementclass OutputEth0 {
  input[0]
    -> q :: Queue($QSIZE)
    -> ToDump("eth-out.dump", ENCAP ETHER, SNAPLEN 102, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
    -> ToDevice(${ETHINTERFACE}, METHOD LINUX);
}

// packets coming from the network, 
// and arriving to click node (before going up to upper layers)
// also: gets and handles TX feedbacks sent from the device driver...
//	output[0] Ethernet+IP packets - to this node (or broadcast)
//      output[1] Ethernet+IP packets - not for this node
//	output[2] TX feedback packets
elementclass InputEth0 {
	$myaddr_ethernet |
	FromDevice(${ETHINTERFACE}, PROMISC false, SNIFFER true, METHOD LINUX)
		-> ToDump("eth-in.dump", ENCAP ETHER, SNAPLEN 102, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
		-> ftx::FilterTX;
	ftx[0]
		-> cl :: Classifier(12/0806, 12/0800);
  	cl[0]
		-> [0] output;
  	cl[1]
		-> hostfilter :: HostEtherFilter($myaddr_ethernet, DROP_OWN false, DROP_OTHER true);
	hostfilter[0]
		-> Classifier(12/0800)
		-> MarkMACHeader
		-> CheckIPHeader2(14)
		-> MarkIPHeader(14)
		-> ToDump("eth-in_0.dump", ENCAP ETHER, SNAPLEN 102, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)		
		-> [1]output;
	hostfilter[1]
		-> Classifier(12/0800)
		-> MarkMACHeader
		-> CheckIPHeader2(14)
		-> MarkIPHeader(14)
		-> ToDump("eth-in_1.dump", ENCAP ETHER, SNAPLEN 102, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)		
		-> [2]output;
	ftx[1]
		-> [3]output;
}



/*****************************************************************************************
*
*			GENERAL PURPOSE  ELEMENTS
*
******************************************************************************************/

/**
* Classify ARP and others
* input[0] from network
* output[0] to network (ARP responses from me)
* output[1] to IP data processor
* output[2] to ARP querier (ARP responses from others)
*/
elementclass ClassifyARP {
	$myaddr, $myaddr_ethernet |
	
	// classifier output 0: ARP requests, output 1: ARP replies, output 2: rest
	input[0] 
		-> arpclass :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	
	// output our response to the network, if we know the answer 
	arpclass[0] 
		-> ARPResponder($myaddr $myaddr_ethernet)
//		-> SetTimestamp
		-> [0]output;
		
	// this is a response from others - pass it to ARP querier
	arpclass[1] 
		-> [2]output
	
	// this is not an ARP packet - pass it to normal IP packets processing
	arpclass[2] 
		-> MarkMACHeader
		-> CheckIPHeader2(OFFSET 14)
		-> MarkIPHeader(14)
		-> [1]output;
}



elementclass TcpOrUdp {
	input
		-> proto_cl :: IPClassifier(ip proto tcp, ip proto udp,-);
	proto_cl[0]
		-> [0]output;
	proto_cl[1]
		-> [0]output;
	proto_cl[2]
		-> Discard;
}


elementclass FixIPChecksums {
      // fix the IP checksum, and any embedded checksums that
      // include data from the IP header (TCP and UDP in particular)
      input -> SetIPChecksum
	  -> ipc :: IPClassifier(tcp, udp, -)
	  -> SetTCPChecksum
	  -> output;
      ipc[1] -> SetUDPChecksum -> output;
      ipc[2] -> output
  }


/**
* Filter out data for localhost, 
* remember that if dst host we are the current hop of the packet
* we have no unicast transmissions, so we are not "expecting" packets 
* we STRIP the ethernet header
* input: ETHERNET data packets
* output[0]: IP packets destined for localhost
* output[1]: IP packets not destined for localhost (should be ignored)
*/ 
elementclass FilterLocalhost {
	$myaddr |
	input
		-> localhost :: IPClassifier(dst host $myaddr, - );
	localhost[0] 
//		-> StripToNetworkHeader
		-> [0]output;
	localhost[1] 
		-> [1]output;
}

/**
* Filter out data for local network
* input: ETHERNET data packets
* output[0]: IP packets destined for this local network
* output[1]: IP packets not destined for local network (should be ignored)
*/ 
elementclass FilterLocalnet {
	$myaddr |
	input
		-> localhost :: IPClassifier(dst net $myaddr:ipnet, - );
	localhost[0] 
//		-> StripToNetworkHeader
		-> [0]output;
	localhost[1] 
		-> [1]output;
}


//get IP data from system and forward to router and vice versa
//
elementclass System {
	tohost :: ToHost(fake0);
	FromHost(fake0, adhocnet, ETHER 2:2:2:2:2:2)
		-> fromhost_cl :: Classifier(12/0806, 12/0800);
  	fromhost_cl[0] -> ARPResponder(0.0.0.0/0 1-1-1-1-1-1) -> tohost;
  	fromhost_cl[1]
		// arp requests or replies go to output 0
		// IP packets go to output 1
		-> ToDump("system-in.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
		-> Classifier(12/0800)
		-> multicast_cl :: IPClassifier(dst 224.0.0.0/4, -);
	multicast_cl[0]
		-> ToDump("system-in_mcast_discarded.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)	
		-> Discard;
	multicast_cl[1]
		-> ToDump("system-in_ip.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
   		-> Strip(14)
		-> CheckIPHeader
		-> MarkIPHeader
		-> [0]output;
		
	input[0]
//		-> Print("Packet to local host, going further")
		-> CheckIPHeader2
		-> ToDump("system-tohost_ipok.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
		-> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) // ensure ethernet for kernel
		-> MarkIPHeader(14)
		-> CheckIPHeader(14)
		-> ToDump("system-tohost.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
		-> tohost;
}


/*****************************************************************************************
*
*  CREATE ELEMENTS
*
******************************************************************************************/

/*****   GENERAL  ******/
randomseed::RandomSeed(111);
system :: System;
//ctrl :: ControlSocket(unix,/tmp/clicksocket);
//chat :: ChatterSocket("TCP",12345);


/*****   ETH0  ******/
inputEth :: InputEth0(me0);
outputEth :: OutputEth0;
filterlocalhostEth :: FilterLocalhost(me0);
filterlocalnetEth :: FilterLocalnet(adhocnet); // only packets to local subnet passthrough
filtermulticastEth :: FilterLocalnet(multicast); // only multicast packets passthrough
//ar :: ARPResponder(me0);
arpquerierEth :: ARPQuerier(me0,POLL_TIMEOUT 0);	// We do not want polling here...
arpclassEth :: ClassifyARP(me0,me0:eth);

/*****   WLAN  ******/
inputWlan :: InputWlan1(adhocnet);
outputWlan :: OutputWlan1;
//filterlocalhostWlan :: FilterLocalhost(adhocnet);
lookup :: RNPLookUpRoute(adhocnet);
// captures packets when node is sink
sink :: RNPSink(adhocnet); 
arpclass :: ClassifyARP(adhocnet,adhocnet:eth);
arpquerier :: ARPQuerier(adhocnet,POLL_TIMEOUT 0);	// We do not want polling here...


ipopt :: IPGWOptions(adhocnet);
oflowmon :: FlowMonitor(ADDR adhocnet, ETHERADDR adhocnet, LCMCHAN oflow, DO_IP true, DO_ETH false);
iflowmon :: FlowMonitor(ADDR adhocnet, ETHERADDR adhocnet, LCMCHAN iflow, DO_IP false, DO_ETH true);
sinkflowmon :: FlowMonitor(ADDR adhocnet, ETHERADDR adhocnet, LCMCHAN sinkflow, DO_IP true, DO_ETH false);
mineiflowmon :: FlowMonitor(ADDR adhocnet, ETHERADDR adhocnet, LCMCHAN mineiflow, DO_IP false, DO_ETH true);
appflowmon :: FlowMonitor(adhocnet, adhocnet, LCMCHAN appflow, DO_IP true, DO_ETH false);



/*****************************************************************************************
*
*  CLICK GRAPH STRUCTURE
*
******************************************************************************************/


/// ARP packets
inputEth[0]
	-> ToDump("arp_eth0.dump", ENCAP ETHER, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> arpclassEth;

/// ARP replies
arpclassEth[0]
	-> ToDump("arp_replies_eth0.dump", ENCAP ETHER, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> outputEth;

/// NO ARP
arpclassEth[1]
	-> ToDump("noarp_wtf.dump", ENCAP ETHER, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> Discard;

/// ARP queries
arpclassEth[2]
	-> ToDump("arp_queries_eth0.dump", ENCAP ETHER, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> [1]arpquerierEth;

// Packets with known MAC address of the destination
arpquerierEth[0]
	-> ToDump("arp_ok_eth0.dump", ENCAP ETHER, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> outputEth;

// ARP Queries
arpquerierEth[1]
	-> ToDump("arp_querysent_eth0.dump", ENCAP ETHER, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> outputEth;


/// ethernet packets from network, destined MAC to this node
inputEth[1]
	-> CheckIPHeader2(14)
	-> filterlocalhostEth;



/// ethernet packets from network not for this node
/// this packets are unicast transmissions with different MAC
/// only captured, in theory, if we are in promiscuous mode
inputEth[2]
	-> Discard;

/// TX feedbacks are not handled at the moment
inputEth[3]	
	-> Discard;

/// IP Packets for this node, pass to system
filterlocalhostEth[0]
	-> StripToNetworkHeader
	-> system;

// check multicast first
filterlocalhostEth[1]
	-> filtermulticastEth;

/// multicast packets
filtermulticastEth[0]
	-> StripToNetworkHeader
	-> system;

/// IP packets destined to other nodes - bridged
filtermulticastEth[1]
	-> filterlocalnetEth;

// IP packets to local network
filterlocalnetEth[0]
	-> ToDump("filterlocalhost1_IGNORED.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
// only TCP/UDP traffic for the moment
	-> StripToNetworkHeader
	-> TcpOrUdp
	-> appflowmon
	-> ToDump("bridged_from_eth0.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> StoreIPAddress(adhocnet,src)
	-> FixIPChecksums	
	-> lookup;

filterlocalnetEth[1]
	-> ToDump("bridged_from_eth0_nonet.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> Discard;

/// system stuff received here is already addressed to adhocnet
/// only need to filter out tcp/udp and send to route
system[0] 
	-> Paint(2)
	-> StripToNetworkHeader
	-> TcpOrUdp
	-> appflowmon
	-> ToDump("local_to_adhoc.dump", ENCAP ETHER, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> lookup;
	


/*****************************************************************************************
*
*				RNP SCHEME
*
******************************************************************************************/


/// ethernet packets from network, destined to this node
inputWlan[0]
	/// mark my packets
	-> Paint(1)
	-> arpclass;

/// ARP replies
arpclass[0] 
	-> outputWlan;

/// NO ARP
arpclass[1]
	-> SetTimestamp
	-> Classifier(12/0800)
	-> MarkMACHeader
	-> CheckIPHeader2(14)
	-> MarkIPHeader(14)
	-> iflowmon
	-> TcpOrUdp
	-> mineiflowmon
	-> StripToNetworkHeader
	-> lookup;

arpclass[2]
	-> [1]arpquerier;

// Packets with known MAC address of the destination
arpquerier[0]
	-> oflowmon
	-> outputWlan;

// ARP Queries
arpquerier[1]
	-> outputWlan;


//Idle -> iflowmon -> filterlocalhost;

/// ethernet packets from network not for this node
/// this packets are unicast transmissions
/// which should not happen here
inputWlan[1]
	-> Discard;

/// TX feedbacks are not handled at the moment
inputWlan[2]	
	-> Discard;


lookup[0] // known destination, dest IP annotation set
	// just in case, strip network header
	-> StripToNetworkHeader
	-> ToDump("look-ok.dump",ENCAP IP, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> SetIPChecksum
	-> DecIPTTL
	-> ipopt;
ipopt[0]
	-> arpquerier;

ipopt[1]
	-> ToDump("ipgwopt-discarded.dump",ENCAP IP, ACTIVATION_LEVEL 2, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> Discard;

lookup[1] // unknown destination, routediscovery
	-> ToDump("look-failed.dump",ENCAP IP, SNAPLEN 52, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> Discard;

lookup[2] // im sink, receive
	-> StripToNetworkHeader
	-> StoreIPAddress(adhocnet,dst)
	-> ToDump("look-sink.dump",ENCAP IP, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> sink;

lookup[3] // discarded packet
	-> ToDump("look-discarded.dump", ENCAP IP, SNAPLEN 52, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> Discard;


/// succesful sinks
sink[0]
	-> ToDump("sink-ok.dump",ENCAP IP, SNAPLEN 52)
	-> sinkflowmon
	-> StoreIPAddress(me1,dst)
	-> SetIPAddress(me1)
	-> FixIPChecksums
	-> ToDump("sink-to_eth.dump",ENCAP IP, SNAPLEN 52)
	/// going to ARP of Eth first
	-> arpquerierEth;	


/// unsuccesful sink
sink[1]
	-> ToDump("sink-failed.dump", ENCAP IP, ACTIVATION_LEVEL 1, DEBUG_LEVEL $DEBUG, UNBUFFERED $UNBUF)
	-> Discard;
	
