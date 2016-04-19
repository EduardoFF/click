// Unicast-version of RNP for linux
AddressInfo(me0	$ADHOCIP $WLANMAC);

/*****************************************************************************************
*  HERE, DEFINE USER ELEMENTS
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
		-> ARPResponder($myaddr, $myaddr_ethernet)
//		-> SetTimestamp
//		-> Print("ARP REPLY n0",TIMESTAMP true)
		-> [0]output;
		
	// this is a response from others - pass it to ARP querier
	arpclass[1] 
		-> [2]output
	
	// this is not an ARP packet - pass it to normal IP packets processing
	arpclass[2] 
		-> MarkMACHeader
		-> CheckIPHeader2(OFFSET 14)
		-> MarkIPHeader(14)
		//-> ToDump("ipdata",PER_NODE true)
		-> [1]output;
}



/// packets going out from click node to the network
/// we get IP packets, and encapsulate in broadcast ethernet
elementclass OutputEth0 {
  input[0]
    -> q :: Queue(100)
    /// write headers  (extended ip_header -> 56 bytes)
    /// ethernet 14 + 56 (IP) + 8 (UDP) + 24 first bytes of data 
//    -> ToDump("out_eth0.dump", ENCAP ETHER, SNAPLEN 102)
    -> ToDevice($WLANINTERFACE, METHOD LINUX);
}


// packets coming from the network, 
// and arriving to click node (before going up to upper layers)
// also: gets and handles TX feedbacks sent from the device driver...
//	output[0] Ethernet to this node (or broadcast)
//      output[1] Ethernet not for this node
//	output[2] TX feedback packets
//      set SNIFFER False to prevent linux from handling broadcasts
elementclass InputEth0 {
	$myaddr_ethernet |
	FromDevice($WLANINTERFACE, PROMISC true, SNIFFER false, METHOD LINUX)
//		//-> Print("From device $WLANINTERFACE",MAXLENGTH 43)
//		-> ToDump("input_eth0.dump", ENCAP ETHER, SNAPLEN 102)
		-> ftx::FilterTX;
	ftx[0]
		-> hostfilter :: HostEtherFilter($myaddr_ethernet, DROP_OWN false, DROP_OTHER true);
//		-> hostfilter :: HostEtherFilter(64:05:04:03:02:01, DROP_OWN false, DROP_OTHER true);
	hostfilter[0]
//		-> ToDump("eth0_in_0.dump", ENCAP ETHER, SNAPLEN 102)
//		-> Print("pkt4me")
		-> [0]output;
	hostfilter[1]
//		-> ToDump("eth0_in_1.dump", ENCAP ETHER, SNAPLEN 102)
//		-> Print("not for me")
		-> [1]output;
	ftx[1]
		-> ExtraDecap	
		//-> Print("TX FEEDBACK device $WLANINTERFACE")
		-> [2]output;
}



//
//get IP data from system and forward to router and vice versa
//
elementclass System {
	tohost :: ToHost(fake0);
	FromHost(fake0, me0, ETHER 2:2:2:2:2:2)
		-> fromhost_cl :: Classifier(12/0806, 12/0800);
  	fromhost_cl[0] -> ARPResponder(0.0.0.0/0 1-1-1-1-1-1) -> tohost;
  	fromhost_cl[1]
		// arp requests or replies go to output 0
		// IP packets go to output 1
//		-> ToDump("fromsystem.dump", ENCAP ETHER)
//		-> Print("FromHostfake0 n0")
		-> Classifier(12/0800)
		-> multicast_cl :: IPClassifier(dst 224.0.0.0/4, -);
	multicast_cl[0]
//		-> Print("From multicast_cl0")
		-> Discard;
	multicast_cl[1]
//		-> ToDump("fromsystem_ip.dump", ENCAP ETHER)
   		-> Strip(14)
//		-> ToDump("my_ip.dump", ENCAP IP, SNAPLEN 52)
		-> CheckIPHeader
		-> MarkIPHeader
		-> [0]output;
		
	input[0]
//		-> Print("Packet to local host, going further")
		-> CheckIPHeader2
//		-> ToDump("systemout_ipok.dump", ENCAP IP)
//		-> IPPrint()
		-> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) // ensure ethernet for kernel
//		-> ToDump("systemout_ethernetpacked.dump", ENCAP ETHER)
		-> MarkIPHeader(14)
//		-> ToDump("systemout_ethernetpacked_ipmarked.dump", ENCAP ETHER)
		-> CheckIPHeader(14)
//		-> ToDump("systemout_tohost.dump", ENCAP ETHER)
		-> tohost;
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






/*****************************************************************************************
*
*  HERE, CREATE ALL REQUIRED ELEMENTS
*
******************************************************************************************/

randomseed::RandomSeed(111);
inputEthSim :: InputEth0(me0);
system :: System;
output :: OutputEth0;
lookup :: RNPLookUpRoute(me0);
sink :: RNPSink(me0); // captures packets when node is sink
//ctrl :: ControlSocket(unix,/tmp/clicksocket);
//chat :: ChatterSocket("TCP",12345);
ipopt :: IPGWOptions(me0);
oflowmon :: FlowMonitor(ADDR me0, ETHERADDR me0, LCMCHAN oflow, DO_IP true, DO_ETH false);
iflowmon :: FlowMonitor(ADDR me0, ETHERADDR me0, LCMCHAN iflow, DO_IP false, DO_ETH true);
sinkflowmon :: FlowMonitor(ADDR me0, ETHERADDR me0, LCMCHAN sinkflow, DO_IP true, DO_ETH false);
mineiflowmon :: FlowMonitor(ADDR me0, ETHERADDR me0, LCMCHAN mineiflow, DO_IP false, DO_ETH true);
appflowmon :: FlowMonitor(me0, me0, LCMCHAN appflow, DO_IP true, DO_ETH false);
arpclass :: ClassifyARP(me0,me0);
arpquerier :: ARPQuerier(me0,POLL_TIMEOUT 0);	// We do not want polling here...

/*****************************************************************************************
*
*
*  HERE, DEFINE THE CLICK GRAPH STRUCTURE
*
*
******************************************************************************************/


/// ethernet packets from network, destined to this node
inputEthSim[0]
	/// mark my packets
	-> Paint(1)
	-> arpclass;
	
//Idle -> iflowmon -> filterlocalhost;


/// ARP replies
arpclass[0] 
	-> output;

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
	//-> ToDump("arpoutput.dump",PER_NODE true)
	-> oflowmon
	-> output;

// ARP Queries
arpquerier[1]
	//-> ToDump("arpoutput.dump",PER_NODE true)
	-> output;

/// ethernet packets from network not for this node
/// discard
inputEthSim[1]
//	-> Print("Not mine")
//	-> ToDump("unicast_ignored.dump", ENCAP ETHER)
	-> Discard;

/// TX feedbacks are not handled at the moment
inputEthSim[2]	
//	-> CheckIPHeader2(OFFSET 17)
//	-> [0]arpquerier;
	-> Discard;



system[0] 
	-> Paint(2)
//	-> ToDump("beforelook_mine.dump", ENCAP IP)
	-> TcpOrUdp
	-> appflowmon		
	-> lookup;

lookup[0] // known destination, dest IP annotation set
	// just in case, strip network header
	-> StripToNetworkHeader
	-> SetIPChecksum
//	-> SetUDPChecksum
//	-> ToDump("lookedup_to_ipout.dump",ENCAP IP)
//	-> Print("Lookup 0",TIMESTAMP true)
	-> DecIPTTL
//	-> ToDump("decipttl.dump",ENCAP IP)
	-> ipopt;

/// packets going out
ipopt[0]
	-> arpquerier;

ipopt[1]
//	-> ToDump("ipgwopt_ERROR.dump",ENCAP IP)
	-> Discard;

lookup[1] // unknown destination, routediscovery
	//-> discoveryqueue;
//	-> ToDump("lookfailed.dump",ENCAP IP, SNAPLEN 52)
//	-> Print("Lookup 1",TIMESTAMP true)
	-> Discard;

lookup[2] // im sink, receive
	-> StripToNetworkHeader
//	-> StoreIPAddress(me0,dst)
//	-> ToDump("before_sink.dump",ENCAP IP)
	-> sink;

lookup[3] // discarded packet
//	-> ToDump("discarded.dump", ENCAP IP, SNAPLEN 52)
	-> Discard;


/// succesful sinks
sink[0]
//	-> SetIPChecksum
//	-> SetUDPChecksum
//	-> ToDump("sinked.dump",ENCAP IP, SNAPLEN 52)
//	-> Print("Sinked",TIMESTAMP true)
//	-> Discard;
	-> sinkflowmon
	-> system;

/// unsuccesful sink
sink[1]
//	-> ToDump("sinked_failed.dump", ENCAP IP)
	-> Discard;
	
