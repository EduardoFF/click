#ifndef RNPLOOKUPROUTE_HH
#define RNPLOOKUPROUTE_HH
#include <click/element.hh>

#include <click/timer.hh>
#include <pthread.h>
#include "lcm/lcm-cpp.hpp"
//#include <unordered_map>
#include <ext/hash_map>
#define RNP_MAX_NEIGHBORS 100
#define RNP_CEIL(VARIABLE) ( (VARIABLE - (int)VARIABLE)==0 ? (int)VARIABLE : (int)VARIABLE+1 )
/*
 * =c
 * RNPLookUpRoute(RTABLE)
 * =s AntHocNet
 * =a RNPRoutingTable
 * =d
 *
 * This element determines wether we know the route to an incoming element, If we do move to output[0] otherwise to output[1] (if we are the source) or [2] (otherwise). */

CLICK_DECLS


/// General purpose hash function
inline 
size_t 
myhash(const char* s, unsigned int seed = 0)
{
    size_t hash = seed;
    while (*s)
    {
        hash = hash * 101  +  *s++;
    }
    return hash;
}

struct IPAddress_hash{
  size_t operator()(const IPAddress &ipaddr) const {
    return myhash(ipaddr.s().c_str());
  }
};

class RNPLookUpRoute : public Element 
{
public:

  RNPLookUpRoute();
  ~RNPLookUpRoute();

  const char *class_name() const	{ return "RNPLookUpRoute"; }
  const char *port_count() const	{ return "1/4"; }
  const char *processing() const	{ return PUSH; }
  RNPLookUpRoute *clone() const	{ return new RNPLookUpRoute; }

  int configure(Vector<String> &, ErrorHandler *);

  int initialize(ErrorHandler *);
  virtual void push (int, Packet *);
  static lcm::LCM *g_lcm;
  //    lcm::LCM *m_lcm;
  IPAddress m_myIP;
  /// next hop neighbors with weight
  //TODO change pair for custom struct
  ////=====================================================================
  typedef std::vector< std::pair<IPAddress, double> > HopList;
  typedef struct  RouteTableEntry
  {
    HopList nexthops;
    /// used to draw a "multinomial" from slots
    char nh_slots[RNP_MAX_NEIGHBORS];
  } RouteTableEntry;
  
  typedef __gnu_cxx::hash_map< IPAddress, RouteTableEntry, IPAddress_hash> RouteTable;
  ////=====================================================================
  RouteTable m_rTable;
  RouteTableEntry m_defaultRoute;
  /// i'm sink
  bool m_imsink;

  //  char m_nh_slots[RNP_MAX_NEIGHBORS];

  /// optional: rate estimation
  //bool m_doRateEstimation;
  //Timer* m_rateEstimationTimer; //! Outgoing rate estimation timer
  //void RateEstimationTimer(Timer* timer);
  //static void handleRateEstimationTimer(Timer* timer, void * data);

  void initRT();
  void initRouteEntry( RouteTableEntry &);
  void resetRT();
  void lockRT();
  void unlockRT();

  Packet * makeRROPT( Packet *packet);
  void setSink(bool);
  void addRTEntry(const char *ip_dst, const char *ip_nh, int w);
  IPAddress nextHop(IPAddress &);
  bool hasNextHop(IPAddress & );
  pthread_mutex_t tablelock;
  /// some statistics
  uint32_t m_sinkReceivedPackets;
private:
  //RNPRoutingTable* routingTable;
  pthread_t m_lcmthread;


public:
  //ANTHOCNETList currentConnectionsInfo;
};

CLICK_ENDDECLS
#endif
