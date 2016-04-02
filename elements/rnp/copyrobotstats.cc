#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include <clicknet/wifi.h>
#include <sstream>
#include "copyrobotstats.hh"
CLICK_DECLS

CopyRobotStats::CopyRobotStats()
{
}

CopyRobotStats::~CopyRobotStats()
{
}

int
CopyRobotStats::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (cp_va_kparse(conf, this, errh,
		   "OFFSET", cpkP+cpkM, cpUnsigned, &_offset,
		   cpEnd) < 0) {
    return -1;
  }
  return 0;
}

int 
CopyRobotStats::initialize(ErrorHandler *)
{
  add_write_handler("robotStatsHandler", CopyRobotStats::robotStatsHandler, 0, 0);
  sprintf(experiment_id,"not-set");
  sprintf(robot_state,"not-set");
  x=0;
  y=0;
  o=0;
  return 0;
}

void
CopyRobotStats::push(int port, Packet * p_in)
{
  assert(port == 0);
  assert(p_in);

  WritablePacket *p = p_in->uniqueify();
  if (!p) { return; }
  
  uint8_t *c = p->data();
  c+=_offset;
  
  memcpy(c, experiment_id, sizeof(char)*16);
  c+=16;
  memcpy(c, robot_state, sizeof(char)*16);
  c+=16;
  
  memcpy(c, &x, sizeof(int32_t));
  c+=sizeof(int32_t);

  memcpy(c, &y, sizeof(int32_t));
  c+=sizeof(int32_t);

  memcpy(c, &o, sizeof(int32_t));
  //  click_chatter("copied rssi %d\n", signal);
  output(0).push(p);
}

int 
CopyRobotStats::robotStatsHandler(const String &data, 
				Element *e, 
				void *user_data, 
				ErrorHandler *errh)
{
  char eid[16];
  char state[16];
  int  x,y,o;

  //  click_chatter("RobotStats handler %s\n",data.c_str());
  fflush(stdout);
  CopyRobotStats *robotstats = ((CopyRobotStats*)e);
  /// 'decode' str msg
  /// experiment_id robot_state x y o
  sscanf(data.c_str(), "%s %s %d %d %d", eid, state, &x, &y, &o);
  memcpy(robotstats->experiment_id,eid,16);
  memcpy(robotstats->robot_state,state,16);
  robotstats->x = x;
  robotstats->y = y;
  robotstats->o = o;
  

  return 0;
}



CLICK_ENDDECLS
EXPORT_ELEMENT(CopyRobotStats)

