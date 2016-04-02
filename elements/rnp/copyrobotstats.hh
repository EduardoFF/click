#ifndef CLICK_COPYROBOTSTATS_HH
#define CLICK_COPYROBOTSTATS_HH
#include <click/element.hh>
#include <click/glue.hh>
CLICK_DECLS

/*
 * =c
 * 
 * CopyRobotStats(OFFSET)
 * 
 *
 *
 */

class CopyRobotStats : public Element { public:
  
  CopyRobotStats();
  ~CopyRobotStats();
  char experiment_id[16];
  char robot_state[16];
  int x,y,o;
  
  const char *class_name() const		{ return "CopyRobotStats"; }
  const char *port_count() const		{ return "1/1"; }
  const char *processing() const		{ return PUSH; }
  CopyRobotStats *clone() { return new CopyRobotStats;}

  static int robotStatsHandler(const String &data, 
			      Element *e, void *user_data, ErrorHandler *errh);
  int initialize(ErrorHandler *);
  
  int configure(Vector<String> &, ErrorHandler *);

  virtual void push(int port, Packet * p_in);

 private:
  
  unsigned int _offset;
};

CLICK_ENDDECLS
#endif
