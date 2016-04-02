/*
 * delayunqueue_timer.{cc,hh} -- element pulls packets from input, delays pushing
 * the packet to output port.
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/error.hh>
#include <click/args.hh>
#include <click/glue.hh>
#include "delayunqueue_timer.hh"
#include <click/standard/scheduleinfo.hh>
CLICK_DECLS

#define DELAYUNQUEUETIMER_USE_USEC 1

DelayUnqueueTimer::DelayUnqueueTimer()
    : _p(0)
{
}

uint32_t
DelayUnqueueTimer::getNextInterval()
{
#if DELAYUNQUEUETIMER_USE_USEC
  //  if( fabs(_delay ) < 0.001 )
  // return 1;
  //uint32_t d_usec = (uint32_t) ceil(_delay*1000);
  return (click_random()%(_delay))+1;
#else
  return click_random()%(_delay)+1;
#endif
}
int
DelayUnqueueTimer::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh).read_mp("DELAY", _delay).complete();
}

int
DelayUnqueueTimer::initialize(ErrorHandler *errh)
{

  uint32_t next_int;
  _timer  = 
    new Timer(&DelayUnqueueTimer::handleTimer,this); 
  /// run handletask when timer goes off
  _timer->initialize(this);
  //  click_chatter("reschedule in %d \n", next_int);
  /// schedule after one second
  next_int = getNextInterval();
 // _timer->schedule_after_ms(next_int);

#if DELAYUNQUEUETIMER_USE_USEC
  _timer->schedule_after(Timestamp::make_usec(next_int));
#else
  _timer->schedule_after(Timestamp::make_msec(next_int));
#endif

  _signal = Notifier::upstream_empty_signal(this, 0, &DelayUnqueueTimer::handleNotify, this);
  return 0;
}

void 
DelayUnqueueTimer::handleNotify(void *data, Notifier *)
{
  DelayUnqueueTimer* ptr = (DelayUnqueueTimer*) data;
//  click_chatter("Notify from queue\n");
  ptr->runTask(true);
}


void 
DelayUnqueueTimer::handleTimer(Timer* timer, void * data)
{
  DelayUnqueueTimer* ptr = (DelayUnqueueTimer*) data;
  ptr->runTask(false);
}


void
DelayUnqueueTimer::cleanup(CleanupStage)
{
    if (_p)
	_p->kill();
}

bool
DelayUnqueueTimer::runTask(bool reschedule)
{
  bool worked = false;
  uint32_t next_int;
//  click_chatter("run_task %s\n", Timestamp::now().unparse().c_str());
  if( reschedule )
  {
    _timer->clear();
    /// schedule after 
    next_int = getNextInterval();
    //    click_chatter("reschedule in %d \n", next_int);
//    _timer->schedule_after_ms(next_int);	
#if DELAYUNQUEUETIMER_USE_USEC
  _timer->schedule_after(Timestamp::make_usec(next_int));
#else
  _timer->schedule_after(Timestamp::make_msec(next_int));
#endif
    return false;
  }


  /// read packet
  _p = input(0).pull();
  if (_p) 
  {
    output(0).push(_p);
    /// schedule after 
    next_int = getNextInterval();
//    click_chatter("running in %d msec\n", next_int);
//    _timer->schedule_after_ms(next_int);	

#if DELAYUNQUEUETIMER_USE_USEC
  _timer->schedule_after(Timestamp::make_usec(next_int));
#else
  _timer->schedule_after(Timestamp::make_msec(next_int));
#endif

    worked = true;
  } else {
//    click_chatter("no_packet\n");
    /// schedule after 
    next_int = getNextInterval();
//    click_chatter("running in %d msec\n", next_int);
#if DELAYUNQUEUETIMER_USE_USEC
  _timer->schedule_after(Timestamp::make_usec(next_int));
#else
  _timer->schedule_after(Timestamp::make_msec(next_int));
#endif


//    _timer->schedule_after_ms(next_int);	
    // no Packet available
    return false;		// without rescheduling
  }

  return worked;
}

void
DelayUnqueueTimer::add_handlers()
{
    add_data_handlers("delay", Handler::OP_READ | Handler::OP_WRITE, &_delay);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DelayUnqueueTimer)
