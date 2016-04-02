#ifndef CLICK_DELAYUNQUEUE_TIMER_HH
#define CLICK_DELAYUNQUEUE_TIMER_HH
#include <click/element.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include <click/notifier.hh>
CLICK_DECLS

/*
=c

DelayUnqueueTimer(DELAY)

=s shaping

delay-inducing pull-to-push converter

=d

Pulls packets from the single input port. Delays them for at least DELAY
seconds, with microsecond precision. A packet with timestamp T will be emitted
no earlier than time (T + DELAY). On output, the packet's timestamp is set to
the delayed time.

DelayUnqueueTimer listens for upstream notification, such as that available from
Queue.

=h delay read/write

Return or set the DELAY parameter.

=a Queue, Unqueue, RatedUnqueue, BandwidthRatedUnqueue, LinkUnqueue,
DelayShaper, SetTimestamp */

class DelayUnqueueTimer : public Element { public:

    DelayUnqueueTimer();

    const char *class_name() const	{ return "DelayUnqueueTimer"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *processing() const	{ return PULL_TO_PUSH; }

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    uint32_t getNextInterval(); /// in microseconds

    static void handleTimer(Timer* timer, void * data);
    static void handleNotify(void * data, Notifier *);
    bool runTask(bool);

  private:

    Packet *_p;
  #if DELAYUNQUEUETIMER_USE_USEC
    uint32_t _delay;
  #else
    uint32_t _delay;
  #endif
    Timer *_timer;

    NotifierSignal _signal;

    void add_handlers();
};

CLICK_ENDDECLS
#endif
