#!/usr/bin/python
import sys
import lcm as lcmengine
import time


from rnp import route_tree_t
from rnp import route_table_t
from rnp import route_entry_t


subscription = []




def msghandler(channel, data):
    msg = route_tree_t.decode(data)
    verbose=True
    if verbose:
        print("Received message on channel \"%s\"" % channel)
        print("number of route-tables: %d" % msg.n)
    tstamp = msg.timestamp
    print tstamp
    for rt in msg.rtable:
        src_ip=rt.node
        for re in rt.entries:
            dst_ip = re.node
            print "route ",src_ip, dst_ip
    
def init_lcm():
    global lcm, subscription, lcm_logger
    
    lcm = lcmengine.LCM("udpm://239.255.76.67:7667?ttl=1")
    subscription.append(lcm.subscribe("RNP", msghandler))

def listen():
    try:
        while True:
            lcm.handle_timeout(1000)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    init_lcm()
    listen()
    print "I'm done, closing LCM connection"

    for s in subscription:
        lcm.unsubscribe(s)
