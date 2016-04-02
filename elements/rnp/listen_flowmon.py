import lcm
import sys
from rnp import flow_list_t, flow_entry_t

def my_handler(channel, data):
    msg = flow_list_t.decode(data)
    print("Received message on channel \"%s\"" % channel)
    print("   timestamp   = %d" % msg.timestamp)
    print("   addr    = %s" % str(msg.addr))
    print("   n    = %d" % msg.n)
    for i in range(msg.n):
        print "flow_%d: "%(i),
        print "addr: %s -> %s "%(msg.flows[i].src_addr, msg.flows[i].dst_addr),
        print "pkt_cnt %d "%(msg.flows[i].pkt_count),
        print "byte_cnt %d "%(msg.flows[i].byte_count),
        print "rate %f "%(msg.flows[i].data_rate),
        print "last_act %d "%(msg.flows[i].last_activity),
    print("")

lc = lcm.LCM()
subscription = lc.subscribe(sys.argv[1], my_handler)

try:
    while True:
        lc.handle()
except KeyboardInterrupt:
    pass

lc.unsubscribe(subscription)
