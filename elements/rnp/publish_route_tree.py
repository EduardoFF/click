#!/usr/bin/env python
"""
   waypoint_scenario_bm - reproduces scenario from bonnmotion traces
   
    Copyright (C) 2014 Eduardo Feo
     
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import lcm
from rnp import route_tree_t
from rnp import route_table_t
from rnp import route_entry_t
import sys
import time
from xml.dom import minidom
from optparse import OptionParser

# the routing tree
rtree = []

def readFile(fname):
    global rtree
    f = open(fname)
    for line in f.readlines():
        s=line.split()
        if len(s)%2==0:
            print "error reading file: line has length ",len(s)
            sys.exit(1)
        node = s[0]
        succ = [s[n:n+2] for n in range(1,len(s),2)]
        succl = [(i,int(j)) for [i,j] in succ]
        rtree.append((node,succl))


def readFromCmdline(args):
    global rtree
    i=0
    while i < len(args):
        node = args[i]
        rt=list()
        i+=1
        m = int(args[i])
        i+=1
        while m:
            dest=args[i]
            i+=1
            w = int(args[i])
            i+=1
            rt.append( (dest,w) )
            m-=1
        rtree.append((node, rt))

parser = OptionParser()
parser.add_option("-f", "--file", dest="filename",
                  help="read data from  FILE", 
                  metavar="FILE")
#parser.add_option("-q", "--quiet",
                  #action="store_false", dest="verbose", default=True,
                                    #help="don't print status messages to stdout")

(options, args) = parser.parse_args()

#print options
#print args

if options.filename:
    readFile(options.filename)

if len(args):
    readFromCmdline(args)

lcm = lcm.LCM("udpm://239.255.76.67:7667?ttl=1")
msg = route_tree_t()
msg.timestamp = int(time.time() * 1000000)
#msg.timestamp = 0

print rtree
msg.n = len(rtree)
rtables=list()
for (node, rtable) in rtree:
    rt = route_table_t()
    rt.node = node
    rt.n = len(rtable)
    entries=list()
    for (nh,w) in rtable:
        re = route_entry_t()
        re.node = nh
        re.weight = w
        entries.append(re)
    rt.entries = entries
    rtables.append(rt)

msg.rtable = rtables
#print msg
lcm.publish("RNP", msg.encode())

