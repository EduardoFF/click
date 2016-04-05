#!/bin/bash


USAGE="<interface> <ip with mask> <channel> <power (dBm)>  optional: if environment variable \n\
DO_FISH equals 1, then it creates a monitor interface over <interface> \n\
example: ./ADHOC_connection_script.sh wlan2 10.42.43.14/24 3 0" 

if [ "$#" -ne "4" ];
then
    echo -e $USAGE
    exit
fi



export DO_FISH=${DO_FISH:="0"}
INTERFACE=$1
IPWITHMASK=$2
CHAN=$3
POWER=$4


function cleanup()
{
    ifconfig | grep -q $INTERFACE
    if [ $? -eq 0 ]; 
    then
	echo "bringing down ${INTERFACE}"
	ifconfig $INTERFACE down
    fi
    ip addr flush dev ${INTERFACE}
    ifconfig | grep -q fish1
    if [ $? -eq 0 ]; 
    then
	echo "bringing down fish1"
	ifconfig fish1 down
	iw dev fish1 del
    fi
}

cleanup
#trap cleanup INT


#
iwconfig ${INTERFACE} mode ad-hoc
iwconfig ${INTERFACE} channel ${CHAN}
iwconfig ${INTERFACE} essid 'ADHOC' ap 06:02:03:04:05:06



ip addr add ${IPWITHMASK} broadcast 10.42.43.255 dev ${INTERFACE}
ip link set ${INTERFACE} up
#ifconfig ${INTERFACE} up
# TX power in dBm
iwconfig ${INTERFACE} txpower ${POWER}
#
iwconfig ${INTERFACE} rts 2400
#iwconfig ${INTERFACE} rts 0
iwconfig ${INTERFACE} rate 54M
if [ "${DO_FISH}" == "1" ];
then
    echo "creating monitor interface fish1"
    iw dev ${INTERFACE} interface add fish1 type monitor flags none
    ifconfig fish1 up
fi

