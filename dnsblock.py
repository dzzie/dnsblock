# dependancies:
#   pip install pydivert
#   pip install dnslib

# info:
#   env: python 2.7 on Win10
#   options: /show or /hide  - sets showBlocked
#   script self elevates to admin can just double click to start
#   more: http://sandsprite.com/blogs/index.php?uid=7&pid=440

# wireshark filter: not ssdp and not arp and not icmp and not icmpv6 and not igmp and not mdns

import pydivert
from dnslib import *
import fnmatch
import winutil
import ctypes, sys, os
from msvcrt import getch

showBlocked = False
packet_filter = "outbound and udp.DstPort == 53"
wu = winutil.WinUtilMixin()  # from fakenet-ng
domains = [] # loaded from blocked.txt in script home dir

def shouldBlock(domain):
    for d in domains:
        if fnmatch.fnmatch(domain, d): return True
    return False

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

def HandleDNS(w,packet):

       err = pid = proc = None
       status = "OK"
       WINDIVERT_DIRECTION_INBOUND = 1

       try:
            pid =  wu.get_pid_port_udp(packet.src_port)
            proc = wu.get_process_image_filename(pid) if pid else None
       except:
           # its possible this will fail but its not so critical that we cant do our main task...
           pass

       try:
            d = DNSRecord.parse(packet.payload)    
       except Exception, e:
            err = 'Error: Invalid DNS Request'
       else:                 
            if QR[d.header.qr] == "QUERY":
                qname = str(d.q.qname)
                if qname[-1] == '.': qname = qname[:-1]
                qtype = QTYPE[d.q.qtype]

                #print 'Received %s request for domain \'%s\'.' % (qtype, qname)

                if not shouldBlock(qname):
                    w.send(packet)         # we can let it pass
                else:
                    status = "BLOCKED"
                    localhost = "::1" if qtype == "AAAA" else "127.0.0.1"   # ipv6 or ipv4 request?
                    # Create a custom response to the query
                    try:
                        response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1, aa=1, ra=1), q=d.q)
                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](localhost)))
                        packet.direction = WINDIVERT_DIRECTION_INBOUND
                        packet.src_addr, packet.dst_addr = packet.dst_addr, packet.src_addr  # swap the src/dest addr and port for the reply..
                        packet.src_port, packet.dst_port = packet.dst_port, packet.src_port
                        packet.payload = response.pack()
                        w.send(packet,True)
                    except:
                        err = "Error creating new dns response"

       if err != None:
           print err
           print "-" * 50
           print(packet)
           print "Payload:"
           print hexdump(packet.payload)
           print "-" * 50
       else:
           if status == "BLOCKED" and showBlocked == False:
               pass
           else:
               print "%5s | %6s | %10s | %30s | %s" % (str(pid), str(qtype), str(proc), str(qname), status) # str() wrappers handle possibility of None


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ------------------ [ script start ] -----------------

if not is_admin():
    #if getattr(sys, 'gettrace', None) != None:
    #if __debug__: 
    if "/iside" in sys.argv: # cheating with vs args...
        print "debugger detected you must run IDE as admin\nPress any key to exit..."
        getch()
    else:
        print("Not running as admin trying to elevate")
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([script] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteA(None, "runas", sys.executable, params, None, 1)
    exit()

if "/show" in sys.argv: showBlocked = True
if "/hide" in sys.argv: showBlocked = False

# load the config file
with open('blocked.txt') as f:
    for line in f:
        line = line.strip()
        if len(line) > 0: domains.append(line)

print "%d domains loaded, showBlocked = %s, filter = %s - hit ctrl+break to exit" % (len(domains), showBlocked, packet_filter)
print "%5s | %6s | %10s | %30s | %s" % ("Pid","Type","Process","Domain","Status")

# main packet handler loop
with pydivert.WinDivert(packet_filter) as w:
    for packet in w:
       #print(packet)
       HandleDNS(w,packet)
       
      

       


