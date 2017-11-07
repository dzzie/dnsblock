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

displayBlocked = False
packet_filter = "outbound and udp.DstPort == 53"
wu = winutil.WinUtilMixin()  # from fakenet-ng
hLog = 0

# loaded from config.txt in script home dir
blackDomains = []     
whiteDomains = []
whiteProcs = [] 
blackProcs = [] 

def blockDomain(domain):
    for d in blackDomains:
        if fnmatch.fnmatch(domain, d): return True
    return False

def isWhiteDomain(domain):
    for d in whiteDomains:
        if fnmatch.fnmatch(domain, d): return True
    return False

def isWhiteProc(processName):
    for d in whiteProcs:
        if fnmatch.fnmatch(processName, d): return True
    return False    

def isBlackProc(processName):
    for d in blackProcs:
        if fnmatch.fnmatch(processName, d): return True
    return False 

def isAdmin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
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

       err = None
       WINDIVERT_DIRECTION_INBOUND = 1
       pid = proc = "???"

       try:
            pid =  wu.get_pid_port_udp(packet.src_port)
            if pid: proc = wu.get_process_image_filename(pid)
            else: pid = "???"
       except:
            pid = proc = "???"

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

                status = "OK"
                blocked = False
                if isWhiteProc(proc):
                    status = "OK (process whitelist)"
                elif isBlackProc(proc):
                    blocked = True
                    status = "BLOCKED (process blacklist)"
                elif isWhiteDomain(qname):
                    status = "OK (domain whitelist)"
                elif blockDomain(qname):
                    blocked = True
                    status = "BLOCKED"

                if not blocked:
                    w.send(packet)         # we can let it pass
                else:
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
           msg = err + "\r\n-" * 50 + str(packet) + "\r\n\r\nPayload:\r\n" + hexdump(packet.payload) + "\r\n-" * 50 + "\r\n"
           hLog.write(msg)
           print msg
       else:
           t = time.strftime("%m/%d/%Y %I:%M %p", time.localtime(time.time()))
           msg = "%20s | %5s | %6s | %15s | %30s | %s" % (t, str(pid), str(qtype), str(proc), str(qname), status) # str() wrappers handle possibility of None
           hLog.write(msg+"\r\n")
           if status.find("OK") >= 0 or (status.find("OK") == -1 and displayBlocked == True):
                print msg
               


# ------------------ [ script start ] -----------------

if not isAdmin():
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

if "/show" in sys.argv: displayBlocked = True
if "/hide" in sys.argv: displayBlocked = False

# load config
with open('config.txt') as f:
    tmpRef = whiteProcs
    for line in f:
        line = line.strip()
        if len(line) > 0:
            if line[0] == "#":
                if line.find("# BLACK LISTED #") >= 0:         tmpRef = blackProcs
                if line.find("# WHITELISTED DOMAINS #") >= 0:   tmpRef = whiteDomains
                if line.find("# BLOCKED DOMAINS #") >= 0:      tmpRef = blackDomains
            else:
                cmt = line.find("#")
                if cmt >= 0: line = line[:cmt-1].strip()
                if len(line) > 0: tmpRef.append(line)

print "%d/%d domains, %d/%d processes, show blocked = %s - press ctrl+break to exit" % (len(whiteDomains), len(blackDomains), len(whiteProcs), len(blackProcs), displayBlocked)
print "%20s | %5s | %6s | %15s | %30s | %s" % ("Time","Pid","Type","Process","Domain","Status")

hLog = open("log.txt","a+",0)

# main packet handler loop
with pydivert.WinDivert(packet_filter) as w:
    try:
        for packet in w:
           HandleDNS(w,packet)
    except Exception as e:
        msg = "Caught error in HandleDNS: " + str(e)  # once in a while getting an access denied error in windivert..
        hLog.write(msg+"\r\n")
        print msg
       
      

       


