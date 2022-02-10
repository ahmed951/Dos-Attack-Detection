
import os
import socket
import struct
from datetime import datetime, timedelta

def check_ip(ip_address):
    cmd = "sudo iptables -L INPUT -n|grep " + ip_address
    check = os.system(cmd)
    if (check == 0):
        return True
    return False
    
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)

ipMap = {}
ipTime = {}

maxRequest = 15

while True:
    packet = s.recvfrom(2048)
    ipHeaderTemp = packet[0][14:34]
    ipHeader = struct.unpack("!8sB3s4s4s",ipHeaderTemp)
    ip = socket.inet_ntoa(ipHeader[3])
    print ("ip source:", ip)
    
    if(check_ip(ip) == False):
        
        if ipMap.__contains__(ip):
            ipMap[ip] = ipMap[ip]+1
            #print ("--->",ipMap[ip])
        else :
            ipMap[ip] = 1
            ipTime[ip] = datetime.now()
            
        print ("ipMap:", ipMap)
        
        if((ipMap[ip] >= maxRequest) ) :
            
            if(ipTime[ip] < datetime.now() < ipTime[ip] + timedelta(seconds=1)):
                """and (ipMap[ip] < resetRequest)"""
                if(ipMap[ip] == maxRequest) : 
                    print("Dos Detected from ip:",ip)
                    print("BLOCK ip")
                    cmd = "sudo iptables -A INPUT -s" + ip + " -j DROP "
                    os.system(cmd)
            else:
                ipMap[ip] = 0
                ipTime[ip] = datetime.now()
