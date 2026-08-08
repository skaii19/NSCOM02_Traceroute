# Chua, Myka Nadine; Lim, Julienne Skye

from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8

# performs a 16 bits ones complement over packet header and payload to ensure intergity
def checksum(source_bytes):
    csum = 0
    countTo = (len(source_bytes) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = source_bytes[count+1] * 256 + source_bytes[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(source_bytes):
        csum = csum + source_bytes[len(source_bytes) - 1]
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
    
    
def receiveOnePing(mySocket, ID, timeout, destAddr):
    global rtt_min, rtt_max, rtt_sum, rtt_count

    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
           return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        #Fill in start

        # get ip header, assume no options
        ip_header = struct.unpack('!BBHHHBBH4s4s' , recPacket[:20])
        ttl = ip_header[5]
        saddr = addr[0]
        length = len(recPacket) - 20

        # ICMP header is 8 bytes
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        # check reply is from the same ID and its echo reply
        if packetID == ID and type == 0:
            timeSent = struct.unpack("d", recPacket[28:28+struct.calcsize("d")])[0]
            rtt = (timeReceived - timeSent) * 1000  # RTT in ms

            # rtt summary stats
            rtt_count += 1
            rtt_sum += rtt
            rtt_min = min(rtt_min, rtt)
            rtt_max = max(rtt_max, rtt)

            return f"{length} bytes from {saddr}: seq_num = {sequence} | ttl = {ttl} | time = {round(rtt, 3)} ms"
        
        # error message parsing
        elif type in (3,11): #host unreacchable or ttl expired
            #ICMP header is now in payload (48 - 55 bytes)
            error_icmp_header_location = recPacket[48:56]
            #unpack just like above, but we only need the packetID to check if it matches our ID
            if len(error_icmp_header_location) >= 8:
                _, _, _, original_packetID, _ = struct.unpack("bbHHh", error_icmp_header_location)
                
                if original_packetID == ID:
                    if type == 3:
                        if code == 0:   return "Network Unreachable"
                        elif code == 1: return "Host Unreachable"
                        elif code == 3: return "Port Unreachable"
                        else: return f"Destination Unreachable"
                    elif type == 11:
                        return "TTL Expired"
            
            
        
        #Fill in end
        
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."

def sendOnePing(mySocket, destAddr, ID, sequenceNumber):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, sequenceNumber)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.

    #header and data is bytes in python3
    myChecksum = checksum(header + data)


    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, sequenceNumber)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


def doOnePing(destAddr, timeout, sequenceNumber):
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details: http://sockraw.org/papers/sock_raw
    
    #Fill in start
    
    #create socket
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    
    #Fill in end

   #generates unique id
    myID = os.getpid() & 0xFFFF # Return the current process i
    
    #Fill in start
    
    #send a single ping using the socket, dst addr and ID
    sendOnePing(mySocket, destAddr, myID, sequenceNumber)
    #add delay using timeout
    #wait for reply
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    #close socket
    mySocket.close()
   
   #Fill in end
    

    return delay
    
#controller, translates hostname to IPv4 address and calls doOnePing function
def ping(host, timeout=2):
    # timeout=2 means: If two seconds go by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost

    global rtt_min, rtt_max, rtt_sum, rtt_count
    rtt_min = float('+inf')
    rtt_max = float('-inf')
    rtt_sum = 0
    rtt_count = 0
    count = 0

    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    
    # Send ping requests to a server separated by approximately one second
    try:
        while 1:
            count += 1
            delay = doOnePing(dest, timeout, count)
            print(delay)
            time.sleep(1)  # one second
    except KeyboardInterrupt:
        print("\nPing stopped by user.")
        if count != 0:
            print("Packet Summary Stats:")
            packet_loss = 100.0 - (rtt_count * 100.0 / count)
            print(f"Packets Sent: {count} | Packets Received: {rtt_count} | Packet Loss: {packet_loss:.2f}%")
            if rtt_count != 0:
                print("RTT Summary Stats:")
                print(f"RTT Min: {rtt_min:.3f} ms | RTT Max: {rtt_max:.3f} ms | RTT Average: {rtt_sum/rtt_count:.3f} ms")

#gets the hostname from the command line and calls ping function
if __name__ == "__main__":
    ping(sys.argv[1])
