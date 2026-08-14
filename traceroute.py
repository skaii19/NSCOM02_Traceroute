from socket import *
import os
import sys
import struct
import time
import select
import requests
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(source_bytes):
# In this function we make the checksum of our packet
# hint: see icmpPing lab
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

def build_packet():
# In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
# packet to be sent was made, secondly the checksum was appended to the header and
# then finally the complete packet was sent to the destination.

# Make the header in a similar way to the ping exercise.
# Append checksum to the header.

# Don’t send the packet yet , just return the final packet in this function.

# So the function ending should look like this

# Header is type (8), code (8), checksum (16), sequence (16)
    myChecksum = 0
    myID = os.getpid() & 0xFFFF
	# Make a dummy header with a 0 checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
	# Calculate  checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
	
	# Get right checksum and put in header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff		
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum,myID, 1)
    packet = header + data
    return packet

# -- BONUS --

GEO_REQ_COUNT = 0
GEO_WINDOW_START = time.time()

def query_geo(ip):
    global GEO_REQ_COUNT, GEO_WINDOW_START
    now = time.time()

    # reset window every 60s
    if now - GEO_WINDOW_START >= 60:
        GEO_WINDOW_START = now
        GEO_REQ_COUNT = 0

    # throttle if limit reached
    if GEO_REQ_COUNT >= 45:
        sleep_for = 60 - (now - GEO_WINDOW_START) + 0.1
        time.sleep(sleep_for)
        GEO_WINDOW_START = time.time()
        GEO_REQ_COUNT = 0

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,city,regionName,country,org,message"
        resp = requests.get(url, timeout=5)
        GEO_REQ_COUNT += 1
        data = resp.json()
        if data.get("status") == "success":
            return {
                "city": data.get("city"),
                "region": data.get("regionName"),
                "country": data.get("country"),
                "org": data.get("org")
            }
        
    except Exception:
        pass
    return None 

def format_geo(geo):
    if not geo:
        return ""
    parts = []
    if geo.get("city"):
        parts.append(geo.get("city"))
    if geo.get("region"):
        parts.append(geo.get("region"))
    if geo.get("country"):
        parts.append(geo.get("country"))
    geo_str = ""
    if parts:
        geo_str += f" [{', '.join(parts)}]"
    if geo.get("org"):
        geo_str += f" {geo.get('org')}"
    return geo_str

def get_route(hostname):
    timeLeft = TIMEOUT
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)
            #Fill in start
            # Make a raw socket named mySocket
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(TIMEOUT)
            mySocket.bind(("", 0))
            #Fill in end
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                
                if whatReady[0] == []: # Timeout
                    print(f" {ttl}  * * * Request timed out.")
                    continue
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    print(f" {ttl}  * * * Request timed out.")
                    continue

            except timeout:
                print(f" {ttl}  * * * Request timed out.")
                continue

            else:
                #Fill in start
                #Fetch the icmp type from the IP packet
                types, code = recvPacket[20:22]
                #Fill in end
                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    geo = query_geo(addr[0])
                    print(f" {ttl}  rtt={(timeReceived - t)*1000:.0f} ms {addr[0]}\n{format_geo(geo)}")

                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    geo = query_geo(addr[0])
                    print(f" {ttl}  rtt={(timeReceived - t)*1000:.0f} ms {addr[0]}\n{format_geo(geo)}")
                    return False

                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    geo = query_geo(addr[0])
                    print(f" {ttl}  rtt={(timeReceived - timeSent)*1000:.0f} ms {addr[0]}\n{format_geo(geo)}")

                    return True
                    
                else:
                    print("error")

                break

            finally:
                mySocket.close()

if __name__ == "__main__":
    reached = get_route(sys.argv[1])
    if reached:
        print("Trace complete.")
    else:
        print("Trace ended: destination not reached (unreachable or max hops exceeded).")