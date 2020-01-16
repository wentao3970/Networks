from binascii import hexlify
import dpkt
import sys
import struct
import datetime
import time
import math

def bytes_to_int (input_bytes) :
    '''Conversion from bytes object to int'''
    isinstance(input_bytes, bytes) or exit (99)
    if (len(input_bytes) == 0):
        return 0

    #why I need the first to be less than 0x80???
    #I delete this conditional statement below
    #(input_bytes[0] < 0x80) or exit (98)

    shift = i1 = 0
    for p in range(1, len(input_bytes)+1):
        i1 += (input_bytes[-p] << shift)
        shift = shift + 8
    return i1

def bytes_to_int1(b):
    i = bytes_to_int(b)
    return int(hex(i), 16)

def get_sourceP(tcp_packet):
    '''Input a tcp packet return the soure port hexadecimal bytes value'''
    bytes_t = bytes(tcp_packet)
    sourceP = bytes_t[0:2]
    int_value = bytes_to_int1(sourceP)
    return int_value

def get_destP(tcp_packet):
    bytes_t = bytes(tcp_packet)
    sourceP = bytes_t[2:4]
    int_value = bytes_to_int1(sourceP)
    return int_value

def get_seq(tcp_packet):
    bytes_t = bytes(tcp_packet)
    sourceP = bytes_t[4:8]
    int_value = bytes_to_int1(sourceP)
    return int_value

def get_ack(tcp_packet):
    bytes_t = bytes(tcp_packet)
    sourceP = bytes_t[8:12]
    int_value = bytes_to_int1(sourceP)
    return int_value

def get_win(tcp_packet):
    bytes_t = bytes(tcp_packet)
    sourceP = bytes_t[14:16]
    int_value = bytes_to_int1(sourceP)
    return int_value

def get_data_length(tcp_packet):
    bytes_t = bytes(tcp_packet.data)
    length = len(bytes_t)
    return length

def get_first2_packet_header_info(trans_send_list, trans_receive_list):
    srcPort_list = []
    destPort_list = []
    seqList = []
    ackList = []
    winList = []
    i = 0
    while i < 2:
        srcPort_list.append(get_sourceP(trans_send_list[i][1]))
        srcPort_list.append(get_sourceP(trans_receive_list[i][1]))
        destPort_list.append(get_destP(trans_send_list[i][1]))
        destPort_list.append(get_destP(trans_receive_list[i][1]))
        seqList.append(get_seq(trans_send_list[i][1]))
        seqList.append(get_seq(trans_receive_list[i][1]))
        ackList.append(get_ack(trans_send_list[i][1]))
        ackList.append(get_ack(trans_receive_list[i][1]))
        ackList.append(get_ack(trans_send_list[i][1]))
        ackList.append(get_ack(trans_receive_list[i][1]))
        i += 1
    j = 0
    while j < 4:
        print('-----------------------')
        print('Source Port:', srcPort_list[j])
        print('Destination Port:', destPort_list[j])
        print('Seq Number:', seqList[j])
        print('Ack Number:', ackList[j])
        print('Window Size:', ackList[j])
        j += 1

def get_sec(time_str):
    """Get Seconds from time."""
    h, m, s = time_str.split(':')
    return float(h) * 3600 + float(m) * 60 + float(s)



if __name__ == '__main__':
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    bufList = []

    tcp_count_sender = 0
    for ts, buf in pcap:
        pair = []
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        pair.append(ts)
        pair.append(tcp)
        bufList.append(pair)
        #print(bufList)

    #Count the number of TCP packets initiated from sender
    sourceList = []
    flows = {}
    srcPort1 = get_sourceP(bufList[0][1])
    sourceList.append(srcPort1)
    flows[srcPort1] = []

    #build a directory, key is port number, value is list of timestamp and tcp packet pairs
    i = 0
    while i < len(bufList):
        sourcePort = get_sourceP(bufList[i][1])
        destPort = get_destP(bufList[i][1])
        tcpPack = bufList[i]

        if sourcePort in sourceList:
            flows[sourcePort].append(tcpPack)
        elif sourcePort == 80:
            flows[destPort].append(tcpPack)
        else:
            sourceList.append(sourcePort)
            flows[sourcePort] = []
            flows[sourcePort].append(tcpPack)
        i += 1
#    print(sourceList)
#    print("Host 130.245.145.12 initiated", len(sourceList), "tcp flows." )
#    print('Port', sourceList[0], 'has', len(flows[sourceList[0]]), 'packets.')
#    print('Port', sourceList[1], 'has', len(flows[sourceList[1]]), 'packets.')
#    print('Port', sourceList[2], 'has', len(flows[sourceList[2]]), 'packets.')

    #First two transactions for each tcp flow.
    for key in flows:
        trans_send_list = []
        trans_receive_list = []
        for pack in flows[key][3:]:
            if get_sourceP(pack[1]) == 80:
                trans_receive_list.append(pack)
            else:
                trans_send_list.append(pack)
#        print('\n=======================================')
#        print('First 2 transactions for port',key,':')
#        get_first2_packet_header_info(trans_send_list, trans_receive_list)

    #Achieve send and receive [timestamp, tcp packket] list of each flow
    for key in flows:
        totalBytes = 0
        sendList = []
        receiveList = []
        for tcppack in flows[key]:
            if get_sourceP(tcppack[1]) == 80:
                receiveList.append(tcppack)
            else:
                sendList.append(tcppack)

        #Empirical throughput calculation
        #(1)Calculate the total bits send from source to Destination
        for packet in sendList:
            totalBytes = totalBytes + len(bytes(packet[1]))
        totalBits = totalBytes * 8

        #(2)calculate the last FIN time munus first SYN time
        tSyn = datetime.datetime.utcfromtimestamp(sendList[0][0])
        tFin = datetime.datetime.utcfromtimestamp(sendList[-1][0])
        timeInterval = str(tFin - tSyn)
        timeInterval = get_sec(timeInterval)
        epthroughput = round(totalBits/1024/1024/timeInterval, 2)

        #(3)Empirical throughput = total bits / time used
#        print('=========================================')
#        print('Port', key, 'empirical throughput is', epthroughput, 'Mbps')


        #Packets loss rate calculation
        sentPacks = len(sendList)
        rsvdPacks = len(receiveList)
        lossRate = (sentPacks - rsvdPacks)/sentPacks
#        print('Port', key, 'loss rate is', "{0:.0%}".format(lossRate))


        #Average RTT calculation
        i = 1
        j = 0
        rttCount = 0
        rtt = 0
        while i < len(sendList):
            tValue = bytes_to_int1(bytes(sendList[i][1])[24:28])
            while j < len(receiveList):
                tEcho = bytes_to_int1(bytes(receiveList[j][1])[28:32])
                if tEcho != tValue:
                    j += 1
                    continue
                else:
                    rttCount += 1
                    sendTime = datetime.datetime.utcfromtimestamp(sendList[i][0])
                    reTime = datetime.datetime.utcfromtimestamp(receiveList[j][0])
                    rtt += get_sec(str(reTime - sendTime))
                    break
            i += 1
        RTT = round(rtt/rttCount,10)
#        print('Port', key, 'average RTT is', RTT, 'seconds')


        #Theoritical throughput calculation
        theoryThroughput = (math.sqrt(3/2)*1448*1024)/(RTT*math.sqrt(lossRate))
        theoryThroughput = round(theoryThroughput/1024/1024, 2)
#        print('Port', key, 'theoritical throughput is', theoryThroughput, 'Mbps')

        #Congestion window size calculation
        print('==========================================')
        print('Port', key, ':')
        i = 2
        j = 0
        windowSize = []
        while i < len(sendList):
            tValue = bytes_to_int1(bytes(sendList[i][1])[24:28])
            while j < len(receiveList):
                size = 0
                tEcho = bytes_to_int1(bytes(receiveList[j][1])[28:32])
                if tEcho != tValue:
                    j += 1
                    continue
                else:
                    reTime = datetime.datetime.utcfromtimestamp(receiveList[j][0])
                    k = i
                    while datetime.datetime.utcfromtimestamp(sendList[k][0]) < reTime:
                        size = size + 1
                        k += 1
                        i = k - 1
                    windowSize.append(size)
                    break
            i += 1
        print('CWND grows like:', windowSize)


        #Retransmissions
        triple = 0
        timeout = 0
        pList = flows[key]
        i = 2
        print('Retransmission situation is calculating: ...')
        while i < len(pList):
            if get_sourceP(pList[i][1]) == 80:
                i += 1
                continue
            else:
                seq = get_seq(pList[i][1])
                j = i + 1
                count = 0
                i += 1
                while j < len(pList):
                    if get_ack(pList[j][1]) == seq:
                        count += 1
                        j += 1
                        continue
                    elif get_seq(pList[j][1]) == seq:
                        if count >= 3:
                            triple += 1
                            break
                        else:
                            timeout += 1
                            break
                    else:
                        j += 1
        print('Retransmission due to triple duplicate ack:', triple)
        print('Retransmission due to timeout:', timeout)

f.close()
