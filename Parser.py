# -*- coding:utf-8 -*-
from struct import *
import socket
import datetime

class parse:
    def __init__(self):
        pass

    # 地址转换
    def eth_addr(self, a):
        return ":".join("%02x" % i for i in a)

    # 解析包
    def parse_packet(self,header,packet):

        # 用字典存储一个包的内容
        packet_context = {}


        # 先处理Pcap包头，提取出时间和包的长度
        pcap_header = {}
        time1 = datetime.datetime.now()
        time = datetime.datetime.strftime(time1, '%Y-%m-%d %H:%M:%S')

        header_len = header.getlen()
        #header_total_len = header.getcaplen()

        pcap_header["Time"] = time
        pcap_header["Packet_len"] = str(header_len) #字符类型传入的不多导致显示不出来

        packet_context.update(pcap_header)
        # print ('%s: captured %d bytes, truncated to %d bytes' %(time, header_len, header_total_len))


        # 再处理pacp包中的数据
        ethh_context = {"Destination MAC": 0, "Source MAC": 0, "Protocol": 8}
        # 解析以太网帧头
        eth_length = 14
        eth_header = packet[:eth_length]
        # print ("eth_header: ",eth_header)
        # print ("type(eth_header): ",type(eth_header))

        eth = eth_header
        eth = unpack("!6s6sH", eth_header)  # !表示网络字节顺序；6s表示6bytes字节长度的string；H表示unsigned short
        # ntohs:将一个无符号短整型数据从网络字节顺序转换为主机字节顺序
        eth_protocol = socket.ntohs(eth[2])

        ethh_context["Destination MAC"] = self.eth_addr(packet[0:6])
        ethh_context["Source MAC"] = self.eth_addr(packet[6:12])
        ethh_context["Protocol"] = str(eth_protocol)

        if str(eth_protocol) == "1544":
             ethh_context["Protocol"] = "ARP"
        #elif str(eth_protocol) == "8" & str(protocol) == "17":
        #      ethh_context["Protocol"] = "Other Protocol"
        # print("ethh_context:", ethh_context)

        packet_context.update(ethh_context)

        # print("packet_context:", packet_context)
        #print ('***********eth_protocol: ', eth_protocol)
        # print (packet[0:6])
        # print (eth_addr(packet[0:6]))
        # print ("Destination MAC: " + eth_addr(packet[0:6]) + "\nSource MAC: " + eth_addr(packet[6:12]) +\
        #      "\nProtocol : " + str(eth_protocol))

        # 解析IP包，IP Protocol number == 8 好像是十六进制
        if eth_protocol == 8:

            # 取IP头的前20个字节
            ip_header = packet[eth_length:20 + eth_length]
            iph = unpack('!BBHHHBBH4s4s',
                         ip_header)  # B：unsigned char==integer 1; H:unsigned short==integer 2; s:string
            # print ("iph: ",iph)  # iph:  (69, 0, 1488, 26291, 16384, 54, 6, 63342, b'u\x176\xa1', b'\n\xaf*\x9f')
            # 说明打印出来的是十进制！ 69 = 0x45 = 01000101
            # 版本号 4个bit,半个字节
            version_ihl = iph[0]  # 69
            version = version_ihl >> 4  # 位运算是先转为2进制，再进行移位
            # print ("ip version: ",version) # 4

            # IP头长度 ???
            ihl = version_ihl & 0xF  # 5
            iph_length = ihl * 4  # 20

            # 服务类型
            service = iph[1]
            # 总长度
            total_ip_length = iph[2]
            # print ("total_ip_length: ",total_ip_length)
            # 标识 IP包标识，主机使用它唯一确定每个发送的数据报
            identification = iph[3]
            # 标志
            flag0 = iph[4]  # 16384
            # print ('flag0: ',flag0)
            flag = flag0 >> 13
            # print ('flag: ',flag)

            # ttl
            ttl = iph[5]
            protocol = iph[6]  # 1:ICMP  2:IGMP  6:TCP  17:UDP  50:ESP  47:GRE
            checksum = iph[7]
            s_addr = socket.inet_ntoa(iph[8])  # IPV4地址转换为ascii字符串
            d_addr = socket.inet_ntoa(iph[9])

            iph_context = {"IP Version": 4, "IP Header Length": 5, "TTL": 0, "Protocol based on IP": 1, "Checksum": 0,
                           "Source": 0, "Destination": 0}
            iph_context["IP Version"] = str(version)
            iph_context["IP Header Length"] = str(ihl)
            iph_context["TTL"] = str(ttl)
            iph_context["Protocol based on IP"] = str(protocol)
            #print ("str protocol: ",str(protocol))

            if str(protocol) == "6":
                ethh_context["Protocol"] = "TCP"
            elif str(protocol) == "1":
                ethh_context["Protocol"] = "ICMP"
            elif str(protocol) == "17":
                ethh_context["Protocol"] = "UDP"
                #print ("ethh_context[\"Protocol\"]",ethh_context["Protocol"])
            else:
                ethh_context["Protocol"] = "Other Protocol"


            iph_context["Checksum"] = str(checksum)
            iph_context["Source"] = s_addr
            iph_context["Destination"] = d_addr

            # print ("iph_context: ",iph_context)
            packet_context.update(ethh_context) # 必须要加它，不然无法更新
            packet_context.update(iph_context)

            # print ("Version: " + str(version) + " IP Header Length: " + str(ihl) + " TTL: " + str(ttl) +\
            #     " Protocol: " + str(protocol) + " Checksum: " + str(checksum) + " Source IP Address: " +\
            #     s_addr + " Destination IP Addrss: " + d_addr)

            # 解析TCP数据包 20个字节
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t + 20]

                tcph = unpack('!HHLLBBHHH', tcp_header)
                # print ("tcph: ",tcph)

                s_port = tcph[0]  # 源端口
                d_port = tcph[1]  # 目的端口
                sequence = tcph[2]  # 序列号
                ack = tcph[3]  # 确认号
                # tcph_length = tcph[4] #TCP头部长度
                # doff_reversed = tcph[5]  # 保留字段
                # tcph_length = doff_reversed >> 4 #TCP 头长度
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                window = tcph[6]
                checksum_tcp = tcph[7]
                urgepkt = tcph[8]

                # print ("Source Port: " + str(s_port) + " Destination Port: " + str(d_port) + " Sequence Number: " + str(sequence) +\
                #     " Acknowledge Number: " + str(ack)  + " TCP Header Length: " + str(tcph_length) + " Window length: " + str(window) + " Checksum_tcp: " + str(checksum_tcp) + " Urgepkt: " + str(urgepkt))

                h_size = eth_length + iph_length + tcph_length * 4  # ???
                data_size = len(packet) - h_size

                #data = packet[h_size:]
                data = str(s_port)+ "->" + str(d_port)
                # print("TCP Data: " + str(data))

                tcph_context = {"Source Port": 0, "Destination Port": 0, "Sequence Number": 0, "Acknowledge Number": 0, \
                                "TCP Header Length": 0, "Window length": 0, "Checksum_tcp": 0, "Urgepkt": 0,
                                "Data": 0}
                tcph_context["Source Port"] = str(s_port)
                tcph_context["Destination Port"] = str(d_port)
                tcph_context["Sequence Number"] = str(sequence)
                tcph_context["Acknowledge Number"] = str(ack)
                tcph_context["TCP Header Length"] = str(tcph_length)
                tcph_context["Window length"] = str(window)
                tcph_context["Checksum_tcp"] = str(checksum_tcp)
                tcph_context["Urgepkt"] = str(urgepkt)
                tcph_context["Data"] = str(data)

                # print("tcph_context: ", tcph_context)

                packet_context.update(tcph_context)
                return packet_context



            # ICMP 包
            elif protocol == 1:
                u = iph_length + eth_length
                icmph_length = 8
                icmp_header = packet[u:u + 8]

                icmph = unpack("!BBHHH", icmp_header)
                # print ("icmph: " ,icmph)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum_icmp = icmph[2]
                identifier = icmph[3]
                sequence_icmp = icmph[4]

                # print ("ICMP Type: " + str(icmp_type) + " ICMP Code: " + str(code) + " ICMP Checksum: " + str(checksum_icmp))

                h_size = iph_length + eth_length + icmph_length
                data_size = len(packet) - h_size
                #data = packet[h_size:]
                data = str(icmp_type) + " id=" + str(identifier) + " seq=" + str(sequence_icmp)
                # print ("ICMP data: " + str(data))

                icmph_context = {"ICMP Type": 0, "ICMP Code": 0, "ICMP Checksum": 0, "Identifier": 0,"Sequence":0}
                icmph_context["ICMP Type"] = str(icmp_type)
                icmph_context["ICMP Code"] = str(code)
                icmph_context["ICMP Checksum"] = str(checksum_icmp)
                icmph_context["Identifier"] = str(identifier)
                icmph_context["Sequence"] = str(sequence_icmp)
                icmph_context["Data"] = str(data)

                # print ("ICMP Header Context: ",icmph_context)

                packet_context.update(icmph_context)
                return packet_context


            # #UDP包
            elif protocol == 17: # UDP
                u = iph_length + eth_length
                udp_length = 8
                udp_header = packet[u:u + 8]
                # print ("udp_h: "+str(udp_header))

                udph = unpack("!HHHH", udp_header)
                # print ("udph: "+str(udph))

                sourceport = udph[0]
                destinport = udph[1]
                userpacket_length = udph[2]
                checksum_udp = udph[3]

                # print ("Souce port: " + str(sourceport)+" Destination port: " + str(destinport) + " User packet length: " + str(userpacket_length) +\
                #        " Checksum UDP: " + str(checksum_udp))

                h_length = eth_length + iph_length + udp_length
                data_size = len(packet) - h_length
                #data = packet[h_length:]
                data = str(sourceport) + " -> " + str(destinport) + " Len=" + str(userpacket_length)
                # print ("UDP data: " + str(data))

                udph_context = {"Souce port": 0, "Destination port": 0, "User packet length": 0, "Checksum UDP": 0,
                                "Data": 0}
                udph_context["Souce port"] = str(sourceport)
                udph_context["Destination port"] = str(destinport)
                udph_context["User packet length"] = str(userpacket_length)
                udph_context["Checksum UDP"] = str(checksum_udp)
                udph_context["Data"] = str(data)

                # print ("UDP Header Context: ",udph_context)

                packet_context.update(udph_context)
                return packet_context

            else:
                non = {"Data":0}
                packet_context.update(non)
                return packet_context
                #return ("Protocol is not TCP,ICMP,UDP")

        elif eth_protocol == 1544 :#0x0608
            #print ("&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            arp_header = packet[eth_length: 28+ eth_length]
            arph = unpack('!HHBBH6s4s6s4s',arp_header)

            hardware_type = arph[0]
            pro_type = arph[1]
            hardware_size = arph[2]
            pro_size = arph[3]
            op = arph[4]
            sender_MAC = self.eth_addr(arph[5])
            sender_IP = socket.inet_ntoa(arph[6])
            target_MAC = self.eth_addr(arph[7])
            target_IP = socket.inet_ntoa(arph[8])

            arph_context = {"Hardware type": 1, "Protocol type": 4, "Hardware size": 6, "Protocol Size": 4, "Opcode": 1, \
                            "Source" : 0, "Source IP Address": 0, "Destination": 0, "Destination IP Address": 0}
            arph_context["Hardware type"] = hardware_type
            arph_context["Protocol type"] = pro_type
            arph_context["Hardware size"] = hardware_size
            arph_context["Protocol Size"] = pro_size
            arph_context["Opcode"] = op
            arph_context["Source"] = sender_MAC
            arph_context["Sender IP Address"] = sender_IP
            arph_context["Destination"] = target_MAC
            arph_context["Target IP Address"] = target_IP
            arph_context["Data"] = "Who has" + target_IP +"? Tell " + sender_IP

            packet_context.update(arph_context)
            return packet_context
