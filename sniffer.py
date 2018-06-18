#-*- coding:utf-8 -*-
#自己编写嗅探器！我不信我写不出来！

import pcapy
import Parser
import datetime
from struct import *
from PyQt5.QtCore import QThread,pyqtSignal
from PyQt5.QtWidgets import QApplication
import sys


class Sniffer(QThread):
    signal = pyqtSignal()

    def __init__(self,dev,filt,parent=None):
        super(Sniffer,self).__init__(parent)
        self._run = True
        self._dev = dev
        self.fil = filt
        self.pack_list = []

    def run(self):
        # 列举出可利用的设备
        # devices = pcapy.findalldevs()
        # print (devices)
        #
        # for d in devices:
        #     print (d)

        #self.dev = input("Enter device name to sniff: ")
        # print ("Sniffer device is: " + dev)
        #dev = "{B2298B5C-F6B2-441F-8B03-ACA781ABF925}"

        # 参数：打开的设备，抓取数据包的最大的字节数，是否设为混杂模式（1），等待数据包的延迟时间（毫秒）
        cap = pcapy.open_live(self._dev, 65536, 1, 0)

        # 进行过滤
        if self.fil != 0:
            #print (type(self.fil))
            #print ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
            cap.setfilter(self.fil)
        # 开始嗅探
        #i=0
        print(cap)
        while self._run :
            (header, packet) = cap.next()
            if len(packet) >= 14:

                p = Parser.parse()
                after_parse = p.parse_packet(header,packet)  # 解析包

                if after_parse != None:
                    after_parse["Original_hex"] = packet.hex()

                    self.pack_list.append(after_parse) # pcap包中的数据解析
                    #print ("after parse: ",after_parse)

                #self.signal.emit(self.pack_list) # 发送信号
                    self.signal.emit()
                #print("pack_list: ", self.pack_list)
                # i+=1
                # print (i)
                    self.sleep(1)


    def stop(self):
        self._run = False

    def get_pack(self):
        pack = self.pack_list.pop(0)
        return pack

    # def get_orig(self):
    #     pack_o = self.pack_orig.pop(0)
    #     return pack_o

if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = Sniffer('{0F761049-52DF-48FC-954C-9AEF70011A72}')
    sniffer.start()
    sys.exit(app.exec_())
# sniffer = Sniffer('{B2298B5C-F6B2-441F-8B03-ACA781ABF925}')
# sniffer.start()


