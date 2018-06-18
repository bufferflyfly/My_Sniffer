# /usr/bin/env python3
# coding: utf-8

from PyQt5 import QtCore, QtWidgets
import pcapy
from PyQt5.QtCore import QThread,pyqtSignal
from PyQt5.QtGui import QStandardItemModel,QStandardItem
from PyQt5.QtWidgets import QTableWidgetItem,QHeaderView,QAbstractItemView,QTreeWidgetItem,QTreeWidget
import sniffer
import re


class Ui_Main(object):
    cap_sig = pyqtSignal(str,str)
    text_sig = pyqtSignal(str)
    tree_sig = pyqtSignal(dict)
    row_sig = pyqtSignal(list)
    # cap_sig.emit(string)
    # button.clicked.connect(self.func)

    def __init__(self):
        self.pack_store = []
        self.pack_hex_store = []

    def setupUi(self, Main):
        Main.setObjectName("Main")
        Main.resize(1100, 800)

        self.main_layout = QtWidgets.QVBoxLayout(Main)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)
        self.main_layout.setObjectName("main_layout")

        self.control_vbox = QtWidgets.QHBoxLayout()
        self.control_vbox.setContentsMargins(10, 10, 10, 10)
        self.control_vbox.setSpacing(10)
        self.control_vbox.setObjectName("control_vbox")

        self.device_cbox = QtWidgets.QComboBox(Main) #下拉框：用于选择网卡
        self.device_cbox.setObjectName("device_cbox")
        self.control_vbox.addWidget(self.device_cbox)
        devices = pcapy.findalldevs()
        self.device_cbox.addItems(devices)


        self.sniff_button = QtWidgets.QPushButton(Main)      # 按钮：用于捕获包
        self.sniff_button.setObjectName("sniff_button")
        self.control_vbox.addWidget(self.sniff_button)
        self.cap_sig.connect(self.capture_start)             # 捕获包
        self.sniff_button.clicked.connect(self.emit_cap_sig) # 发送捕获包的信号

        self.filter_input = QtWidgets.QLineEdit(Main)    # 行文本：用于填写过滤规则
        self.filter_input.setObjectName("filter_input")
        self.control_vbox.addWidget(self.filter_input)

        self.filter_button = QtWidgets.QPushButton(Main) # 过滤按钮：用于过滤
        self.filter_button.setObjectName("filter_button")
        self.control_vbox.addWidget(self.filter_button)
        self.main_layout.addLayout(self.control_vbox)
        self.filter_button.clicked.connect(self.emit_cap_sig)

        self.quit_button = QtWidgets.QPushButton(Main)  # 暂停按钮
        self.quit_button.setObjectName("filter_button")
        self.control_vbox.addWidget(self.quit_button)
        self.main_layout.addLayout(self.control_vbox)


        self.packet_table = QtWidgets.QTableWidget(Main) # 列表：用于列举包
        self.packet_table.setObjectName("packet_table")
        self.main_layout.addWidget(self.packet_table)
        #self.packet_table.verticalHeader().setVisible(False) #设置垂直表头隐藏
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels([ "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)     # 表格填满窗口
        #self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) #是否拉伸
        self.packet_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 设置表格不能被修改
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows) # 设置表格为整行选中
        #self.packet_table.itemClicked.connect(self.emit_text_sig)
        self.packet_table.itemClicked.connect(self.get_trigger) # 触发
        self.packet_table.itemClicked.connect(self.get_trigger_tree)  # 触发
        self.packet_table.itemClicked.connect(self.get_row)
        #print(self.packet_table.selectedIndexes())
        #print(self.packet_table.selectedItems())
        # self.running_tree = True

        self.details_hbox = QtWidgets.QHBoxLayout()
        self.details_hbox.setObjectName("details_hbox")

        self.tree = QtWidgets.QTreeWidget(Main) #树形结构
        self.tree.setObjectName("tree_text")
        self.tree.setHeaderHidden(True) #隐藏1
        self.details_hbox.addWidget(self.tree)
        self.tree.setColumnCount(1)
        #self.updatetree()


        self.details_text = QtWidgets.QPlainTextEdit(Main) #用于列举详细包信息
        self.details_text.setObjectName("details_text")
        self.details_hbox.addWidget(self.details_text)
        self.details_text.setReadOnly(True) # 设为只读

        self.main_layout.addLayout(self.details_hbox)

        self.retranslateUi(Main)
        QtCore.QMetaObject.connectSlotsByName(Main)

    def retranslateUi(self, Main):
        _translate = QtCore.QCoreApplication.translate
        Main.setWindowTitle(_translate("Main", "Sniffer"))
        self.sniff_button.setText(_translate("Main", "Catch"))
        self.filter_button.setText(_translate("Main", "Filter"))
        self.quit_button.setText(_translate("Main", "Quit"))

    # def get_filter_text(self):
    #     self.filter_input.text()

    # 得到行号
    def get_row(self):
        self.selectedRow = list()
        item = self.packet_table.selectedItems()
        for i in item:
            if self.packet_table.indexFromItem(i).row() not in self.selectedRow:
                self.selectedRow.append(self.packet_table.indexFromItem(i).row())
        row_num = self.selectedRow[0]  # 点击得到当前行的行号
        print("row num: ",row_num)

        # print("//////////////////////////////////")
        self.text_sig.emit(self.pack_hex_store[row_num])
        self.tree_sig.emit(self.pack_store[row_num])
        print("self.pack_hex_store[row_num]: ",self.pack_hex_store[row_num])
        print("self.pack_store[row_num]: ",self.pack_store[row_num])

    def emit_cap_sig(self):
        # print("text",type(self.filter_input.text()))
        # print("debice:",type(self.device_cbox.currentText()))
        self.cap_sig.emit(self.device_cbox.currentText(),str(self.filter_input.text()))

    def capture_start(self,s,f):
        self.sniff = sniffer.Sniffer(s,f)
        self.sniff.start()
        #self.sniff.signal.connect(self.updatetable)
        self.sniff.signal.connect(self.pack_receive)
        #self.sniff.signal.connect(self.pack_receive_original)
        self.quit_button.clicked.connect(self.sniff.stop) #暂停按钮实现

    def pack_receive(self):
        # self.pack_store = []  # 写到这里总是报错，如果写到__init__()中就不会报错啦！
        # self.pack_hex_store = []
        sender = self.sender()# 接收任意类型的信号str list dict int
        pack = sender.get_pack()
        self.pack_store.append(pack)
        pack_hex = pack['Original_hex'] # 数据包的十六进制字符串
        self.pack_hex_store.append(pack_hex)
        # print("pack:",pack)
        # print ("pack_original:",pack_hex)
        # print(type(pack))
        # print(type(pack_hex))
        if pack != None:
            ptime = pack["Time"]
            src = pack["Source"]
            dst = pack["Destination"]
            ptcl = pack["Protocol"]
            plen = pack['Packet_len']
            info = pack["Data"]
            self.updatable1(ptime,src,dst,ptcl,plen,info)
            # self.text_sig.emit(pack_hex) # 如果这样写就会一直传数据不会停，所以我定义了一个变量点击行就触发那个函数展示数据包信息。
            # self.tree_sig.emit(pack)

            # row_num = self.get_row()
            # if row_num == []:
            #     self.text_sig.emit(self.pack_hex_store[0])
            #     self.tree_sig.emit(self.pack_store[0])
            # else:
            #     self.text_sig.emit(self.pack_hex_store[row_num[0]])
            #     self.tree_sig.emit(self.pack_store[row_num[0]])

    # 包的列表
    def updatetable(self,plist):
        for p in plist:
            if p != None:
                self.updatable1(p['Time'],p['Source MAC Address'],p['Destination MAC Addrss'],p['Protocol'],p['Protocol'],p['Data'])

    def updatable1(self,ptime,src,dst,ptcl,plen,info):
        row = self.packet_table.rowCount() #设置行
        self.packet_table.insertRow(row)   #插入行
        self.packet_table.setItem(row, 0, QTableWidgetItem(ptime))
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QTableWidgetItem(ptcl))
        self.packet_table.setItem(row, 4, QTableWidgetItem(plen))
        self.packet_table.setItem(row, 5, QTableWidgetItem(info))

    # def updatetable(self,plist):
    #     for p in plist:
    #         print(str(p['Time']))
    #         self.newItem = QTableWidgetItem(str(p))
    #         self.packet_table.setItem(1,1,self.newItem)

    # def emit_text_sig(self):
    #     #self.text_sig.emit(str)
    #     self.text_sig.connect(self.updatetext)

    # def pack_receive_original(self):
    #     sender = self.sender()
    #     pack_original = sender.get_orig()
    #
    #     if pack_original != None:
    #         return str(pack_original)

            # b_h = pack_original.hex()
            # left = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", b_h) # 用空格分开的16进制字符串
            # right = ''.join([chr(int(b, 16)) for b in [b_h[i:i+2] for i in range(0, len(b_h), 2)]])
            # print(left)
            # print(right)
            # self.details_text.appendPlainText(left)
            # self.details_text.insertPlainText(right)
            # self.details_text.setContentsMargins(200,200,200,200)
        #return str(pack_original)

        #p = bytes(plist,'utf-8')
        # hex_plist = binascii.b2a_hex(p)
        #self.packet_table.itemClicked.connect(self.details_text.appendPlainText(str(pack_original)))
        #self.text_sig.connect(self.updatetext)
            #self.details_text.appendPlainText(str(pack_original))
        #sender = self.sender()

    # 触发的是文本
    def get_trigger(self):
        self.running = True
        self.text_sig.connect(self.updatetext)

    def updatetext(self,pack_hex):
        if self.running == True:
            b_h = pack_hex      #字符串
            left = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", b_h) # 用空格分开的16进制字符串
            right = ''.join([chr(int(b, 16)) for b in [b_h[i:i+2] for i in range(0, len(b_h), 2)]])
            print(left)
            print(right)
            self.details_text.setPlainText(" ") # 清空之前的
            self.details_text.appendPlainText("Hex information:\n " + left + "\n")
            self.details_text.insertPlainText("Unicode inforamtion:\n " + right + "\n")

            self.running = False

    # 触发的是树
    def get_trigger_tree(self):
        self.running_tree = True
        self.tree_sig.connect(self.updatetree)

    def updatetree(self,pack):
        if self.running_tree == True:

            self.tree.clear()
            root1 = QTreeWidgetItem(self.tree)
            root1.setText(0, "Frame: " + str(pack["Packet_len"])+ " bytes")
            child1 = QTreeWidgetItem(root1)
            child1.setText(0, "Arrival Time: " + str(pack["Time"]) + '\n' + "Frame Length: " + str(pack["Packet_len"]) + "bytes")

            root2 = QTreeWidgetItem(self.tree)
            root2.setText(0, "Ethernet,Src: " + str(pack["Source MAC"]) + ", Dst: " + str(pack["Destination MAC"]))#str(pack[])
            child2 = QTreeWidgetItem(root2)
            child2.setText(0, "Source Mac: "+str(pack['Source MAC']) + '\n' + "Destination MAC: " + str(pack["Destination MAC"]) + "\n" + "Protocol: " + str(pack["Protocol"]))

            print (pack['Protocol'])

            if str(pack['Protocol']) == 'UDP' :
                root3 = QTreeWidgetItem(self.tree)
                root3.setText(0, "Internet Protocol Version " + str(pack["IP Version"]) + ", Src: " + str(
                        pack['Source']) + ", Dst" + str(pack['Destination']))
                child3 = QTreeWidgetItem(root3)
                child3.setText(0, "IP Header Length: " + str(
                    int(str(pack['IP Header Length'])) * 4) + "\n" + "Time to live: " + str(pack['TTL']) + "\n" + "Source IP Address: " + str(
                        pack["Source"]) + "\n" + "Destination IP Address: " + str(
                        pack['Destination']) + "\nProtocol: " + str(
                        pack['Protocol']) + "\nHeader Checksum: " + str(pack['Checksum']))

                root4 = QTreeWidgetItem(self.tree)
                root4.setText(0,"User Datagram Protocol, Src Port: " + str(pack['Souce port']) + "Dst Port: " + str(pack['Destination port']))
                child4 = QTreeWidgetItem(root4)
                child4.setText(0,"Source Port: " + str(pack['Souce port']) + "\n" + 'Destination Port: ' + str(pack['Destination port']) + \
                               "\n" + "Length: " + str(pack['User packet length']) + "\nChecksum: " + str(pack['Checksum UDP']))


            elif str(pack['Protocol']) == 'TCP' :
                root3 = QTreeWidgetItem(self.tree)
                root3.setText(0, "Internet Protocol Version " + str(pack["IP Version"]) + ", Src: " + str(
                    pack['Source']) + ", Dst" + str(pack['Destination']))
                child3 = QTreeWidgetItem(root3)
                child3.setText(0, "IP Header Length: " + str(
                    int(str(pack['IP Header Length'])) * 4) + "\n" + "Time to live: " + str(
                    pack['TTL']) + "\n" + "Source IP Address: " + str(
                    pack["Source"]) + "\n" + "Destination IP Address: " + str(
                    pack['Destination']) + "\nProtocol: " + str(
                    pack['Protocol']) + "\nHeader Checksum: " + str(pack['Checksum']))

                root4 = QTreeWidgetItem(self.tree)
                root4.setText(0, "Transmission Protocol, Src Port: " + str(pack['Source Port']) + ",Dst Port: " + str(pack['Destination Port']))
                child4 = QTreeWidgetItem(root4)
                child4.setText(0, "Source Port: " + str(pack['Source Port']) + "\n" + 'Destination Port: ' + str(pack['Destination Port']) + \
                               "\n" + "Sequence Number: " + str(pack['Sequence Number']) + "\nAcknowledge Number: " + str(pack['Acknowledge Number']) +\
                               "\nTCP Header Length: " + str(int(str(pack['TCP Header Length']))*4) + "\nWindow length: " + str(pack['Window length']) +\
                               "\nChecksum: " + str(pack['Checksum_tcp']) + "\nUrgent pointer: " + str(pack['Urgepkt']))

            elif str(pack['Protocol']) == 'ICMP':
                root3 = QTreeWidgetItem(self.tree)
                root3.setText(0, "Internet Protocol Version " + str(pack["IP Version"]) + ", Src: " + str(
                    pack['Source']) + ", Dst" + str(pack['Destination']))
                child3 = QTreeWidgetItem(root3)
                child3.setText(0, "IP Header Length: " + str(
                    int(str(pack['IP Header Length'])) * 4) + "\n" + "Time to live: " + str(
                    pack['TTL']) + "\n" + "Source IP Address: " + str(
                    pack["Source"]) + "\n" + "Destination IP Address: " + str(
                    pack['Destination']) + "\nProtocol: " + str(
                    pack['Protocol']) + "\nHeader Checksum: " + str(pack['Checksum']))

                root4 = QTreeWidgetItem(self.tree)
                root4.setText(0, "Internet Control Message Protocol")
                child4 = QTreeWidgetItem(root4)
                child4.setText(0, "Type: " + str(pack["ICMP Type"]) + "\nCode: " +str(pack["ICMP Code"]) +"\nChecksum: " + str(pack["ICMP Checksum"]) + "\nIdentifier: " + str(pack["Identifier"] + "\nSequenct Numver: " + str(pack["Sequence"])))

            elif str(pack["Protocol"]) == "ARP":
                root3 = QTreeWidgetItem(self.tree)
                root3.setText(0,"Address Resolution Protocol " )
                child3 = QTreeWidgetItem(root3)
                child3.setText(0,"Hardware type: " + str(pack["Hardware type"]) + '\n' + "Protocol type: " + str(pack["Protocol type"]) + "\n" + \
                               "Hardware size: " + str(pack["Hardware size"]) + '\n' + "Protocol size: " + str(pack["Protocol Size"]) + "\n" +\
                               "Opcode: " + str(pack["Opcode"]) + '\n' + "Sender MAC Address: " + str(pack["Source"]) + "\n" +\
                               "Sender IP Address: " + str(pack["Source IP Address"]) + "\n" + "Target MAC Address: " + str(pack["Destination"]) + '\n' +\
                               "Target IP Address: " + str(pack["Target IP Address"]))


            self.running_tree = False




