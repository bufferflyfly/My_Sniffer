
# /usr/bin/env python3
# coding: utf-8
import sys
from PyQt5.QtWidgets import QDialog, QApplication, \
        QTableWidget, QTableWidgetItem, QTreeWidgetItem, QLabel
from Gui import Ui_Main


class AppWindow(QDialog, Ui_Main):
    def __init__(self):
        super(AppWindow, self).__init__()
        self.setupUi(self)
        self.init_ui()

    def init_ui(self):
        pass


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = AppWindow()
    w.show()
    sys.exit(app.exec_())

