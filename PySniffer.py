import scapy, sys, os, subprocess
from PyQt6 import QtCore, QtGui, QtWidgets
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(640, 480)
        MainWindow.setFixedSize(640, 480)
        MainWindow.setStyleSheet("QPushButton {\n"
        "    background-color: #262626;\n"
        "    color: #ffffff;\n"
        "    border: 1px solid #007bff;\n"
        "    border-radius: 8px;\n"
        "    padding: 10px 20px;\n"
        "    font-size: 14px;\n"
        "}\n"
        "\n"
        "QLineEdit {\n"
        "    background-color: #181818;\n"
        "    color: #ffffff;\n"
        "    border: 1px solid #444444;\n"
        "    border-radius: 5px;\n"
        "    padding: 5px 10px;\n"
        "}\n"
        "\n"
        "QLineEdit:hover, QLineEdit:focus {\n"
        "    border: 1px solid #007bff;\n"
        "}\n"
        "\n"
        "QPlainTextEdit {\n"
        "    background-color: #181818;\n"
        "    color: #ffffff;\n"
        "    border: 1px solid #007bff;\n"
        "    border-radius: 5px;\n"
        "    padding: 5px 10px;\n"
        "}\n"
        "\n"
        "QPushButton:hover {\n"
        "    background-color: #0056b3; \n"
        "    border: 1px solid #007bff;\n"
        "}\n"
        "\n"
        "QPushButton:pressed {\n"
        "    background-color: #007bff; \n"
        "    border: 1px solid #007bff;\n"
        "}\n"
        "color: rgb(38, 38, 38);")
        self.isrun = None
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.plainTextEdit = QtWidgets.QPlainTextEdit(parent=self.centralwidget)
        self.plainTextEdit.setGeometry(QtCore.QRect(10, 50, 621, 341))
        self.plainTextEdit.setObjectName("plainTextEdit")


        self.pushButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(527, 400, 101, 41))
        self.pushButton.setObjectName("pushButton")

        self.pushButton_2 = QtWidgets.QPushButton(parent=self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(420, 400, 101, 41))
        self.pushButton_2.setObjectName("pushButton_2")

        self.checkBox = QtWidgets.QCheckBox(parent=self.centralwidget)
        self.checkBox.setGeometry(QtCore.QRect(10, 10, 61, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.checkBox.setFont(font)
        self.checkBox.setObjectName("checkBox")

        self.lineEdit_2 = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(10, 400, 321, 31))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.checkBox_2 = QtWidgets.QCheckBox(parent=self.centralwidget)
        self.checkBox_2.setGeometry(QtCore.QRect(70, 10, 61, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.checkBox_2.setFont(font)
        self.checkBox_2.setObjectName("checkBox_2")
        self.checkBox_3 = QtWidgets.QCheckBox(parent=self.centralwidget)
        self.checkBox_3.setGeometry(QtCore.QRect(130, 10, 61, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.checkBox_3.setFont(font)
        self.checkBox_3.setObjectName("checkBox_3")
        self.checkBox_4 = QtWidgets.QCheckBox(parent=self.centralwidget)
        self.checkBox_4.setGeometry(QtCore.QRect(190, 10, 61, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.checkBox_4.setFont(font)
        self.checkBox_4.setObjectName("checkBox_4")
        self.label = QtWidgets.QLabel(parent=self.centralwidget)
        self.label.setGeometry(QtCore.QRect(500, 10, 131, 31))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(parent=self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(330, 10, 190, 31))
        self.label_2.setObjectName("label_2")
        self.plainTextEdit = QtWidgets.QPlainTextEdit(parent=self.centralwidget)
        self.plainTextEdit.setGeometry(QtCore.QRect(10, 50, 621, 341))
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.plainTextEdit.setReadOnly(True)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 640, 30))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(parent=self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuHelp = QtWidgets.QMenu(parent=self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        self.menuAbout = QtWidgets.QMenu(parent=self.menubar)
        self.menuAbout.setObjectName("menuAbout")
        MainWindow.setMenuBar(self.menubar)
        self.actionSave_logs = QtGui.QAction(parent=MainWindow)
        self.actionSave_logs.setObjectName("actionSave_logs")
        self.actionView_help = QtGui.QAction(parent=MainWindow)
        self.actionView_help.setObjectName("actionView_help")
        self.actionAbout_PySniff = QtGui.QAction(parent=MainWindow)
        self.actionAbout_PySniff.setObjectName("actionAbout_PySniff")
        self.menuFile.addAction(self.actionSave_logs)
        self.menuHelp.addAction(self.actionView_help)
        self.menuAbout.addAction(self.actionAbout_PySniff)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())
        self.menubar.addAction(self.menuAbout.menuAction())
        self.threadsnif = snifferthread()
        self.threadsnif.textupdate.connect(self.addlog)
        self.threadsnif.countupdate.connect(self.updatelabel)
        self.stattimer = QtCore.QTimer()
        self.stattimer.timeout.connect(self.calculate)
        self.lastpacket = 0


        self.pushButton.clicked.connect(self.startsniff)
        self.pushButton_2.clicked.connect(self.stopsniff)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def calculate(self):
        current = self.threadsnif.counter
        diff = current - self.lastpacket
        pps = diff / 2
        _translate = QtCore.QCoreApplication.translate
        self.label_2.setText(_translate("MainWindow", f"Packet per second: {pps:.1f}"))
        self.lastpacket = current
        

    def startsniff(self):
        if not self.threadsnif.isRunning():
            self.lastpacket = 0
            self.label_2.setText("Packet per second: 0.0")
            self.stattimer.start(2000)
            self.plainTextEdit.appendPlainText("Launch sniffing...")
            self.isrun = True
            self.threadsnif.showdns = self.checkBox.isChecked()
            self.threadsnif.showhttp = self.checkBox_2.isChecked()
            self.threadsnif.showtcp = self.checkBox_3.isChecked()
            self.threadsnif.showudp = self.checkBox_4.isChecked()
            self.threadsnif.filter = self.lineEdit_2.text().strip()
            self.threadsnif.start()

    def stopsniff(self):
        self.lastpacket = 0
        self.threadsnif.stop()
        self.stattimer.stop()
        if self.isrun:
            QtCore.QTimer.singleShot(500, self.sent)
            self.isrun = False
        else:
            return
        
    def sent(self):
        self.plainTextEdit.appendPlainText("End sniffing...")

    def updatelabel(self, count):
        _translate = QtCore.QCoreApplication.translate
        self.label.setText(_translate("MainWindow", f"Packet count: {count}"))

    def addlog(self, text):
        self.plainTextEdit.appendPlainText(text)
        self.plainTextEdit.ensureCursorVisible()

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "PySniffer v1.5"))
        self.pushButton.setText(_translate("MainWindow", "Start"))
        self.pushButton_2.setText(_translate("MainWindow", "Stop"))
        self.checkBox.setText(_translate("MainWindow", "Dns"))
        self.checkBox_2.setText(_translate("MainWindow", "Http"))
        self.checkBox_3.setText(_translate(_translate("MainWindow", "Tcp"), "Tcp"))
        self.checkBox_4.setText(_translate(_translate("MainWindow", "Udp"), "Udp"))
        self.label.setText(_translate("MainWindow", "Packet count: 0"))
        self.label_2.setText(_translate("MainWindow", "Packet per second: 0"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuHelp.setTitle(_translate("MainWindow", "Help"))
        self.menuAbout.setTitle(_translate("MainWindow", "About"))
        self.actionSave_logs.setText(_translate("MainWindow", "Save logs"))
        self.actionView_help.setText(_translate("MainWindow", "View help"))
        self.actionAbout_PySniff.setText(_translate("MainWindow", "About PySniff"))



class snifferthread(QtCore.QThread):
    textupdate = QtCore.pyqtSignal(str)
    countupdate = QtCore.pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.running = False
        self.filter = ""
        self.showdns = False
        self.showhttp = False
        self.showtcp = False
        self.showudp = False
        self.counter = 0

    def run(self):
        self.running = True
        filter_arg = self.filter if self.filter else None
        sniff(filter=filter_arg, prn=self.ppacket, stop_filter=lambda x: not self.running, store=0)

    def stop(self):
        self.running = False
        self.counter = 0

    def ppacket(self, pkt):
        if not pkt.haslayer(IP):
            return



        proto = "IP/Other"

        if pkt.haslayer(DNS):
            proto = "DNS"
        elif pkt.haslayer(TCP):
            if pkt[TCP].dport in (80, 443) or pkt[TCP].sport in (80, 443):
                proto = "HTTP"
            else:
                proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"

        show = False
        if proto == "DNS" and self.showdns:
            show = True
        elif proto == "HTTP" and self.showhttp:
            show = True
        elif proto == "TCP" and self.showtcp:
            show = True
        elif proto == "UDP" and self.showudp:
            show = True
        elif proto == "IP/Other":
            show = False

        if show:
            src_port = ""
            dst_port = ""
            if pkt.haslayer(TCP):
                src_port = f":{pkt[TCP].sport}"
                dst_port = f":{pkt[TCP].dport}"
            elif pkt.haslayer(UDP):
                src_port = f":{pkt[UDP].sport}"
                dst_port = f":{pkt[UDP].dport}"

            info = f"[{proto}] {pkt[IP].src}{src_port} -> {pkt[IP].dst}{dst_port}"
            self.textupdate.emit(info)
            self.counter += 1
            self.countupdate.emit(self.counter)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
