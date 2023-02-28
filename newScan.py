import netScanner as netscanner
import sys
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPalette, QFont
from PySide6.QtWidgets import (QApplication, QMainWindow, QSizePolicy,
    QWidget, QGridLayout, QPushButton, QHBoxLayout, QLabel, QTabWidget,
    QFormLayout, QLineEdit, QListWidget, QCheckBox, QRadioButton)
from PySide6.QtCharts import (QAreaSeries, QBarSet, QChart, QChartView,
                              QLineSeries, QPieSeries, QScatterSeries,
                              QSplineSeries, QStackedBarSeries)
from PySide6 import QtGui

import os
import netScanner as netscanner
import ipDiscoverer as ipdisc

class ScanOptions(QWidget):
    def __init__(self):
        super().__init__()
        self.__init_ui()
        self.show()

    def __init_ui(self):
        self.main_layout = QGridLayout()
        self.setLayout(self.main_layout)

        host_disc = QWidget()
        host_disc_layout = QFormLayout()

        host_disc.setLayout(host_disc_layout)
        host_disc.label = QLabel(host_disc)
        host_disc.label.setText(u'Discover hosts')
        host_disc.label.setFont(QFont('Arial', 14))
        host_disc.label.resize(200, 40)
        host_disc.label.setStyleSheet("border: 1px solid black;")

        vuln_scan = QWidget()
        vuln_scan_layout = QFormLayout()

        vuln_scan.setLayout(vuln_scan_layout)
        vuln_scan.label = QLabel(vuln_scan)
        vuln_scan.label.setText(u'Vulnerability scan')
        vuln_scan.label.setFont(QFont('Arial', 14))
        vuln_scan.label.resize(200, 40)
        vuln_scan.label.setStyleSheet("border: 1px solid black;")

        other_widget = QWidget()
        other_widget_layout = QFormLayout()

        other_widget.setLayout(other_widget_layout)
        other_widget.label = QLabel(other_widget)
        other_widget.label.setText(u'Other options')
        other_widget.label.setFont(QFont('Arial', 14))
        other_widget.label.resize(200, 40)
        other_widget.label.setStyleSheet("border: 1px solid black;")

        self.main_layout.addWidget(host_disc, 0, 0)
        self.main_layout.addWidget(vuln_scan, 1, 0)
        self.main_layout.addWidget(other_widget, 2, 0)

    def host_discovery():
        #input network adress: input host adresses manually / auto detection
        #IP: IPv4 / IPv6 (not implemented)
        #Enable OS detection? 
        #Enable port service discovery?


        return None
    
    def vulnerability_scan():
        #Form
        #input network adress: input host adresses manually / auto detection
        #IP: IPv4 / IPv6 (not implemented)
        #Choose scan mechanism:
        #>Nmap:
        #>>Choose scan script:
        #>>>vulscan:
        #>>>>download latest CVE library? (*Note*: requires admin permissions)
        #>>>vulners
        #>>>vuln
        #>Shodan (requires API key + tokens) (not implemented)
        #Choose vulnerability metric:
        #>CVE - CVSS 
        return None
    
    def clear_cache():
        for filename in os.listdir('./temp/'):
            if (filename == 'cve-cvss-db.csv'): continue
            #os.remove(filename)

