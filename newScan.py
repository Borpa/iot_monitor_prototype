import netScanner as netscanner
import sys
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPalette, QFont
from PySide6.QtWidgets import (QApplication, QMainWindow, QSizePolicy,
    QWidget, QGridLayout, QPushButton, QHBoxLayout, QLabel, QTabWidget,
    QFormLayout, QLineEdit, QListWidget, QCheckBox, QRadioButton, QButtonGroup)
from PySide6.QtCharts import (QAreaSeries, QBarSet, QChart, QChartView,
                              QLineSeries, QPieSeries, QScatterSeries,
                              QSplineSeries, QStackedBarSeries)
from PySide6 import QtGui, QtCore

import os
import netScanner as netscanner
import ipDiscoverer as ipdisc

class ScanOptions(QWidget):
    def __init__(self):
        super().__init__()
        self.__init_ui()
        self.show()

    def switch(self, bool):
        print(bool)
        self.network_input.setEnabled(bool)

    def __init_ui(self):
        self.main_layout = QGridLayout()
        self.setLayout(self.main_layout)

        #Host discovery options
        host_disc = QWidget()
        host_disc_layout = QFormLayout()
        host_disc.setLayout(host_disc_layout)
        host_disc.label = QLabel(host_disc)
        host_disc.label.setText(u'Discover hosts')
        host_disc.label.setFont(QFont('Arial', 12))
        host_disc.label.resize(200, 30)
        host_disc.label.setStyleSheet("border: 1px solid black;")

        host_disc.os_detection_cb = QCheckBox(host_disc)
        host_disc.os_detection_cb.setChecked(True)
        host_disc.os_detection_cb.setText(u'Detect OS')
        host_disc.service_detection_cb = QCheckBox(host_disc)
        host_disc.service_detection_cb.setChecked(True)
        host_disc.service_detection_cb.setText(u'Detect ports and services')

        host_disc_layout.addRow(host_disc.label)
        host_disc_layout.addRow(host_disc.os_detection_cb, host_disc.service_detection_cb)
        
        host_disc.rb_ipv4 = QRadioButton('IPv4', host_disc)
        host_disc.rb_ipv4.setChecked(True)
        host_disc.rb_ipv6 = QRadioButton('IPv6', host_disc)
        host_disc.rb_ipv6.setEnabled(False)
        host_disc_layout.addRow(host_disc.rb_ipv4, host_disc.rb_ipv6)

        host_disc.network_label = QLabel(host_disc)
        host_disc.network_label.setText(u'Network/hosts address')
        host_disc.network_cb = QCheckBox(host_disc)
        host_disc.network_cb.setText(u'Auto-detect network')
        host_disc.network_cb.setChecked(True)

        host_disc.network_input = QLineEdit(host_disc)
        host_disc.network_input.setEnabled(False)
        host_disc.network_label.setFont(QFont('Arial', 10))
        host_disc.network_cb.toggled.connect(lambda checked: host_disc.network_input.setEnabled(not checked))

        host_disc_layout.addRow(host_disc.network_label)
        host_disc_layout.addRow(host_disc.network_cb)
        host_disc_layout.addRow('Input addresses manually: ', host_disc.network_input)


        host_disc.button_disc = QPushButton()
        host_disc.button_disc.setText('Discover hosts')

        container = QWidget()
        cont_layout = QHBoxLayout()
        container.setLayout(cont_layout)
        cont_layout.setAlignment(Qt.AlignLeft)
        cont_layout.addWidget(host_disc.button_disc)

        host_disc_layout.addRow(container)

        #host_disc_layout.addRow(host_disc.rb_group)

        # Vulnerability scan options

        vuln_scan = QWidget()
        vuln_scan_layout = QFormLayout()
        vuln_scan.setLayout(vuln_scan_layout)
        vuln_scan.label = QLabel(vuln_scan)
        vuln_scan.label.setText(u'Vulnerability scan')
        vuln_scan.label.setFont(QFont('Arial', 12))
        vuln_scan.label.resize(200, 30)
        vuln_scan.label.setStyleSheet("border: 1px solid black;")
        vuln_scan_layout.addRow(vuln_scan.label)
        vuln_scan.rb_ipv4 = QRadioButton('IPv4', vuln_scan)
        vuln_scan.rb_ipv4.setChecked(True)
        vuln_scan.rb_ipv6 = QRadioButton('IPv6', vuln_scan)
        vuln_scan.rb_ipv6.setEnabled(False)
        vuln_scan_layout.addRow(vuln_scan.rb_ipv4, vuln_scan.rb_ipv6)


        vuln_scan.button_scan = QPushButton()
        vuln_scan.button_scan.setText('Scan for vulnerabilities')
        container = QWidget()
        cont_layout = QHBoxLayout()
        container.setLayout(cont_layout)
        cont_layout.setAlignment(Qt.AlignLeft)
        cont_layout.addWidget(vuln_scan.button_scan)
        vuln_scan_layout.addRow(container)

        #Other options
        other_widget = QWidget()
        other_widget_layout = QFormLayout()
        other_widget.setLayout(other_widget_layout)
        other_widget.label = QLabel(other_widget)
        other_widget.label.setText(u'Other options')
        other_widget.label.setFont(QFont('Arial', 12))
        other_widget.label.resize(200, 30)
        other_widget.label.setStyleSheet("border: 1px solid black;")
        other_widget_layout.addRow(other_widget.label)

        other_widget.button_cache = QPushButton()
        other_widget.button_cache.setText('Clear cache')
        container = QWidget()
        cont_layout = QHBoxLayout()
        container.setLayout(cont_layout)
        cont_layout.setAlignment(Qt.AlignLeft)
        cont_layout.addWidget(other_widget.button_cache)
        other_widget_layout.addRow(container)

        other_widget.button_update = QPushButton()
        other_widget.button_update.setText('Update vulnerability databases')
        container = QWidget()
        cont_layout = QHBoxLayout()
        container.setLayout(cont_layout)
        cont_layout.setAlignment(Qt.AlignLeft)
        cont_layout.addWidget(other_widget.button_update)
        other_widget_layout.addRow(container)

        #Adding widgets to the main layout
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
    
    def update_cve_db():
        #https://www.cve.org/Downloads
        #https://scipag.github.io/vulscan/
        return None

    def clear_cache():
        for filename in os.listdir('./temp/'):
            if (filename == 'cve-cvss-db.csv'): continue
            #os.remove(filename)

