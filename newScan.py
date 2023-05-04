from PySide6.QtCore import Qt, QTranslator, QSize, QRect, QObject, QPropertyAnimation
from PySide6.QtGui import QFont, QMovie
from PySide6.QtWidgets import (QWidget, QGridLayout, QPushButton, QHBoxLayout, QLabel,
                               QFormLayout, QLineEdit, QCheckBox, QRadioButton, QComboBox, QMessageBox)

import os
import netScanner as netscanner
import json
import ipDiscoverer as discoverer
import re
import multiprocessing as mp
import pandas as pd


def hostscan(hosts, args):
    netscanner.discover_hosts_placeholder(hosts, args)


def vulnscan(hosts, args):
    netscanner.scan_placeholder(hosts, args)


class LoadingStatus(QMessageBox):
    def __init__(self):
        super().__init__()
        self.label = QLabel(self)

        self.movie = QMovie('./images/loading.gif')
        self.label.setMovie(self.movie)
        self.label.resize(10, 10)
        self.startAnim()

    def startAnim(self):
        self.movie.start()

    def stopAnim(self):
        self.movie.stop()
        self.label.setText('Done')


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

        # Host discovery options
        self.host_disc = QWidget()
        host_disc_layout = QFormLayout()
        self.host_disc.setLayout(host_disc_layout)
        self.host_disc.label = QLabel(self.host_disc)
        self.host_disc.label.setText(self.tr('Discover hosts'))
        self.host_disc.label.setFont(QFont('Arial', 12))
        self.host_disc.label.resize(200, 30)
        self.host_disc.label.setStyleSheet("border: 1px solid black;")

        self.host_disc.os_detection_cb = QCheckBox(self.host_disc)
        self.host_disc.os_detection_cb.setChecked(True)
        self.host_disc.os_detection_cb.setText(self.tr('Detect OS'))
        self.host_disc.service_detection_cb = QCheckBox(self.host_disc)
        self.host_disc.service_detection_cb.setChecked(True)
        self.host_disc.service_detection_cb.setText(
            u'Detect ports and services')

        host_disc_layout.addRow(self.host_disc.label)
        host_disc_layout.addRow(
            self.host_disc.os_detection_cb, self.host_disc.service_detection_cb)

        self.host_disc.rb_ipv4 = QRadioButton('IPv4', self.host_disc)
        self.host_disc.rb_ipv4.setChecked(True)
        self.host_disc.rb_ipv6 = QRadioButton('IPv6', self.host_disc)
        self.host_disc.rb_ipv6.setEnabled(False)
        host_disc_layout.addRow(self.host_disc.rb_ipv4, self.host_disc.rb_ipv6)

        self.host_disc.network_label = QLabel(self.host_disc)
        self.host_disc.network_label.setText(self.tr('Network/hosts address'))
        self.host_disc.network_cb = QCheckBox(self.host_disc)
        self.host_disc.network_cb.setText(self.tr('Auto-detect network'))
        self.host_disc.network_cb.setChecked(True)

        self.host_disc.network_input = QLineEdit(self.host_disc)
        self.host_disc.network_input.setEnabled(False)
        self.host_disc.network_label.setFont(QFont('Arial', 10))
        self.host_disc.network_cb.toggled.connect(
            lambda checked: self.host_disc.network_input.setEnabled(not checked))

        host_disc_layout.addRow(self.host_disc.network_label)
        host_disc_layout.addRow(self.host_disc.network_cb)
        host_disc_layout.addRow(
            self.tr('Input addresses manually: '), self.host_disc.network_input)

        self.host_disc.button_disc = QPushButton()
        self.host_disc.button_disc.setText(self.tr('Discover hosts'))
        self.host_disc.button_disc.clicked.connect(self.host_discovery)

        container = QWidget()
        self.cont_layout = QHBoxLayout()
        container.setLayout(self.cont_layout)
        self.cont_layout.setAlignment(Qt.AlignLeft)
        self.cont_layout.addWidget(self.host_disc.button_disc)

        host_disc_layout.addRow(container)

        # host_disc_layout.addRow(host_disc.rb_group)

        # Vulnerability scan options

        self.vuln_scan = QWidget()
        vuln_scan_layout = QFormLayout()
        self.vuln_scan.setLayout(vuln_scan_layout)
        self.vuln_scan.label = QLabel(self.vuln_scan)
        self.vuln_scan.label.setText(self.tr('Vulnerability scan'))
        self.vuln_scan.label.setFont(QFont('Arial', 12))
        self.vuln_scan.label.resize(200, 30)
        self.vuln_scan.label.setStyleSheet("border: 1px solid black;")
        vuln_scan_layout.addRow(self.vuln_scan.label)
        self.vuln_scan.rb_ipv4 = QRadioButton('IPv4', self.vuln_scan)
        self.vuln_scan.rb_ipv4.setChecked(True)
        self.vuln_scan.rb_ipv6 = QRadioButton('IPv6', self.vuln_scan)
        self.vuln_scan.rb_ipv6.setEnabled(False)
        vuln_scan_layout.addRow(self.vuln_scan.rb_ipv4, self.vuln_scan.rb_ipv6)

        # network scan method selection
        container = QWidget(self.vuln_scan)
        self.cont_layout = QHBoxLayout()
        container.setLayout(self.cont_layout)
        self.cont_layout.setAlignment(Qt.AlignLeft)
        self.vuln_scan.scan_label = QLabel(container)
        self.vuln_scan.scan_label.setText(self.tr('Select scanner: '))
        self.vuln_scan.scan_label.setFont(QFont('Arial', 10))
        self.vuln_scan.method_cmb = QComboBox(container)
        self.vuln_scan.method_cmb.addItem(u'Nmap')
        self.vuln_scan.method_cmb.addItem(
            self.tr('Shodan (requires API key + tokens)'))

        self.vuln_scan.api_label = QLabel(container)
        self.vuln_scan.api_label.setText(u'Shodan API key: ')
        self.vuln_scan.api_label.setFont(QFont('Arial', 10))

        self.vuln_scan.api_input = QLineEdit(container)
        if (self.__load_shodan_api()):
            self.vuln_scan.api_input.setText(self.__load_shodan_api())

        self.vuln_scan.save_api = QPushButton(container)
        self.vuln_scan.save_api.setText(self.tr('Save API'))
        self.vuln_scan.save_api.clicked.connect(self.__save_shodan_api)

        self.cont_layout.addWidget(self.vuln_scan.scan_label)
        self.cont_layout.addWidget(self.vuln_scan.method_cmb)
        self.cont_layout.addWidget(self.vuln_scan.api_label)
        self.cont_layout.addWidget(self.vuln_scan.api_input)
        self.cont_layout.addWidget(self.vuln_scan.save_api)
        vuln_scan_layout.addRow(container)

        # vulnerability db selection
        container = QWidget(self.vuln_scan)
        self.cont_layout = QHBoxLayout()
        container.setLayout(self.cont_layout)
        self.cont_layout.setAlignment(Qt.AlignLeft)
        self.vuln_scan.db_label = QLabel(container)
        self.vuln_scan.db_label.setText(
            self.tr('Select vulnerability scan script + db: '))
        self.vuln_scan.db_label.setFont(QFont('Arial', 10))
        self.vuln_scan.script_cmb = QComboBox(container)
        self.vuln_scan.script_cmb.addItem(u'vulscan + cve (Recommended)')
        self.vuln_scan.script_cmb.addItem(u'vulners + cve')
        self.vuln_scan.script_cmb.addItem(u'vuln')

        self.vuln_scan.metric_label = QLabel(container)
        self.vuln_scan.metric_label.setText(
            self.tr('Select vulnerability metric: '))
        self.vuln_scan.metric_label.setFont(QFont('Arial', 10))
        self.vuln_scan.metric_cmb = QComboBox(container)
        self.vuln_scan.metric_cmb.addItem(self.tr('CVE + CVSS score'))

        self.cont_layout.addWidget(self.vuln_scan.db_label)
        self.cont_layout.addWidget(self.vuln_scan.script_cmb)
        self.cont_layout.addWidget(self.vuln_scan.metric_label)
        self.cont_layout.addWidget(self.vuln_scan.metric_cmb)
        vuln_scan_layout.addRow(QWidget())
        vuln_scan_layout.addRow(container)

        # vuln_scan_layout.addWidget(vuln_scan.method_cmb)

        # network/hosts addresses input
        self.vuln_scan.network_label = QLabel(self.vuln_scan)
        self.vuln_scan.network_label.setText(self.tr('Network/hosts address'))
        self.vuln_scan.network_label.setFont(QFont('Arial', 10))
        self.vuln_scan.network_cb = QCheckBox(self.vuln_scan)
        self.vuln_scan.network_cb.setText(self.tr('Auto-detect network'))
        self.vuln_scan.network_cb.setChecked(True)

        self.vuln_scan.network_input = QLineEdit(self.vuln_scan)
        self.vuln_scan.network_input.setEnabled(False)
        self.vuln_scan.network_cb.toggled.connect(
            lambda checked: self.vuln_scan.network_input.setEnabled(not checked))

        vuln_scan_layout.addRow(self.vuln_scan.network_label)
        vuln_scan_layout.addRow(self.vuln_scan.network_cb)
        vuln_scan_layout.addRow(
            self.tr('Input addresses manually: '), self.vuln_scan.network_input)

        self.vuln_scan.button_scan = QPushButton()
        self.vuln_scan.button_scan.setText(self.tr('Scan for vulnerabilities'))
        self.vuln_scan.button_scan.clicked.connect(self.vulnerability_scan)
        container = QWidget()
        self.cont_layout = QHBoxLayout()
        container.setLayout(self.cont_layout)
        self.cont_layout.setAlignment(Qt.AlignLeft)
        self.cont_layout.addWidget(self.vuln_scan.button_scan)
        vuln_scan_layout.addRow(container)

        # Other options
        other_widget = QWidget()
        other_widget_layout = QFormLayout()
        other_widget.setLayout(other_widget_layout)
        other_widget.label = QLabel(other_widget)
        other_widget.label.setText(self.tr('Other options'))
        other_widget.label.setFont(QFont('Arial', 12))
        other_widget.label.resize(200, 30)
        other_widget.label.setStyleSheet("border: 1px solid black;")
        other_widget_layout.addRow(other_widget.label)

        other_widget.save_sett = QPushButton()
        other_widget.save_sett.setText(self.tr('Save settings'))
        other_widget.button_update = QPushButton()
        other_widget.button_update.setText(
            self.tr('Update vulnerability database'))
        other_widget.button_update.clicked.connect(self.update_cve_db)
        other_widget.button_cache = QPushButton()
        other_widget.button_cache.setText(self.tr('Clear cache'))
        other_widget.button_cache.clicked.connect(self.clear_cache)

        container = QWidget()
        self.cont_layout = QHBoxLayout()
        container.setLayout(self.cont_layout)
        self.cont_layout.setAlignment(Qt.AlignLeft)
        self.cont_layout.addWidget(other_widget.button_cache)
        self.cont_layout.addWidget(other_widget.button_update)
        self.cont_layout.addWidget(other_widget.save_sett)
        other_widget_layout.addRow(container)

        # Adding widgets to the main layout
        self.main_layout.addWidget(self.host_disc, 0, 0, 1, 1)
        self.main_layout.addWidget(self.vuln_scan, 1, 0, 1, 1)
        self.main_layout.addWidget(other_widget, 2, 0, 1, 1)

    def __save_shodan_api(self):
        api = self.vuln_scan.api_input.text()

        dict = {'API': api}
        with open('./temp/shodan.json', 'w') as file_json:
            json.dump(dict, file_json)

        dlg = QMessageBox(self)
        dlg.setWindowTitle("Notification")
        dlg.setText("Saved")
        dlg.exec_()

    def __load_shodan_api(self):
        if (not os.path.exists('./temp/shodan.json')):
            return False

        with open(f'./temp/shodan.json', 'r') as file_json:
            api = json.load(file_json)
        return api['API']

    def host_discovery(self):
        hosts = '127.0.0.1'
        if (not self.host_disc.network_cb.isChecked()):
            hosts = str(self.host_disc.network_input.text())
            if (not re.fullmatch('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hosts)):
                hosts = discoverer.get_network_local_IPV4()
        else:
            hosts = discoverer.get_network_local_IPV4()

        args = ''  # argument string

        if (self.host_disc.service_detection_cb.isChecked()):
            args = args + '-sV' + ' '
        if (self.host_disc.os_detection_cb.isChecked()):
            args = args + '-O' + ' '

        if __name__ == 'newScan':
            print(hosts + ' ' + args)
            context = mp.get_context('spawn')
            process = context.Process(target=hostscan, args=(hosts, args))
            # loading = LoadingStatus()
            # loading.setStyleSheet("QLabel{min-width: 200px; min-height: 180px;}")
            # loading.exec_()
            process.start()
            # while (process.is_alive):
            #    continue
            # process.join()
            # loading.stopAnim()
            # loading.close()
            # Notification

            # dlg = QMessageBox(self)
            # dlg.setWindowTitle("Notification")
            # dlg.setText("Host discovery complete")
            # dlg.exec_()

        # input network adress: input host adresses manually / auto detection
        # IP: IPv4 / IPv6 (not implemented)
        # Enable OS detection?
        # Enable port service discovery?

    def vulnerability_scan(self):
        hosts = '127.0.0.1'
        if (not self.vuln_scan.network_cb.clicked):
            hosts = self.vuln_scan.network_input.text
            if (not re.fullmatch('^\d{1,3}\.\d{1,3}\.\d{1,3}\.$', hosts)):
                hosts = discoverer.get_network_local_IPV4()
        else:
            hosts = discoverer.get_network_local_IPV4()
        args = ''

        print(hosts)

        # netscanner.scan_placeholder(hosts)

        dlg = QMessageBox(self)
        dlg.setWindowTitle("Notification")
        dlg.setText("Vulnerability scan complete")
        dlg.exec_()

        # Form
        # input network adress: input host adresses manually / auto detection
        # IP: IPv4 / IPv6 (not implemented)
        # Choose scan mechanism:
        # >Nmap:
        # >>Choose scan script:
        # >>>vulscan:
        # >>>>download latest CVE library? (*Note*: requires admin permissions)
        # >>>vulners
        # >>>vuln
        # >Shodan (requires API key + tokens) (not implemented)
        # Choose vulnerability metric:
        # >CVE - CVSS
        return None

    def update_cve_db(self):
        # https://www.cve.org/Downloads
        # https://scipag.github.io/vulscan/
        # https://cve.mitre.org/data/downloads/allitems.csv

        source_url = "https://cve.mitre.org/data/downloads/allitems.csv"

        df = pd.read_csv(source_url)
        df.to_csv('./temp/allitems.csv')

        dlg = QMessageBox(self)
        dlg.setWindowTitle("Notification")
        dlg.setText("Update complete")
        dlg.exec_()

    def clear_cache(self):
        for filename in os.listdir('./temp/'):
            if (filename == 'cve-cvss-db.csv'):
                continue
            # os.remove(filename)
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Notification")
        dlg.setText("Cache cleared")
        dlg.exec_()
