import sys
from PySide6.QtCore import QPointF, Qt
from PySide6.QtWidgets import (QApplication, QMainWindow, QSizePolicy,
                               QWidget, QGridLayout, QTabWidget)
from PySide6.QtCharts import QChart, QChartView, QPieSeries
from PySide6 import QtGui

import pandas as pd
from random import random, uniform
from deviceList import DeviceList

import netScanner as netscanner
from newScan import ScanOptions


class SystemStats(QWidget):
    def __init__(self):
        super().__init__()
        # self.setWindowTitle('IoT Monitor')
        # QWidget.__init__(self, parent)

        self.charts = []
        self.vulns = self.__load_vuln_data()
        self.hosts = self.__load_host_data()
        self.init_UI()

        self.show()

    def init_UI(self):
        def create_chart_view(chart, x, y, legend_alignment=Qt.AlignRight):
            chart_view = QChartView(chart)
            chart_view.setSizePolicy(QSizePolicy.Ignored,
                                     QSizePolicy.Ignored)

            chart_view.chart().legend().setAlignment(legend_alignment)
            stats_layout.addWidget(chart_view, x, y)
            system_stats_page.charts.append(chart_view)

        main_layout = QGridLayout(self)  # app layout (not just the main page)
        self.setLayout(main_layout)

        # TODO: move to a separate class
        tab = QTabWidget(self)
        system_stats_page = QWidget(self)  # main page (for the tabs)
        stats_layout = QGridLayout()
        system_stats_page.setLayout(stats_layout)
        system_stats_page.charts = []

        # pie chart for cvss scores
        try:
            create_chart_view(self.__create_vuln_pie_chart(), 1, 0)
        except:
            print('Vulnerability data not found')

        create_chart_view(self.__create_os_pie_chart(), 1, 1, Qt.AlignBottom)
        create_chart_view(self.__create_vendor_pie_chart(), 2, 0)
        create_chart_view(self.__create_ports_pie_chart(), 2, 1)

        device_list = DeviceList()
        new_scan = ScanOptions()

        tab.addTab(system_stats_page, self.tr('System stats'))
        tab.addTab(device_list, self.tr('Device list'))
        tab.addTab(new_scan, self.tr('New scan'))

        main_layout.addWidget(tab, 0, 0, 2, 1)

    # possible interfaces

    # systemStats.py
    # def __get_os_stats(self):
    # def __get_vuln_stats(self):
    # def __get_ports_stats(self):
    # def __get_device_stats(self):
    # def __get_cvss_scores():
    # def __switch_to_piechart(widget):
    # def __switch_to_bargraph(widget):

    # deviceList.py
    # def __get_device_list(self):
    # def __get_device_stats(self):
    # def __create_device_info_widget(device):
    # def __get_vuln_pie_chart():
    # def __get_vuln_info():

    # newScan.py
    # def __full_scan():
    # def __discover_hosts():
    # def scan():

    # https://www.pythontutorial.net/pyqt/pyqt-qtabwidget/

    def __load_vuln_data(self):
        # return pd.read_csv('./temp/scan.csv')
        return netscanner.get_vuln_scan_result()

    def __load_host_data(self):
        return netscanner.get_host_scan_result()

    def __create_vuln_pie_chart(self):
        chart = QChart()
        chart.setTitle(self.tr('Vulnerabilities, CVSS Scores'))
        series = QPieSeries(chart)
        df_cvss = pd.read_csv('./temp/cve-cvss-db.csv')
        low = med = high = crit = 0
        average = 0
        # TODO: cache the result into a temp file
        for cvss in df_cvss['CVSS'].values:
            try:
                cvss = float(cvss)
            except:
                cvss = 0
            average += cvss
            match cvss:
                case score if 0 <= score < 4:
                    low += 1
                case score if 4 <= score < 7:
                    med += 1
                case score if 7 <= score < 9:
                    high += 1
                case _:
                    crit += 1

        average = average / len(df_cvss['CVSS'].values)

        series.append(f'Low: {low}', low)
        series.append(f'Medium: {med}', med)
        series.append(f'High: {high}', high)
        series.append(f'Critical: {crit}', crit)
        series.setPieSize(1)
        chart.addSeries(series)
        # should return chartview instead of chart (or should it not?) ?
        return chart
        # maybe should leave it as it is

    def __create_vendor_pie_chart(self):
        if (self.hosts == None and self.vulns == None):
            return

        if (self.vulns != None):
            hosts = self.vulns
        else:
            hosts = self.hosts['scan']

        chart = QChart()
        chart.setTitle(self.tr('Vendors'))
        series = QPieSeries(chart)
        vendor_dict = dict()

        for host in hosts.keys():
            try:
                vendor = hosts[host]['vendor']
            except:
                vendor = self.tr('Unknown vendor')
            if (vendor == {}):
                vendor = self.tr('Unknown vendor')

            if (type(vendor) == dict):
                key = list(vendor.keys())[0]
                vendor = vendor[key]

            if (vendor in vendor_dict.keys()):
                vendor_dict[vendor] += 1
            else:
                vendor_dict[vendor] = 1

        for vendor in vendor_dict.keys():
            series.append(
                vendor + f': {vendor_dict[vendor]}', vendor_dict[vendor])

        series.setPieSize(1)
        chart.addSeries(series)
        return chart

    def __create_ports_pie_chart(self):
        if (self.hosts == None and self.vulns == None):
            return

        if (self.vulns != None):
            hosts = self.vulns
        else:
            hosts = self.hosts['scan']

        chart = QChart()
        chart.setTitle(self.tr('Open ports'))  # services?
        series = QPieSeries(chart)
        ports_dict = dict()

        port_types = ['tcp', 'udp']

        for host in hosts.keys():
            for port_type in port_types:
                try:
                    port_list = hosts[str(host)][port_type].keys()
                except:
                    continue

                for port in port_list:
                    if (hosts[host][port_type][port]['state'] == 'open'):
                        openport = str(port) + '/' + port_type

                        if (openport in ports_dict.keys()):
                            ports_dict[openport] += 1
                        else:
                            ports_dict[openport] = 1

        for port in ports_dict.keys():
            series.append(port + f': {ports_dict[port]}', ports_dict[port])

        series.setPieSize(1)
        chart.addSeries(series)
        return chart

    def __create_os_pie_chart(self):
        if (self.hosts == None and self.vulns == None):
            return

        if (self.vulns != None):
            hosts = self.vulns
        else:
            hosts = self.hosts['scan']

        chart = QChart()
        chart.setTitle(self.tr('OS'))
        series = QPieSeries(chart)
        os_dict = dict()

        for host in hosts.keys():
            try:
                os = hosts[host]['osmatch'][0]['name']
            except:
                os = self.tr('Unknown OS')

            if (os in os_dict.keys()):
                os_dict[os] += 1
            else:
                os_dict[os] = 1

        for os in os_dict.keys():
            series.append(os + f': {os_dict[os]}', os_dict[os])

        # series.append('Unknown OS: 1', 1)
        # for data in self.hosts['']:
        #    series.append(data[1], data[0].y())
        series.setPieSize(1)
        chart.addSeries(series)
        return chart

# if __name__ == "__main__":
#    app = QApplication(sys.argv)
#    window = QMainWindow()
#    window.setWindowTitle('Iot monitor')
#    window.setWindowIcon(QtGui.QIcon('./images/logo_new.png'))
#    widget = SystemStats()
#    window.setCentralWidget(widget)
#    available_geometry = window.screen().availableGeometry()
#    width = available_geometry.width()
#    height = available_geometry.height()
#    window.setMinimumSize(width * 0.5, height * 0.5)
#    window.setFixedSize(width * 0.8, height * 0.85)
#    window.show()
#    sys.exit(app.exec())
