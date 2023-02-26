import sys
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPalette
from PySide6.QtWidgets import (QApplication, QMainWindow, QSizePolicy,
    QWidget, QGridLayout, QPushButton, QHBoxLayout, QLabel, QTabWidget,
    QFormLayout, QLineEdit, QListWidget)
from PySide6.QtCharts import (QAreaSeries, QBarSet, QChart, QChartView,
                              QLineSeries, QPieSeries, QScatterSeries,
                              QSplineSeries, QStackedBarSeries)
from PySide6 import QtGui

import cveFetcher as fetcher
import netScanner as scanner
import pandas as pd
import numpy as np
import ast

class DeviceList(QWidget):
    def __init__(self):
        super().__init__()
        self.hosts = scanner.get_host_scan_result()
        self.charts = []
        self.__init_ui()
        self.show()

    def __init_ui(self):
        main_layout = QGridLayout()
        self.setLayout(main_layout)

        chart_view = QChartView(self.__get_vuln_pie_chart('192.168.3.12'))
        chart_view.setSizePolicy(QSizePolicy.Ignored,
                                 QSizePolicy.Ignored)
        
        chart_view.chart().legend().setAlignment(Qt.AlignRight)
        main_layout.addWidget(chart_view, 0, 0)
        self.charts.append(chart_view)

    def __get_device_list():
        return None
    
    def __create_device_list_widget(self):
        list_widget = QListWidget(self)
        device_list = self.__get_device_list()
        for device in device_list:
            list_widget.addItem(device.Name)
        list_widget.itemClicked.connect(self.__device_list_item_clicked)

        return list_widget
    
    def __device_list_item_clicked(self, item):
        device = __get_device_stats(item.text())
        __create_device_info_widget(self, device)

    def __get_device_stats(self, device):
        #df = pd.read_csv('./temp/scan.csv')
        #stats = df.loc[df['host'] == device]
        stats = self.hosts[device]
        ports = stats['tcp'].keys()
        cols = ['state', 'name', 'product', 'version']
        df = pd.DataFrame(columns=cols)

        for port in ports:
            state = stats['tcp'][port]['state']
            name = stats['tcp'][port]['name']
            product = stats['tcp'][port]['product']
            version = stats['tcp'][port]['version']
            df = df.append(pd.DataFrame([state, name, product, version], 
                                        columns=cols), ignore_index=True)
        return df

    def __create_device_info_widget(self, device):
        device_info = QWidget(self)
        info_layout = QGridLayout()
        device_info.setLayout(info_layout)

        piechart = __get_vuln_pie_chart(device_info, device)

        info_layout.addWidget(piechart, 0, 0)

        vuln_list = QListWidget(device_info)

        return None
    
    def __get_vuln_pie_chart(self, device):
        chart = QChart()
        chart.setTitle("Vulnerabilities, CVSS scores - {}".format(device))

        series = QPieSeries(chart)
        
        df = pd.read_csv('./temp/scan.csv')
        cve_list = df['CVE'].loc[df['host'] == device].values

        cve_list = str(cve_list[0])
        cve_list = ast.literal_eval(cve_list)
        df_cvss = pd.read_csv('./temp/cve-cvss-db.csv')

        #Low 0 3.9
        #Medium 4 6.9 
        #High 7 8.9
        #Critical 9 10
        low = med = high = crit = 0

        average = 0

        for cve in cve_list:
            row = df_cvss.loc[df_cvss['CVE'] == cve]
            cvss = row['CVSS'].values
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

        series.append('Low: {}'.format(low), low)
        series.append('Medium: {}'.format(med), med)
        series.append('High: {}'.format(high), high)
        series.append('Critical: {}'.format(crit), crit)

        average = average / len(cve_list)

        series.setPieSize(1)
        chart.addSeries(series)

        return chart
    
    def __vuln_list_item_clicked(widget, item):
        vuln_desc = __get_vuln_info(item.text())['description']
        cve_widget = QWidget()
        widget.info_layout.addWidget()

    def __get_vuln_info(cve):
        info = fetcher.get_CVE_details(cve)
        score = fetcher.get_CVSS_score(cve)
        return {'description': info, 'cvss score': score}