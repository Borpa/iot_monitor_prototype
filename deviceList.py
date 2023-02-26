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
        self.__init_ui()
        self.show()

    def __init_ui(self):
        main_layout = QGridLayout()
        self.setLayout(main_layout)

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
    
    def __get_vuln_pie_chart(widget, device):
        chart = QChart()
        chart.setTitle("Vulnerabilities")

        series = QPieSeries(chart)
        
        df = pd.read_csv('./temp/scan.csv')
        cve_list = df['CVE'].loc[df['host'] == device]
        cve_list = ast.literal_eval(cve_list)
        df_cvss = pd.read_csv('./temp/cve-cvss-db.csv')
        
        #Low 0 3.9
        #Medium 4 6.9 
        #High 7 8.9
        #Critical 9 10

        low = []
        med = []
        high = []
        crit = []

        average = 0

        for cve in cve_list:
            cvss = df_cvss['CVSS'].loc[df_cvss['CVE'] == cve]
            cvss = float(cvss)
            average += cvss

            match cvss:
                case score if score in np.arange(0, 4, 0.1):
                    low.append(1)
                case score if score in np.arange(4, 7, 0.1):
                    med.append(1)
                case score if score in np.arange(7, 9, 0.1):
                    high.append(1)
                case _:
                    crit.append(1)

        series.append('Low', low)
        series.append('Medium', med)
        series.append('High', high)
        series.append('Critical', crit)

        average = average / len(cve_list)

        series.setPieSize(1)
        chart.addSeries(series)

        return None
    
    def __vuln_list_item_clicked(widget, item):
        vuln_desc = __get_vuln_info(item.text())['description']
        cve_widget = QWidget()
        widget.info_layout.addWidget()

    def __get_vuln_info(cve):
        info = fetcher.get_CVE_details(cve)
        score = fetcher.get_CVSS_score(cve)
        return {'description': info, 'cvss score': score}