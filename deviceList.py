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
import pandas as pd
import json

class DeviceList(QWidget):
    def __init__(self):
        super().__init__()
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

    def __get_device_stats(device):
        df = pd.read_csv('./temp/scan.csv')
        stats = df.loc[df['host'] == device]
        return stats

    def __create_device_info_widget(self, device):
        device_info = QWidget(self)
        info_layout = QGridLayout()
        device_info.setLayout(info_layout)

        piechart = __get_vuln_pie_chart(device_info, device)

        info_layout.addWidget(piechart, 0, 0)

        vuln_list = QListWidget(device_info)

        return None
    
    def __get_vuln_pie_chart(widget, device):
        return None
    
    def __vuln_list_item_clicked(widget, item):
        vuln_desc = __get_vuln_info(item.text())
        cve_widget = QWidget()
        widget.info_layout.addWidget()

    def __get_vuln_info(cve):
        info = fetcher.get_CVE_info_from_NIST_JSON(cve)
        return info