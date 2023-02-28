import sys
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPalette
from PySide6.QtWidgets import (QApplication, QMainWindow, QSizePolicy,
    QWidget, QGridLayout, QPushButton, QHBoxLayout, QLabel, QTabWidget,
    QFormLayout, QLineEdit, QListWidget, QDialog, QPlainTextEdit)
from PySide6.QtCharts import (QAreaSeries, QBarSet, QChart, QChartView,
                              QLineSeries, QPieSeries, QScatterSeries,
                              QSplineSeries, QStackedBarSeries)
from PySide6 import QtGui

import cveFetcher as fetcher
import netScanner as netscanner
import pandas as pd
import json
import ast
import os

class CveBrower(QDialog):
    def __init__(self, device, cvss_rating):
        super().__init__()
        self.device = device
        self.cvss_rating = cvss_rating

        self.__init_ui()
        self.setWindowTitle(f'CVE browser, rating: {cvss_rating}')
        self.setFixedSize(720, 480)
        self.show()

    def __init_ui(self):
        self.main_layout = QGridLayout()
        self.setLayout(self.main_layout)

        cve_list = self.__create_cve_list_widget(self.device)
        self.main_layout.addWidget(cve_list, 0, 0)
        self.main_layout.addWidget(QWidget(), 0, 1)
        

    def __create_cve_list_widget(self, device):
        list_widget = QListWidget(self)
        #df = pd.read_csv('./temp/scan.csv')
        #df = pd.read_json(f'./temp/{self.device}_cve.json')

        f = open (f'./temp/{self.device}_cve.json', 'r')
        data = json.loads(f.read())

        rating = self.cvss_rating.replace(':', '')
        rating = rating.split()[0]
        rating = rating.lower()
        if (rating == 'medium'): rating = 'med'
        if (rating == 'critical'): rating = 'crit'

        cve_list = data[rating]

        f.close()

        #cve_list = str(cve_list[0])
        #cve_list = ast.literal_eval(cve_list)
        for cve in cve_list:
            list_widget.addItem(cve)
        list_widget.itemClicked.connect(self.__cve_list_item_clicked)

        list_widget.setFixedWidth(200)

        return list_widget

    def __cve_list_item_clicked(self, item):
        qtext = QPlainTextEdit()
        qtext.setFixedHeight(700)
        qtext.setReadOnly(True)
        desc = fetcher.get_CVE_details(item.text())
        
        qtext.setPlainText(f'Rating: {fetcher.get_CVSS_score(item.text())} \nDescription:{desc}')
        self.main_layout.addWidget(qtext, 0, 1)