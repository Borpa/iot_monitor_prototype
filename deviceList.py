import sys
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPalette
from PySide6.QtWidgets import (QApplication, QMainWindow, QSizePolicy,
    QWidget, QGridLayout, QPushButton, QHBoxLayout, QLabel, QTabWidget,
    QFormLayout, QLineEdit, QListWidget, QPlainTextEdit)
from PySide6.QtCharts import (QAreaSeries, QBarSet, QChart, QChartView,
                              QLineSeries, QPieSeries, QScatterSeries,
                              QSplineSeries, QStackedBarSeries)
from PySide6 import QtGui

import json

import cveFetcher as fetcher
import netScanner as netscanner
from cveBrowser import CveBrower as browser
import pandas as pd
import ast
import os


#TODO: move out the json init to other class 
class DeviceList(QWidget):
    def __handle_double_clicked(self, slice):
        #print(slice.label(), slice.value())
        #print(self.current_device)

        bwr = browser(device=self.current_device, cvss_rating=slice.label())
        bwr.exec_()

    def __init__(self):
        super().__init__()
        self.hosts = netscanner.get_host_scan_result()
        self.charts = []
        self.current_device = ''
        self.__init_ui()
        self.show()

    def __init_ui(self):
        self.main_layout = QGridLayout()
        self.setLayout(self.main_layout)

        device_list = self.__create_device_list_widget()
        self.main_layout.addWidget(device_list, 0, 0)
        self.main_layout.addWidget(QWidget(), 0, 1)
    
    def __create_device_list_widget(self):
        list_widget = QListWidget(self)
        df = pd.read_csv('./temp/scan.csv')
        device_list = df['host'].values.tolist()
        for device in device_list:
            list_widget.addItem(device)
        list_widget.itemClicked.connect(self.__device_list_item_clicked)

        list_widget.setFixedWidth(300)

        return list_widget
    
    def __device_list_item_clicked(self, item):
        self.current_device = item.text()

        #device = self.__get_device_stats(item.text())
        #self.__create_device_info_widget(device)
        chart = self.__get_cvss_pie_chart(item.text())
        chart_view = QChartView(chart)
        chart_view.setSizePolicy(QSizePolicy.Ignored,
                                 QSizePolicy.Ignored)
        
        chart_view.chart().legend().setAlignment(Qt.AlignRight)

        device_info = QWidget(self)
        device_info_layout = QGridLayout()
        device_info.setLayout(device_info_layout)
        device_info_layout.addWidget(chart_view, 0, 0)
        qtext = QPlainTextEdit()
        qtext.setFixedHeight(200)
        qtext.setReadOnly(True)

        stats = self.__get_device_stats(item.text())
        qtext.setPlainText(stats.to_string(col_space=30, justify='justify-all'))

        device_info_layout.addWidget(qtext, 1, 0)
        
        #cve_list = self.__create_cve_list_widget(item.text())

        

        #cve_widget = QWidget()
        #cve_layout = QGridLayout()
        #cve_widget.setLayout(cve_layout)

        #cve_layout.addWidget(cve_list, 0, 0)


        #device_info_layout.addWidget(cve_list, 1, 0)
        #cve = self.__create_cve_list_widget(item.text())
        #cve.setFixedWidth(200)
        #cve.setFixedHeight(200)
        #desc = QLineEdit(device_info)
        #desc.setFixedWidth(200)
        #desc.setReadOnly(True)
        #self.main_layout.addWidget(cve, 0, 2)
        #self.main_layout.addWidget(desc, 1, 2)
        self.main_layout.addWidget(device_info, 0, 1)
        

    def __create_cve_list_widget(self, device):
        list_widget = QListWidget(self)
        df = pd.read_csv('./temp/scan.csv')
        cve_list = df['CVE'].loc[df['host'] == device].values
        cve_list = str(cve_list[0])
        cve_list = ast.literal_eval(cve_list)
        for cve in cve_list:
            list_widget.addItem(cve)
        list_widget.itemClicked.connect(self.__cve_list_item_clicked)

        return list_widget

    def __cve_list_item_clicked(self, item):
        return None

    def __get_device_stats(self, device):
        #df = pd.read_csv('./temp/scan.csv')
        #stats = df.loc[df['host'] == device]
        
        #stats = self.hosts[device]
        #ports = stats['tcp'].keys()

        stats = netscanner.get_vuln_scan_result()
        stats = stats[device]
        ports = stats['tcp'].keys()

        cols = ['port', 'state', 'name', 'product', 'version']
        #df = pd.DataFrame(columns=cols)

        prt = []
        state = []
        name = []
        product = []
        version = []

        for port in ports:
            state.append(stats['tcp'][port]['state'])
            name.append(stats['tcp'][port]['name'])
            product.append(stats['tcp'][port]['product'])
            version.append(stats['tcp'][port]['version'])
            prt.append(str(port) + '/tcp')
            #row = [port, state, name, product, version]
            #row = list(map(lambda x:'-' if x == '' else x, row))
            #print(row)
            #df = df.append(pd.DataFrame({'port': port, 'state': state, 'name': name, 'product': product, 'version': version}, 
            #                           columns=cols), ignore_index=True)

        df = pd.DataFrame({'port': prt, 'state': state, 'name': name, 'product': product, 'version': version})
        return df

    def __get_device_OS_vendor(self, device):
        os = self.hosts[device]['osmatch']
        vendor = self.hosts[device]['vendor']
        return {'os':os,'vendor':vendor}

    def __create_device_info_widget(self, device):
        device_info = QWidget(self)
        info_layout = QGridLayout()
        device_info.setLayout(info_layout)

        piechart = self.__get_cvss_pie_chart(device)

        info_layout.addWidget(piechart, 0, 0)

        cve_list = QListWidget(device_info)

        return None
    
    def __get_cvss_pie_chart(self, device):    
        chart = QChart()
        chart.setTitle("Vulnerabilities, CVSS scores - {}".format(device))

        series = QPieSeries(chart)

        if (os.path.exists(f'./temp/{device}.json')):
            df = pd.read_json(f'./temp/{device}.json')
            low = df['low'].values
            med = df['med'].values
            high = df['high'].values
            crit = df['crit'].values

            series.append(f'Low: {low}', low)
            series.append(f'Medium: {med}', med)
            series.append(f'High: {high}', high)
            series.append(f'Critical: {crit}', crit)
            series.setPieSize(1)
            series.doubleClicked.connect(self.__handle_double_clicked)
            chart.addSeries(series)

            return chart
        
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
        cve_low = []
        cve_med = []
        cve_high = []
        cve_crit = []

        #average = 0
        #TODO: improve caching the result into a temp file
        for cve in cve_list:
            row = df_cvss.loc[df_cvss['CVE'] == cve]
            cvss = row['CVSS'].values
            try:
                cvss = float(cvss)
            except:
                cvss = 0
            #average += cvss
            match cvss:
                case score if 0 <= score < 4:
                    low += 1 
                    cve_low.append(cve)
                case score if 4 <= score < 7:
                    med += 1
                    cve_med.append(cve)
                case score if 7 <= score < 9:
                    high += 1
                    cve_high.append(cve) 
                case _:
                    crit += 1
                    cve_crit.append(cve)

        #average = average / len(df_cvss['CVSS'].values)

        series.append(f'Low: {low}', low)
        series.append(f'Medium: {med}', med)
        series.append(f'High: {high}', high)
        series.append(f'Critical: {crit}', crit)

        dict = {'low': [low], 'med': [med], 'high': [high], 'crit': [crit]}
        dict_cve = {'low': cve_low, 'med': cve_med, 'high': cve_high, 'crit': cve_crit}

        df_cache = pd.DataFrame(dict)
        df_cache.to_json(f'./temp/{device}.json')

        with open(f'./temp/{device}_cve.json', 'w') as outfile:
            json.dump(dict_cve, outfile)

        #df_cache_cve = pd.DataFrame(dict_cve)
        #df_cache_cve.to_json(f'./temp/{device}_cve.json')

        #average = average / len(cve_list)

        series.doubleClicked.connect(self.__handle_double_clicked)
        series.setPieSize(1)
        chart.addSeries(series)

        return chart

    def __vuln_list_item_clicked(widget, item):
        vuln_desc = widget.__get_vuln_info(item.text())['description']
        cve_widget = QWidget()
        widget.info_layout.addWidget()

    def __get_vuln_info(self, cve):
        info = fetcher.get_CVE_details(cve)
        score = fetcher.get_CVSS_score(cve)
        return {'description': info, 'cvss score': score}