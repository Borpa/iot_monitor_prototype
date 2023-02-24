import sys
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPalette
from PySide6.QtWidgets import (QApplication, QMainWindow, QSizePolicy,
    QWidget, QGridLayout, QPushButton, QHBoxLayout, QLabel)
from PySide6.QtCharts import (QAreaSeries, QBarSet, QChart, QChartView,
                              QLineSeries, QPieSeries, QScatterSeries,
                              QSplineSeries, QStackedBarSeries)
from random import random, uniform

class GridTest(QWidget):
    def __init__(self):
        super().__init__()
        #QWidget.__init__(self, parent)
        
        self.charts = []
        self.init_UI()
        self.setWindowTitle('IoT Monitor')  
        self.show()

    def init_UI(self):
        grid = QGridLayout()  

        self.list_count = 3
        self.value_max = 10
        self.value_count = 7
        self.data_table = self.generate_random_data(self.list_count,
            self.value_max, self.value_count)
        
        for i in range(1 ,3):
            for j in range(2):
                    chart_view = QChartView(self.create_pie_chart())
                    chart_view.setSizePolicy(QSizePolicy.Ignored,
                                             QSizePolicy.Ignored)
                    
                    chart_view.chart().legend().setAlignment(Qt.AlignRight)
                    #chart_view.chart().legend().show()
                    grid.addWidget(chart_view, i, j)
                    self.charts.append(chart_view)

        
        qbox = QHBoxLayout()

        buttonDevicesList = QPushButton()
        buttonDevicesList.setFixedHeight(20)
        buttonDevicesList.setMaximumWidth(300)
        buttonDevicesList.setText("Devices list")

        buttonNewScan = QPushButton()
        buttonNewScan.setFixedHeight(20)
        buttonNewScan.setMaximumWidth(300)
        buttonNewScan.setText("New scan")

        qbox.addWidget(buttonDevicesList)
        qbox.addWidget(buttonNewScan)
        
        grid.addLayout(qbox, 0 ,0)

        self.setLayout(grid)

        #self.horizontalLayout.setObjectName(u"horizontalLayout")
        #self.themeLabel = QLabel()
        #self.themeLabel.setObjectName(u"themeLabel")
        #self.themeLabel.setText("Hello world")
        #self.themeLabel.setFixedHeight(20)
        #self.horizontalLayout.addWidget(self.themeLabel)
        

        #self.themeComboBox = QComboBox()
        #self.themeComboBox.setObjectName(u"themeComboBox")

        #self.horizontalLayout.addWidget(self.themeComboBox)



        #gridMain = QGridLayout()

        #gridMain.addLayout(qbox, 0, 0)
        #gridMain.addLayout(grid, 1, 1)
        #gridMain.setColumnStretch(1, 1)


    def create_pie_chart(self):
        chart = QChart()
        chart.setTitle("Pie chart")

        series = QPieSeries(chart)
        for data in self.data_table[0]:
            slc = series.append(data[1], data[0].y())
            #if data == self.data_table[0][0]:
            #    # Show the first slice exploded with label
            #    slc.setLabelVisible()
            #    slc.setExploded()
            #    slc.setExplodeDistanceFactor(0.5)

        series.setPieSize(1)
        chart.addSeries(series)

        return chart

    def generate_random_data(self, list_count, value_max, value_count):
        data_table = []
        for i in range(list_count):
            data_list = []
            y_value = 0
            for j in range(value_count):
                constant = value_max / float(value_count)
                y_value += uniform(0, constant)
                x_value = (j + random()) * constant
                value = QPointF(x_value, y_value)
                label = f"Slice {i}: {j}"
                data_list.append((value, label))
            data_table.append(data_list)

        return data_table

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QMainWindow()
    widget = GridTest()
    window.setCentralWidget(widget)
    available_geometry = window.screen().availableGeometry()
    width = available_geometry.width()
    height = available_geometry.height()
    window.setMinimumSize(width * 0.5, height * 0.5)
    window.setFixedSize(width * 0.8, height * 0.85)
    window.show()
    sys.exit(app.exec())