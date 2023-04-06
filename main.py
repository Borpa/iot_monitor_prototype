import sys
from PySide6.QtWidgets import QApplication, QMainWindow
from PySide6 import QtGui

from Iot_monitor import SystemStats

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QMainWindow()
    window.setWindowTitle('Iot monitor')
    window.setWindowIcon(QtGui.QIcon('./images/logo_new.png'))
    widget = SystemStats()
    window.setCentralWidget(widget)
    available_geometry = window.screen().availableGeometry()
    width = available_geometry.width()
    height = available_geometry.height()
    window.setMinimumSize(width * 0.5, height * 0.5)
    window.setFixedSize(width * 0.8, height * 0.85)
    window.show()
    sys.exit(app.exec())
