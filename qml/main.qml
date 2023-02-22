import QtQuick 2.15
import QtQuick.Window 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15

ApplicationWindow{
    id: window
    width: 400
    height: 500
    visible: true
    title: qsTr("Login page")

    Material.theme: Material.Dark
    Material.accent: Material.LightBlue

    flags: Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint | Qt.CustomizeWindowHint | Qt.MSWindowsFixedSizeDialogHint | Qt.WindowTiltHint


    QtObject{
        id: internal
        property string user: "login"
        property string pass: "pass"

        function checkLogin(username, password){
            if (username === user && password === pass){
                var component = Qt.createComponent("app.qml")
                var win = component.createObject()
                win.show()
                visible = false
            }
            else{
                if (username != user){
                    usernameField.Material.foreground = Material.Pink
                    usernameField.Material.accent = Material.Pink
                }
                else{
                    usernameField.Material.foreground = Material.LightBlue 
                    usernameField.Material.accent = Material.LightBlue
                }
            }
        }
    }

    Rectangle {
        id: topBar
        height: 40
        color: Material.color(Material.Blue)
        anchors{
            top: parent.top
            left: parent.left
            right: parent.right
            margins:10
        }
        radius: 10
        
        Text {
            text: qsTr("Hello world")
            anchors.verticalCenter: parent.verticalCenter
            anchors.horizontalCenter: parent.horizontalCenter
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            color: "#ffffff"
            font.pointSize: 12       
        }
    }

    Image {
        id: image
        width: 200
        height: 100
        source: "../images/logo.png"
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: topBar.bottom
        anchors.topMargin: 60
    }

    TextField {
        id: usernameField
        width: 300
        text: qsTr("")
        selectByMouse: true
        placeholderText: qsTr("Username or email")
        verticalAlignment: Text.AlignVCenter
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: image.bottom
        anchors.topMargin: 60
    }
    TextField {
        id: passwordField
        width: 300
        text: qsTr("")
        selectByMouse: true
        placeholderText: qsTr("Password")
        verticalAlignment: Text.AlignVCenter
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: usernameField.bottom
        anchors.topMargin: 10
        echoMode: TextInput.Password
    }

    CheckBox{
        id: checkbox
        text: qsTr("Save password")
        anchors.top: passwordField.bottom
        anchors.topMargin: 10
        anchors.horizontalCenter: parent.horizontalCenter
    }

    Button{
        id: buttonLogin
        width: 300
        text: qsTr("Login")
        anchors.top: checkbox.bottom
        anchors.topMargin: 10

        anchors.horizontalCenter: parent.horizontalCenter

        onClicked: internal.checkLogin(usernameField.text, passwordField.text)
    }
}