import QtQuick
import QtQuick.Layouts
import Protect3Theme

Rectangle {
    id: toast
    property string message: ""
    property string kind: "info" // info, success, warn, error
    property bool showing: false

    readonly property color tint: {
        switch (kind) {
        case "success": return Theme.accent
        case "warn": return Theme.warn
        case "error": return Theme.danger
        default: return Theme.info
        }
    }

    width: Math.min(460, Math.max(240, row.implicitWidth + 28))
    height: row.implicitHeight + 20
    radius: Theme.radMd
    color: Theme.bgElevated
    border.width: 1
    border.color: tint
    visible: opacity > 0.01
    opacity: showing ? 1.0 : 0.0

    transform: Translate {
        y: toast.showing ? 0 : 14
        Behavior on y { NumberAnimation { duration: Theme.durPanel; easing.type: Easing.OutCubic } }
    }

    Behavior on opacity { NumberAnimation { duration: Theme.durPanel } }

    function show(msg, msgKind) {
        message = msg
        kind = msgKind || "info"
        showing = true
        timer.restart()
    }

    Timer {
        id: timer
        interval: 3800
        onTriggered: toast.showing = false
    }

    RowLayout {
        id: row
        anchors.fill: parent
        anchors.margins: 10
        spacing: 8

        Rectangle {
            width: 4
            height: Math.max(18, txt.implicitHeight)
            radius: 2
            color: toast.tint
        }

        Text {
            id: txt
            Layout.fillWidth: true
            text: toast.message
            color: Theme.textPrimary
            font.family: Theme.fontUi
            font.pixelSize: Theme.typeBody
            wrapMode: Text.WordWrap
        }

        StudioButton {
            text: "Đóng"
            variant: "ghost"
            compact: true
            onClicked: toast.showing = false
        }
    }
}
