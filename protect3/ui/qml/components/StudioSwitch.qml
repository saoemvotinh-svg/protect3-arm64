import QtQuick
import QtQuick.Layouts
import Protect3Theme

Rectangle {
    id: root
    property string title: ""
    property string subtitle: ""
    property string badgeText: ""
    property string badgeTone: "info"
    property bool checked: false
    property bool interactive: true
    property string conflictText: ""
    readonly property bool hasConflict: conflictText !== ""
    signal toggled(bool value)

    implicitWidth: 260
    implicitHeight: rowLayout.implicitHeight + 14
    Layout.fillWidth: true
    Layout.minimumWidth: 0
    Layout.minimumHeight: implicitHeight
    radius: Theme.radSm
    color: hasConflict
           ? Theme.dangerDim
           : (mouse.containsMouse && interactive ? Theme.bgElevated : Theme.bgInput)
    border.width: 1
    border.color: hasConflict
                  ? Theme.danger
                  : (checked ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.35) : Theme.borderSubtle)
    opacity: interactive ? 1.0 : 0.55

    RowLayout {
        id: rowLayout
        anchors.fill: parent
        anchors.leftMargin: 10
        anchors.rightMargin: 10
        anchors.topMargin: 7
        anchors.bottomMargin: 7
        spacing: 10

        ColumnLayout {
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            spacing: 2

            RowLayout {
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                spacing: 6

                Text {
                    text: root.title
                    color: Theme.textPrimary
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.typeBody
                    font.weight: Font.Medium
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                }

                StudioBadge {
                    visible: root.badgeText !== ""
                    text: root.badgeText
                    tone: root.badgeTone
                    monospace: true
                    Layout.alignment: Qt.AlignVCenter
                }
            }

                Text {
                    text: root.subtitle
                    visible: text !== ""
                    color: Theme.textMuted
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.typeCaption
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                Text {
                    text: root.hasConflict ? ("✕ " + root.conflictText) : ""
                    visible: root.hasConflict
                    color: Theme.danger
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.typeCaption
                    font.weight: Font.DemiBold
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
        }

        // Custom crisp switch track & thumb
        Rectangle {
            id: track
            implicitWidth: 38
            implicitHeight: 20
            Layout.preferredWidth: 38
            Layout.preferredHeight: 20
            Layout.alignment: Qt.AlignVCenter
            radius: 10
            color: root.checked ? Theme.accent : Theme.bgHover
            border.width: 1
            border.color: root.checked ? Theme.accent : Theme.borderStrong

            Rectangle {
                width: 14
                height: 14
                radius: 7
                y: 3
                x: root.checked ? track.width - width - 3 : 3
                color: root.checked ? Theme.accentText : Theme.textSecondary
                Behavior on x { NumberAnimation { duration: Theme.durMicro; easing.type: Easing.OutCubic } }
            }
        }
    }

    MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: true
        enabled: root.interactive
        cursorShape: Qt.PointingHandCursor
        onClicked: root.toggled(!root.checked)
    }
}
