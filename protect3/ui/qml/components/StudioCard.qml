import QtQuick
import QtQuick.Layouts
import Protect3Theme

Rectangle {
    id: root
    property string title: ""
    property string subtitle: ""
    property string badgeText: ""
    property string badgeTone: "neutral"
    default property alias contentData: innerCol.data

    color: Theme.bgSurface
    radius: Theme.radMd
    border.width: 1
    border.color: Theme.borderSubtle
    clip: true
    implicitWidth: 240
    implicitHeight: layoutCol.implicitHeight + Theme.sp16 * 2
    Layout.minimumWidth: 0

    ColumnLayout {
        id: layoutCol
        anchors.fill: parent
        anchors.margins: Theme.sp16
        spacing: Theme.sp12

        RowLayout {
            Layout.fillWidth: true
            visible: root.title !== "" || root.badgeText !== ""
            spacing: Theme.sp8

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2

                Text {
                    text: root.title
                    visible: text !== ""
                    color: Theme.textPrimary
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.typeHeading
                    font.weight: Font.DemiBold
                    Layout.fillWidth: true
                    elide: Text.ElideRight
                }

                Text {
                    text: root.subtitle
                    visible: text !== ""
                    color: Theme.textSecondary
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.typeSmall
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }

            StudioBadge {
                visible: root.badgeText !== ""
                text: root.badgeText
                tone: root.badgeTone
            }
        }

        ColumnLayout {
            id: innerCol
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.minimumWidth: 0
            spacing: Theme.sp12
        }
    }
}
