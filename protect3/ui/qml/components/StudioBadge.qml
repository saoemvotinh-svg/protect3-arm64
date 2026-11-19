import QtQuick
import Protect3Theme

Rectangle {
    id: root
    property string text: ""
    property string tone: "neutral" // neutral, accent, info, warn, danger, violet
    property bool monospace: false

    readonly property color fillColor: {
        switch (tone) {
        case "accent": return Theme.accentDim
        case "info": return Theme.infoDim
        case "warn": return Theme.warnDim
        case "danger": return Theme.dangerDim
        case "violet": return Theme.violetDim
        default: return Theme.bgElevated
        }
    }

    readonly property color labelColor: {
        switch (tone) {
        case "accent": return Theme.accent
        case "info": return Theme.info
        case "warn": return Theme.warn
        case "danger": return Theme.danger
        case "violet": return Theme.violet
        default: return Theme.textSecondary
        }
    }

    implicitWidth: Math.max(26, lbl.implicitWidth + 16)
    implicitHeight: Math.round(24 * Math.min(1.25, Theme.fontScale))
    radius: Theme.radPill
    color: fillColor
    border.width: 1
    border.color: tone === "neutral" ? Theme.borderSubtle : Qt.rgba(labelColor.r, labelColor.g, labelColor.b, 0.35)

    Text {
        id: lbl
        anchors.centerIn: parent
        text: root.text
        color: root.labelColor
        font.family: root.monospace ? Theme.fontMono : Theme.fontUi
        font.pixelSize: Theme.typeCaption
        font.weight: Font.DemiBold
    }
}
