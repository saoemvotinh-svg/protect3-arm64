import QtQuick
import QtQuick.Controls.Basic
import Protect3Theme

Button {
    id: control
    property string variant: "secondary" // primary, secondary, ghost, danger
    property string iconName: ""
    property bool compact: false

    implicitHeight: Math.round((compact ? 30 : 38) * Math.min(1.25, Theme.fontScale))
    implicitWidth: Math.max(compact ? 66 : 100, contentRow.implicitWidth + (compact ? 20 : 28))
    focusPolicy: Qt.StrongFocus
    hoverEnabled: true

    readonly property color baseFill: {
        if (!enabled) return Theme.bgElevated
        switch (variant) {
        case "primary": return down ? Qt.darker(Theme.accent, 1.15) : (hovered ? Theme.accentHover : Theme.accent)
        case "danger": return down ? Qt.darker(Theme.dangerDim, 1.1) : (hovered ? Theme.dangerHover : Theme.dangerDim)
        case "ghost": return down ? Theme.bgHover : (hovered ? Theme.bgElevated : "transparent")
        default: return down ? Theme.bgHover : (hovered ? Theme.bgHover : Theme.bgElevated)
        }
    }

    readonly property color fgColor: {
        if (!enabled) return Theme.textMuted
        if (variant === "primary") return Theme.accentText
        if (variant === "danger") return Theme.danger
        return Theme.textPrimary
    }

    scale: !Theme.reducedMotion && pressed && enabled ? 0.985 : 1.0
    Behavior on scale { NumberAnimation { duration: Theme.durMicro; easing.type: Easing.OutCubic } }

    background: Rectangle {
        radius: Theme.radSm
        color: control.baseFill
        border.width: control.visualFocus || variant !== "ghost" ? 1 : 0
        border.color: {
            if (control.visualFocus) return Theme.borderFocus
            if (!control.enabled) return Theme.borderSubtle
            if (variant === "primary") return Theme.accent
            if (variant === "danger") return Qt.rgba(Theme.danger.r, Theme.danger.g, Theme.danger.b, 0.45)
            return control.hovered ? Theme.borderStrong : Theme.borderSubtle
        }
        Behavior on color { ColorAnimation { duration: Theme.durMicro } }
        Behavior on border.color { ColorAnimation { duration: Theme.durMicro } }
    }

    contentItem: Row {
        id: contentRow
        spacing: 6
        anchors.centerIn: parent

        Loader {
            active: control.iconName !== ""
            visible: active
            anchors.verticalCenter: parent.verticalCenter
            sourceComponent: StudioIcon {
                name: control.iconName
                size: control.compact ? 13 : 15
                color: control.fgColor
            }
        }

        Text {
            text: control.text
            color: control.fgColor
            font.family: Theme.fontUi
            font.pixelSize: control.compact ? Theme.typeSmall : Theme.typeBody
            font.weight: variant === "primary" ? Font.DemiBold : Font.Medium
            anchors.verticalCenter: parent.verticalCenter
            elide: Text.ElideRight
        }
    }
}
