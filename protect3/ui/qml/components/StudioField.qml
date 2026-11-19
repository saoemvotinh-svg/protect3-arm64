import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts
import Protect3Theme

ColumnLayout {
    id: root
    property string label: ""
    property string placeholder: ""
    property alias text: input.text
    property bool monospace: false
    property bool readOnly: false
    property string conflictText: ""
    readonly property bool hasConflict: conflictText !== ""
    signal acceptedText(string value)
    signal editedText(string value)

    spacing: 4
    Layout.minimumWidth: 0

    Text {
        visible: root.label !== ""
        text: root.label
        color: root.hasConflict ? Theme.danger : Theme.textSecondary
        font.family: Theme.fontUi
        font.pixelSize: Theme.typeSmall
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }

    TextField {
        id: input
        Layout.fillWidth: true
        Layout.minimumWidth: 0
        implicitWidth: 120
        implicitHeight: Math.round(38 * Math.min(1.25, Theme.fontScale))
        placeholderText: root.placeholder
        placeholderTextColor: Theme.textMuted
        color: Theme.textPrimary
        selectedTextColor: Theme.accentText
        selectionColor: Theme.accent
        readOnly: root.readOnly
        font.family: root.monospace ? Theme.fontMono : Theme.fontUi
        font.pixelSize: root.monospace ? Theme.typeMono : Theme.typeBody
        leftPadding: 10
        rightPadding: 10

        background: Rectangle {
            radius: Theme.radSm
            color: root.hasConflict ? Theme.dangerDim : Theme.bgInput
            border.width: 1
            border.color: root.hasConflict ? Theme.danger : (input.activeFocus ? Theme.borderFocus : Theme.borderSubtle)
        }

        onTextEdited: root.editedText(text)
        onEditingFinished: root.acceptedText(text)
    }

    Text {
        visible: root.hasConflict
        text: root.hasConflict ? ("✕ " + root.conflictText) : ""
        color: Theme.danger
        font.family: Theme.fontUi
        font.pixelSize: Theme.typeCaption
        font.weight: Font.DemiBold
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }
}
