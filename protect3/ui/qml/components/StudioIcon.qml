import QtQuick
import QtQuick.Shapes
import Protect3Theme

Item {
    id: root
    property string name: "shield"
    property int size: 16
    property color color: Theme.textPrimary

    implicitWidth: size
    implicitHeight: size
    width: size
    height: size

    readonly property string svgPath: {
        switch (name) {
        case "shield": return "M12 2L4 5v6c0 5.5 3.4 10.6 8 12 4.6-1.4 8-6.5 8-12V5l-8-3zm0 2.2l6 2.2v4.6c0 4.4-2.6 8.6-6 9.8-3.4-1.2-6-5.4-6-9.8V6.4l6-2.2z"
        case "radar": return "M12 2a10 10 0 1 0 10 10h-2a8 8 0 1 1-8-8V2zm0 4a6 6 0 1 0 6 6h-2a4 4 0 1 1-4-4V6zm1 6.4l3.8 2.2-1 1.7L11 13V7h2v5.4z"
        case "layers": return "M12 2L2 7l10 5 10-5-10-5zm0 12.6L4.2 10.7 2 11.8l10 5 10-5-2.2-1.1L12 14.6zm0 4.2L4.2 15 2 16l10 5 10-5-2.2-1.1L12 18.8z"
        case "bug": return "M19 8h-1.8c-.4-1-.9-1.8-1.7-2.4l1.2-1.2-1.4-1.4-1.5 1.5C13.2 4.2 12.6 4 12 4s-1.2.2-1.8.5L8.7 3 7.3 4.4l1.2 1.2C7.7 6.2 7.2 7 6.8 8H5v2h1.2c-.1.6-.2 1.3-.2 2H4v2h2v1c0 2.6 1.7 4.8 4 5.6V10h4v10.6c2.3-.8 4-3 4-5.6v-1h2v-2h-2c0-.7-.1-1.4-.2-2H19V8z"
        case "terminal": return "M3 4h18a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm1 2v12h16V6H4zm2.5 3.2L10.3 12l-3.8 2.8-1.2-1.6L7.5 12 5.3 10.8l1.2-1.6zM12 14h5v2h-5v-2z"
        case "gauge": return "M12 4a9 9 0 0 0-9 9c0 2.4.9 4.7 2.6 6.4l1.4-1.4A7 7 0 1 1 17 18l1.4 1.4A9 9 0 0 0 12 4zm4.2 5.2l-5 4.4a1.5 1.5 0 1 0 2.2 2l4.2-5-.4-.4-1-1z"
        case "play": return "M8 5v14l11-7-11-7z"
        case "check": return "M9 16.2L4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4L9 16.2z"
        case "folder": return "M10 4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h6z"
        case "shuffle": return "M16 3h5v5l-1.8-1.8-4.2 4.2-1.4-1.4 4.2-4.2L16 3zM4 6h5.6l8.6 8.6L20 13v5h-5l1.8-1.8L8.8 8H4V6zm5.6 10H4v2h6.4l2.8-2.8-1.4-1.4-2.2 2.2z"
        case "copy": return "M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z"
        case "trash": return "M6 7h12l-1 14H7L6 7zm3-4h6l1 2H8l1-2z"
        case "plus": return "M11 4h2v7h7v2h-7v7h-2v-7H4v-2h7V4z"
        case "refresh": return "M17.6 6.4A8 8 0 1 0 20 12h-2a6 6 0 1 1-1.8-4.2L13 11h7V4l-2.4 2.4z"
        case "menu": return "M3 6h18v2H3V6zm0 5h18v2H3v-2zm0 5h18v2H3v-2z"
        default: return "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z"
        }
    }

    Shape {
        anchors.fill: parent
        scale: root.size / 24.0
        transformOrigin: Item.TopLeft
        antialiasing: true

        ShapePath {
            fillColor: root.color
            strokeColor: "transparent"
            PathSvg { path: root.svgPath }
        }
    }
}
