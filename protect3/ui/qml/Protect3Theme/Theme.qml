pragma Singleton
import QtQuick

QtObject {
    id: theme

    property bool darkMode: true
    property bool reducedMotion: false
    property real fontScale: 1.0

    // Adaptive Dark ("Obsidian") & Light ("Kyoto Washi") Surface Tokens
    readonly property color bgCanvas: darkMode ? "#0B1018" : "#F4F6FA"
    readonly property color bgSidebar: darkMode ? "#0F1622" : "#E9EDF5"
    readonly property color bgSurface: darkMode ? "#141D2B" : "#FFFFFF"
    readonly property color bgElevated: darkMode ? "#1B273A" : "#E3E9F3"
    readonly property color bgInput: darkMode ? "#0B111A" : "#F8FAFD"
    readonly property color bgHover: darkMode ? "#24354F" : "#D6DFED"
    readonly property color bgRowAlt: darkMode ? "#111A28" : "#EFF3F9"

    // Structural Hairline Borders
    readonly property color borderSubtle: darkMode ? "#26364D" : "#CFD8E6"
    readonly property color borderStrong: darkMode ? "#3B5273" : "#9BAEC9"
    readonly property color borderFocus: darkMode ? "#2EC4A0" : "#0F8F72"

    // High-Contrast Typography Colors
    readonly property color textPrimary: darkMode ? "#F0F5FC" : "#0F172A"
    readonly property color textSecondary: darkMode ? "#C0CFE3" : "#334155"
    readonly property color textMuted: darkMode ? "#93A7C2" : "#52647D"

    // Domain Accents & Severity Signals
    readonly property color accent: darkMode ? "#2EC4A0" : "#0F8F72"
    readonly property color accentHover: darkMode ? "#3AD8B2" : "#0C785F"
    readonly property color accentText: darkMode ? "#05201A" : "#FFFFFF"
    readonly property color accentDim: darkMode ? "#143835" : "#DDF5EE"

    readonly property color info: darkMode ? "#6CA9F7" : "#1D5ED4"
    readonly property color infoDim: darkMode ? "#182D49" : "#E4EEFF"
    readonly property color warn: darkMode ? "#F0B254" : "#B4690E"
    readonly property color warnDim: darkMode ? "#3B2C14" : "#FEF2DA"
    readonly property color danger: darkMode ? "#F2797D" : "#C72E37"
    readonly property color dangerDim: darkMode ? "#3F1D24" : "#FDE8EA"
    readonly property color dangerHover: darkMode ? "#54252E" : "#FACDD2"
    readonly property color violet: darkMode ? "#AC99FA" : "#6444D2"
    readonly property color violetDim: darkMode ? "#28224A" : "#EEE9FF"

    // Fonts & Scaled Readability Type System (Bumped baseline + live fontScale)
    readonly property string fontUi: "Segoe UI"
    readonly property string fontMono: "Consolas"
    readonly property int typeHero: Math.round(23 * fontScale)
    readonly property int typeTitle: Math.round(18 * fontScale)
    readonly property int typeHeading: Math.round(15 * fontScale)
    readonly property int typeBody: Math.round(14 * fontScale)
    readonly property int typeMono: Math.round(13 * fontScale)
    readonly property int typeSmall: Math.round(13 * fontScale)
    readonly property int typeCaption: Math.round(12 * fontScale)

    // Spacing & Radius Scale
    readonly property int sp4: 4
    readonly property int sp8: 8
    readonly property int sp12: 12
    readonly property int sp16: 16
    readonly property int sp20: 20
    readonly property int sp24: 24

    readonly property int radSm: 6
    readonly property int radMd: 10
    readonly property int radLg: 14
    readonly property int radPill: 999

    // Intentional Motion Timings (obeys reducedMotion accessibility flag)
    readonly property int durMicro: reducedMotion ? 0 : 70
    readonly property int durPanel: reducedMotion ? 0 : 120
    readonly property int durContext: reducedMotion ? 0 : 140
}
