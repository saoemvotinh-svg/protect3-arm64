import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Dialogs
import QtQuick.Layouts
import QtQuick.Window
import Protect3Theme
import "components"
import "views"

ApplicationWindow {
    id: win
    visible: true
    width: 1340
    height: 860
    minimumWidth: 1080
    minimumHeight: 720
    title: "Protect3 " + vm.appVersion + " — Android ARM64 Studio"
    color: Theme.bgCanvas

    property int currentTab: 0
    property bool dragHovering: false
    readonly property int navRowH: Math.round(42 * Math.min(1.2, Theme.fontScale))
    readonly property int navGap: 6

    Behavior on color { ColorAnimation { duration: Theme.durMicro } }

    Binding {
        target: Theme
        property: "reducedMotion"
        value: vm.reducedMotion
    }
    Binding {
        target: Theme
        property: "darkMode"
        value: vm.darkMode
    }
    Binding {
        target: Theme
        property: "fontScale"
        value: vm.fontScale
    }

    Connections {
        target: vm
        function onToastRequested(msg, kind) {
            toastBanner.show(msg, kind)
        }
    }

    onClosing: function(close) {
        if (vm.busy) {
            close.accepted = false
            toastBanner.show("Đang có tác vụ xử lý chạy nền. Vui lòng đợi hoàn tất trước khi đóng.", "warn")
        }
    }

    // Keyboard Shortcuts
    Shortcut { sequence: "Ctrl+1"; onActivated: win.currentTab = 0 }
    Shortcut { sequence: "Ctrl+2"; onActivated: win.currentTab = 1 }
    Shortcut { sequence: "Ctrl+3"; onActivated: win.currentTab = 2 }
    Shortcut { sequence: "Ctrl+4"; onActivated: win.currentTab = 3 }
    Shortcut { sequence: "Ctrl+5"; onActivated: win.currentTab = 4 }
    Shortcut { sequence: "Ctrl+O"; onActivated: if (!vm.busy) sourceDialog.open() }
    Shortcut { sequence: "Ctrl+I"; onActivated: if (!vm.busy && vm.sourcePath !== "") vm.inspectLibrary() }
    Shortcut { sequence: "F5"; onActivated: if (!vm.busy && !vm.planHasError && vm.sourcePath !== "" && vm.outputPath !== "") { win.currentTab = 3; vm.runProtect() } }
    Shortcut { sequence: "Ctrl+B"; onActivated: if (!vm.busy && !vm.planHasError && vm.sourcePath !== "" && vm.outputPath !== "") { win.currentTab = 3; vm.runProtect() } }
    Shortcut { sequence: "Ctrl+M"; onActivated: vm.reducedMotion = !vm.reducedMotion }
    Shortcut { sequence: "Ctrl+D"; onActivated: vm.darkMode = !vm.darkMode }
    Shortcut { sequence: "Ctrl+="; onActivated: vm.fontScale = Math.min(1.3, vm.fontScale + 0.15) }
    Shortcut { sequence: "Ctrl+-"; onActivated: vm.fontScale = Math.max(0.95, vm.fontScale - 0.15) }

    // Native File & Folder Dialogs
    FileDialog {
        id: sourceDialog
        title: "Chọn thư viện Android ARM64 (.so)"
        nameFilters: ["Shared library (*.so)", "All files (*)"]
        onAccepted: vm.selectSource(selectedFile.toString())
    }

    FileDialog {
        id: outputDialog
        title: "Chọn nơi lưu thư viện .so đã bảo vệ"
        fileMode: FileDialog.SaveFile
        defaultSuffix: "so"
        nameFilters: ["Shared library (*.so)", "All files (*)"]
        onAccepted: vm.outputPath = selectedFile.toString()
    }

    FolderDialog {
        id: ndkDialog
        title: "Chọn thư mục Android NDK"
        onAccepted: vm.ndkPath = selectedFolder.toString()
    }

    FileDialog {
        id: saveProfileDialog
        title: "Lưu cấu hình Protect3 (.json)"
        fileMode: FileDialog.SaveFile
        defaultSuffix: "json"
        nameFilters: ["Protect3 Profile (*.json)"]
        onAccepted: vm.saveConfigProfile(selectedFile.toString())
    }

    FileDialog {
        id: loadProfileDialog
        title: "Nạp cấu hình Protect3 (.json)"
        nameFilters: ["Protect3 Profile (*.json)", "All files (*)"]
        onAccepted: vm.loadConfigProfile(selectedFile.toString())
    }

    // Main Application Shell
    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Left Navigation Rail
        Rectangle {
            id: rail
            Layout.fillHeight: true
            Layout.preferredWidth: vm.sidebarCollapsed ? 68 : Math.round(248 * Math.min(1.15, Theme.fontScale))
            color: Theme.bgSidebar
            Behavior on color { ColorAnimation { duration: Theme.durMicro } }

            Behavior on Layout.preferredWidth {
                NumberAnimation { duration: Theme.durPanel; easing.type: Easing.OutCubic }
            }

            // Right hairline separator
            Rectangle {
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.right: parent.right
                width: 1
                color: Theme.borderSubtle
            }

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Theme.sp12
                spacing: Theme.sp8

                // Brand Header
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 10
                    Layout.bottomMargin: Theme.sp8

                    Rectangle {
                        width: 34
                        height: 34
                        radius: Theme.radSm
                        color: Theme.accentDim
                        border.width: 1
                        border.color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.45)

                        StudioIcon {
                            anchors.centerIn: parent
                            name: "shield"
                            size: 18
                            color: Theme.accent
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: vm.sidebarCollapsed = !vm.sidebarCollapsed
                        }
                    }

                    ColumnLayout {
                        visible: !vm.sidebarCollapsed
                        Layout.fillWidth: true
                        spacing: 0
                        Text {
                            text: "Protect3"
                            color: Theme.textPrimary
                            font.family: Theme.fontUi
                            font.pixelSize: Theme.typeTitle
                            font.weight: Font.Bold
                        }
                        Text {
                            text: "ARM64 STUDIO · v" + vm.appVersion
                            color: Theme.textMuted
                            font.family: Theme.fontMono
                            font.pixelSize: Theme.typeCaption
                        }
                    }

                    StudioButton {
                        visible: !vm.sidebarCollapsed
                        iconName: "menu"
                        variant: "ghost"
                        compact: true
                        implicitWidth: 28
                        onClicked: vm.sidebarCollapsed = true
                    }
                }

                // Navigation Stack with Animated Active Indicator
                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 5 * (win.navRowH + win.navGap)

                    Rectangle {
                        id: activePill
                        width: parent.width
                        height: win.navRowH
                        radius: Theme.radSm
                        color: Theme.accentDim
                        border.width: 1
                        border.color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.4)
                        y: win.currentTab * (win.navRowH + win.navGap)

                        Behavior on y {
                            NumberAnimation { duration: Theme.durPanel; easing.type: Easing.OutCubic }
                        }

                        Rectangle {
                            width: 3
                            height: Math.round(win.navRowH * 0.5)
                            radius: 2
                            color: Theme.accent
                            anchors.left: parent.left
                            anchors.leftMargin: 4
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }

                    Column {
                        anchors.fill: parent
                        spacing: win.navGap

                        Repeater {
                            model: [
                                { icon: "radar", title: "Phân tích & Hàm", shortcut: "Ctrl+1" },
                                { icon: "layers", title: "Lớp bảo vệ", shortcut: "Ctrl+2" },
                                { icon: "bug", title: "Chống soi IDA Pro", shortcut: "Ctrl+3" },
                                { icon: "terminal", title: "Thực thi & Xác minh", shortcut: "Ctrl+4" },
                                { icon: "gauge", title: "Benchmark & Log", shortcut: "Ctrl+5" }
                            ]

                            Item {
                                width: parent.width
                                height: win.navRowH

                                Rectangle {
                                    anchors.fill: parent
                                    radius: Theme.radSm
                                    color: navMouse.containsMouse && win.currentTab !== index ? Theme.bgElevated : "transparent"
                                    Behavior on color { ColorAnimation { duration: Theme.durMicro } }
                                }

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 12
                                    anchors.rightMargin: 10
                                    spacing: 10

                                    StudioIcon {
                                        name: modelData.icon
                                        size: 16
                                        color: win.currentTab === index ? Theme.accent : Theme.textSecondary
                                        Layout.alignment: Qt.AlignVCenter
                                    }

                                    Text {
                                        visible: !vm.sidebarCollapsed
                                        text: modelData.title
                                        color: win.currentTab === index ? Theme.textPrimary : Theme.textSecondary
                                        font.family: Theme.fontUi
                                        font.pixelSize: Theme.typeBody
                                        font.weight: win.currentTab === index ? Font.DemiBold : Font.Normal
                                        Layout.fillWidth: true
                                        elide: Text.ElideRight
                                    }

                                    Text {
                                        visible: !vm.sidebarCollapsed
                                        text: modelData.shortcut
                                        color: Theme.textMuted
                                        font.family: Theme.fontMono
                                        font.pixelSize: Theme.typeCaption
                                    }
                                }

                                MouseArea {
                                    id: navMouse
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: win.currentTab = index
                                }
                            }
                        }
                    }
                }

                Item { Layout.fillHeight: true }

                // Sidebar Bottom Accessibility & Quick Info
                Rectangle {
                    visible: !vm.sidebarCollapsed
                    Layout.fillWidth: true
                    height: sideFootCol.implicitHeight + 16
                    radius: Theme.radSm
                    color: Theme.bgSurface
                    border.width: 1
                    border.color: Theme.borderSubtle

                    ColumnLayout {
                        id: sideFootCol
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 8

                        // Dark / White Mode Segmented Selector
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            Text {
                                text: "Giao diện (Ctrl+D)"
                                color: Theme.textSecondary
                                font.pixelSize: Theme.typeCaption
                                font.weight: Font.DemiBold
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 4
                                StudioButton {
                                    Layout.fillWidth: true
                                    text: "Tối"
                                    compact: true
                                    variant: vm.darkMode ? "primary" : "secondary"
                                    onClicked: vm.darkMode = true
                                }
                                StudioButton {
                                    Layout.fillWidth: true
                                    text: "Sáng"
                                    compact: true
                                    variant: !vm.darkMode ? "primary" : "secondary"
                                    onClicked: vm.darkMode = false
                                }
                            }
                        }

                        // Font Scale Preset Selector
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            Text {
                                text: "Cỡ chữ hiển thị"
                                color: Theme.textSecondary
                                font.pixelSize: Theme.typeCaption
                                font.weight: Font.DemiBold
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 4
                                StudioButton {
                                    Layout.fillWidth: true
                                    text: "Vừa"
                                    compact: true
                                    variant: Math.abs(vm.fontScale - 1.0) < 0.05 ? "primary" : "secondary"
                                    onClicked: vm.fontScale = 1.0
                                }
                                StudioButton {
                                    Layout.fillWidth: true
                                    text: "Lớn"
                                    compact: true
                                    variant: Math.abs(vm.fontScale - 1.15) < 0.05 ? "primary" : "secondary"
                                    onClicked: vm.fontScale = 1.15
                                }
                                StudioButton {
                                    Layout.fillWidth: true
                                    text: "To"
                                    compact: true
                                    variant: Math.abs(vm.fontScale - 1.3) < 0.05 ? "primary" : "secondary"
                                    onClicked: vm.fontScale = 1.3
                                }
                            }
                        }

                        StudioSwitch {
                            Layout.fillWidth: true
                            title: "Giảm hiệu ứng"
                            subtitle: "Ctrl+M"
                            checked: vm.reducedMotion
                            onToggled: function(v) { vm.reducedMotion = v }
                        }

                        Text {
                            text: vm.hasElf ? vm.elfBadgeText : "Kéo thả .so vào cửa sổ"
                            color: Theme.textMuted
                            font.family: Theme.fontMono
                            font.pixelSize: Theme.typeCaption
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }
                }
            }
        }

        // Right Main Workbench Area
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.minimumWidth: 0
            spacing: 0

            // Top Persistent Target Bar
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: topBarGrid.implicitHeight + 20
                color: Theme.bgSidebar

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    height: 1
                    color: Theme.borderSubtle
                }

                GridLayout {
                    id: topBarGrid
                    anchors.fill: parent
                    anchors.margins: 10
                    columns: 6
                    columnSpacing: Theme.sp8
                    rowSpacing: Theme.sp8

                    StudioField {
                        Layout.fillWidth: true
                        Layout.columnSpan: 2
                        placeholder: "File .so đầu vào (ARM64 ET_DYN)..."
                        monospace: true
                        text: vm.sourcePath
                        onEditedText: function(t) { vm.sourcePath = t }
                        onAcceptedText: function(t) { vm.sourcePath = t }
                    }
                    StudioButton {
                        text: "Chọn .so…"
                        iconName: "folder"
                        enabled: !vm.busy
                        onClicked: sourceDialog.open()
                    }

                    StudioField {
                        Layout.fillWidth: true
                        Layout.columnSpan: 2
                        placeholder: "Đường dẫn xuất .so bảo vệ..."
                        monospace: true
                        text: vm.outputPath
                        onEditedText: function(t) { vm.outputPath = t }
                        onAcceptedText: function(t) { vm.outputPath = t }
                    }
                    RowLayout {
                        spacing: Theme.sp8
                        StudioButton {
                            text: "Lưu ra…"
                            enabled: !vm.busy
                            onClicked: outputDialog.open()
                        }
                        StudioSwitch {
                            title: "Ghi đè"
                            implicitWidth: Math.round(118 * Math.min(1.25, Theme.fontScale))
                            Layout.fillWidth: false
                            checked: vm.forceOverwrite
                            onToggled: function(v) { vm.forceOverwrite = v }
                        }
                    }

                    // Second Top Row: Quick Context Chips & Primary CTAs
                    RowLayout {
                        Layout.columnSpan: 6
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: Theme.sp8

                        Flow {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            spacing: Theme.sp8

                            StudioBadge {
                                text: vm.elfBadgeText
                                tone: vm.hasElf ? "accent" : "neutral"
                                monospace: true
                            }

                            StudioBadge {
                                visible: vm.options.block_ida || vm.options.troll_ida
                                text: vm.options.block_ida && vm.options.troll_ida
                                    ? "IDA: Ẩn code + " + decoyModel.count + " hàm F5"
                                    : (vm.options.troll_ida ? "IDA: Đổi tên " + (vm.options.troll_barcode_length || 0) + " ký tự" : "IDA: Ẩn toàn bộ code")
                                tone: "violet"
                            }

                            StudioBadge {
                                visible: vm.planHasError
                                text: "Xung đột cấu hình!"
                                tone: "danger"
                            }
                        }

                        StudioButton {
                            text: vm.darkMode ? "Nền Sáng" : "Nền Tối"
                            compact: true
                            variant: "ghost"
                            onClicked: vm.darkMode = !vm.darkMode
                        }

                        StudioButton {
                            text: "Phân tích .so (Ctrl+I)"
                            iconName: "radar"
                            enabled: !vm.busy && vm.sourcePath !== ""
                            onClicked: {
                                win.currentTab = 0
                                vm.inspectLibrary()
                            }
                        }

                        StudioButton {
                            text: vm.busy ? "Đang xử lý…" : "Tạo .so bảo vệ (F5)"
                            iconName: "play"
                            variant: "primary"
                            enabled: !vm.busy && !vm.planHasError && vm.sourcePath !== "" && vm.outputPath !== ""
                            onClicked: {
                                win.currentTab = 3
                                vm.runProtect()
                            }
                        }
                    }
                }
            }

            // Active Workspace Content with Subtle Motion Transition
            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true

                StackLayout {
                    id: workspaceStack
                    anchors.fill: parent
                    anchors.margins: Theme.sp12
                    currentIndex: win.currentTab

                    onCurrentIndexChanged: {
                        if (!Theme.reducedMotion) {
                            workspaceReveal.restart()
                        }
                    }

                    InspectorView { onRequestBrowseInput: sourceDialog.open() }
                    ProtectionMatrixView {
                        onRequestBrowseNdk: ndkDialog.open()
                        onRequestSaveProfile: saveProfileDialog.open()
                        onRequestLoadProfile: loadProfileDialog.open()
                    }
                    IdaTrollView {}
                    BuildVerifyView {}
                    BenchmarkTriageView {}
                }

                ParallelAnimation {
                    id: workspaceReveal
                    NumberAnimation { target: workspaceStack; property: "opacity"; from: 0.86; to: 1.0; duration: Theme.durContext; easing.type: Easing.OutCubic }
                }
            }

            // Bottom Operational Status Bar
            Rectangle {
                Layout.fillWidth: true
                height: Math.round(34 * Math.min(1.2, Theme.fontScale))
                color: Theme.bgSidebar
                Behavior on color { ColorAnimation { duration: Theme.durMicro } }

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    height: 1
                    color: Theme.borderSubtle
                }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Theme.sp12
                    anchors.rightMargin: Theme.sp12
                    spacing: 10

                    Rectangle {
                        width: 8
                        height: 8
                        radius: 4
                        color: {
                            if (vm.busy) return Theme.warn
                            if (vm.statusKind === "error") return Theme.danger
                            if (vm.statusKind === "success") return Theme.accent
                            return Theme.info
                        }
                    }

                    Text {
                        text: vm.statusText
                        color: Theme.textSecondary
                        font.pixelSize: Theme.typeSmall
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }

                    Text {
                        text: vm.runtimeSummary
                        color: Theme.textMuted
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeCaption
                        elide: Text.ElideRight
                        Layout.maximumWidth: 380
                    }
                }
            }
        }
    }

    // Window-wide Drag & Drop Zone for .so files
    DropArea {
        anchors.fill: parent
        onEntered: function(drag) {
            if (drag.hasUrls) {
                win.dragHovering = true
                drag.acceptProposedAction()
            }
        }
        onExited: win.dragHovering = false
        onDropped: function(drop) {
            win.dragHovering = false
            if (drop.hasUrls && drop.urls.length > 0) {
                var picked = String(drop.urls[0])
                if (picked.toLowerCase().endsWith(".so")) {
                    win.currentTab = 0
                    vm.selectSource(picked)
                } else {
                    toastBanner.show("Hãy thả file thư viện ARM64 đuôi .so.", "warn")
                }
            }
        }
    }

    Rectangle {
        anchors.fill: parent
        visible: win.dragHovering
        color: Qt.rgba(Theme.bgCanvas.r, Theme.bgCanvas.g, Theme.bgCanvas.b, 0.9)
        border.width: 2
        border.color: Theme.accent
        Column {
            anchors.centerIn: parent
            spacing: 8
            StudioIcon { name: "folder"; size: 42; color: Theme.accent; anchors.horizontalCenter: parent.horizontalCenter }
            Text { text: "Thả file .so ARM64 vào đây để phân tích"; color: Theme.textPrimary; font.pixelSize: Theme.typeTitle; font.weight: Font.DemiBold }
        }
    }

    ToastBanner {
        id: toastBanner
        anchors.right: parent.right
        anchors.rightMargin: Theme.sp16
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 42
        z: 99
    }
}
