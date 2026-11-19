import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts
import Protect3Theme
import "../components"

Item {
    id: root

    ColumnLayout {
        anchors.fill: parent
        spacing: Theme.sp12

        // Top Grid: Execution Status & Live Plan / Verification Result
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.sp12

            StudioCard {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 1
                title: "Kế hoạch thực thi F05 & Trạng thái Build"
                badgeText: vm.busy ? "ĐANG XỬ LÝ" : (vm.planHasError ? "XUNG ĐỘT" : "SẴN SÀNG")
                badgeTone: vm.busy ? "warn" : (vm.planHasError ? "danger" : "accent")

                // Active Roadmap ID Pills
                Flow {
                    Layout.fillWidth: true
                    spacing: 5
                    visible: vm.planActiveIds.length > 0
                    Repeater {
                        model: vm.planActiveIds
                        StudioBadge {
                            text: modelData
                            tone: "accent"
                            monospace: true
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: buildPlanCol.implicitHeight + (vm.planHasError ? 20 : 0)
                    Layout.minimumHeight: implicitHeight
                    radius: Theme.radSm
                    color: vm.planHasError ? Theme.dangerDim : "transparent"
                    border.width: vm.planHasError ? 1 : 0
                    border.color: vm.planHasError ? Theme.danger : "transparent"

                    ColumnLayout {
                        id: buildPlanCol
                        anchors.fill: parent
                        anchors.margins: vm.planHasError ? 10 : 0
                        spacing: 6

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.sp8
                            Text {
                                text: vm.planSummaryText
                                color: vm.planHasError ? Theme.danger : Theme.textSecondary
                                font.pixelSize: Theme.typeSmall
                                font.weight: vm.planHasError ? Font.DemiBold : Font.Normal
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                            StudioButton {
                                visible: vm.planHasError
                                text: vm.hasElf ? "Tự chỉnh cho .so này" : "Tự gỡ xung đột"
                                compact: true
                                variant: "secondary"
                                onClicked: vm.adaptOptionsToLoadedElf()
                            }
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            visible: vm.planHasError && vm.conflictList && vm.conflictList.length > 0
                            spacing: 3

                            Repeater {
                                model: vm.conflictList || []
                                Text {
                                    Layout.fillWidth: true
                                    text: "• " + (modelData.message || "")
                                    color: Theme.danger
                                    font.family: Theme.fontUi
                                    font.pixelSize: Theme.typeCaption
                                    font.weight: Font.DemiBold
                                    wrapMode: Text.WordWrap
                                }
                            }
                        }
                    }
                }

                // Determinate / Indeterminate Animated Progress Strip
                ProgressBar {
                    Layout.fillWidth: true
                    indeterminate: vm.busy
                    value: vm.busy ? 0 : (vm.hasVerifyResult ? 1.0 : 0.0)
                    implicitHeight: 8

                    background: Rectangle {
                        radius: 4
                        color: Theme.bgInput
                        border.width: 1
                        border.color: Theme.borderSubtle
                    }

                    contentItem: Item {
                        Rectangle {
                            width: parent.width * (vm.busy ? 0.35 : (vm.hasVerifyResult ? 1.0 : 0.0))
                            height: parent.height
                            radius: 4
                            color: vm.statusKind === "error" ? Theme.danger : Theme.accent
                            x: vm.busy ? pulseAnimX : 0
                            property real pulseAnimX: 0

                            SequentialAnimation on pulseAnimX {
                                running: vm.busy && !Theme.reducedMotion
                                loops: Animation.Infinite
                                NumberAnimation { from: 0; to: Math.max(0, width * 1.85); duration: 900; easing.type: Easing.InOutQuad }
                                NumberAnimation { from: Math.max(0, width * 1.85); to: 0; duration: 900; easing.type: Easing.InOutQuad }
                            }
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    visible: !!vm.options.report_only && (!!vm.options.anti_gg || !!vm.options.gg_honeypot || !!vm.options.debugger)
                    implicitHeight: buildWarnRow.implicitHeight + 14
                    Layout.minimumHeight: implicitHeight
                    radius: Theme.radSm
                    color: Theme.warnDim
                    border.width: 1
                    border.color: Theme.warn

                    RowLayout {
                        id: buildWarnRow
                        anchors.fill: parent
                        anchors.margins: 7
                        spacing: Theme.sp8
                        Text {
                            Layout.fillWidth: true
                            text: "Đang bật 'Chỉ ghi log (report_only)' — phát hiện GG/debug sẽ không tự thoát app."
                            color: Theme.warn
                            font.family: Theme.fontUi
                            font.pixelSize: Theme.typeCaption
                            font.weight: Font.DemiBold
                            wrapMode: Text.WordWrap
                        }
                        StudioButton {
                            text: "Chặn thật ngay"
                            compact: true
                            variant: "primary"
                            onClicked: {
                                vm.setOption("report_only", false)
                                vm.setOption("deny_attach", true)
                                vm.setOption("runtime_anti_debug", true)
                            }
                        }
                    }
                }

                Flow {
                    Layout.fillWidth: true
                    spacing: Theme.sp8
                    StudioButton {
                        text: "Tạo .so bảo vệ"
                        variant: "primary"
                        iconName: "play"
                        enabled: !vm.busy && !vm.planHasError && vm.sourcePath !== "" && vm.outputPath !== ""
                        onClicked: vm.runProtect()
                    }
                    StudioButton {
                        text: "Kiểm tra output"
                        iconName: "check"
                        enabled: !vm.busy && (vm.outputPath !== "" || vm.lastOutputPath !== "")
                        onClicked: vm.runVerify()
                    }
                    StudioButton {
                        text: "Mở thư mục kết quả"
                        iconName: "folder"
                        onClicked: vm.openOutputFolder()
                    }
                }
            }

            StudioCard {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 1
                title: "Kết quả xác minh Output (.protect3.json)"
                badgeText: vm.hasVerifyResult ? String(vm.verifyResult.status || "").toUpperCase() : "CHƯA CHẠY"
                badgeTone: !vm.hasVerifyResult ? "neutral" : (vm.verifyResult.status === "passed" ? "accent" : "danger")

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.sp12
                    rowSpacing: 6
                    visible: vm.hasVerifyResult

                    Text { text: "Output SHA-256:"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                    Text {
                        text: vm.verifyResult.sha256 || ""
                        color: Theme.textPrimary
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeCaption
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                    }

                    Text { text: "Watermark (A08):"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                    Text {
                        text: vm.verifyResult.watermark_verified === null || vm.verifyResult.watermark_verified === undefined
                            ? "Không cấu hình"
                            : (vm.verifyResult.watermark_verified ? "Khớp 128-bit watermark" : "Không khớp")
                        color: vm.verifyResult.watermark_verified ? Theme.accent : Theme.textSecondary
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeMono
                    }

                    Text { text: "Biến đổi hàm:"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                    Text {
                        text: (vm.lastProtectMetrics.transformedCount || 0) + " hàm · " + (vm.lastProtectMetrics.stringsCount || 0) + " chuỗi Vault"
                        color: Theme.textPrimary
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeMono
                    }

                    Text { text: "Unicorn (F03):"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                    Text {
                        readonly property var semItems: vm.lastProtectMetrics.semantics || []
                        readonly property string semTone: {
                            if (!semItems || semItems.length === 0) return "muted"
                            var hasPass = false, hasFail = false
                            for (var i = 0; i < semItems.length; ++i) {
                                if (semItems[i].status === "failed") hasFail = true
                                else if (semItems[i].status === "passed") hasPass = true
                            }
                            if (hasFail) return "danger"
                            if (hasPass) return "accent"
                            return "warn"
                        }
                        text: {
                            if (!semItems || semItems.length === 0) return "Chưa bật (tùy chọn --verify-semantics)"
                            var p = 0, s = 0, f = 0, u = 0
                            for (var i = 0; i < semItems.length; ++i) {
                                var st = semItems[i].status
                                if (st === "passed") p++
                                else if (st === "skipped") s++
                                else if (st === "failed") f++
                                else u++
                            }
                            var parts = []
                            if (p > 0) parts.push(p + " passed")
                            if (s > 0) parts.push(s + " skipped")
                            if (f > 0) parts.push(f + " failed")
                            if (u > 0) parts.push(u + " unavailable")
                            return parts.length ? parts.join(" · ") : "Đã chạy"
                        }
                        color: semTone === "danger" ? Theme.danger : (semTone === "accent" ? Theme.accent : (semTone === "warn" ? Theme.warn : Theme.textMuted))
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeMono
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    Text { text: "Phạm vi kiểm tra:"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                    Text {
                        text: vm.verifyResult.scope || ""
                        color: Theme.textMuted
                        font.pixelSize: Theme.typeCaption
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }

                Text {
                    visible: !vm.hasVerifyResult
                    text: "Bấm 'Tạo .so bảo vệ' hoặc 'Kiểm tra output' để kiểm định chữ ký cấu trúc ELF, ABI export, hash SHA-256 và watermark A08."
                    color: Theme.textMuted
                    font.pixelSize: Theme.typeSmall
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                // Embedded ARM64 Runtime Card footer
                Rectangle {
                    Layout.fillWidth: true
                    height: rtRow.implicitHeight + 12
                    color: Theme.bgInput
                    radius: Theme.radSm
                    border.width: 1
                    border.color: Theme.borderSubtle

                    RowLayout {
                        id: rtRow
                        anchors.fill: parent
                        anchors.margins: 6
                        spacing: 8
                        Text {
                            text: "Runtime: " + vm.runtimeSummary
                            color: Theme.textSecondary
                            font.family: Theme.fontMono
                            font.pixelSize: Theme.typeCaption
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                        StudioButton {
                            text: "Build guard.bin (NDK)"
                            compact: true
                            enabled: !vm.busy && vm.ndkPath !== ""
                            onClicked: vm.runBuildRuntime()
                        }
                    }
                }
            }
        }

        // Bottom Split: Live Console Stream & Capabilities Ledger
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: Theme.sp12

            StudioCard {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 3
                title: "Nhật ký thực thi trực tiếp (Streaming Log)"
                badgeText: "Worker Output"
                badgeTone: "info"

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 6
                    StudioButton { text: "Sao chép log"; iconName: "copy"; compact: true; onClicked: vm.copyText(vm.logText) }
                    StudioButton { text: "Xóa log"; iconName: "trash"; compact: true; onClicked: vm.clearLog() }
                    Item { Layout.fillWidth: true }
                    Text {
                        text: "Desktop log: " + vm.logFilePath
                        color: Theme.textMuted
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeCaption
                        elide: Text.ElideMiddle
                        Layout.maximumWidth: 320
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: Theme.bgInput
                    radius: Theme.radSm
                    border.width: 1
                    border.color: Theme.borderSubtle

                    ScrollView {
                        anchors.fill: parent
                        anchors.margins: 6
                        TextArea {
                            text: vm.logText
                            readOnly: true
                            selectByMouse: true
                            color: Theme.textPrimary
                            font.family: Theme.fontMono
                            font.pixelSize: Theme.typeMono
                            wrapMode: TextEdit.WordWrap
                            background: Item {}
                        }
                    }
                }
            }

            StudioCard {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 2
                title: "Phạm vi năng lực & Trạng thái Pass"
                badgeText: "Capabilities"
                badgeTone: "neutral"

                ListView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    model: capModel
                    spacing: 6
                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                    delegate: Rectangle {
                        width: ListView.view ? ListView.view.width : (parent ? parent.width : 300)
                        height: capCol.implicitHeight + 14
                        radius: Theme.radSm
                        color: Theme.bgInput
                        border.width: 1
                        border.color: status === "enabled" ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.4) : Theme.borderSubtle

                        ColumnLayout {
                            id: capCol
                            anchors.fill: parent
                            anchors.margins: 8
                            spacing: 4
                            RowLayout {
                                Layout.fillWidth: true
                                Text {
                                    text: feature
                                    color: Theme.textPrimary
                                    font.pixelSize: Theme.typeSmall
                                    font.weight: Font.DemiBold
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight
                                }
                                StudioBadge {
                                    text: status.toUpperCase()
                                    tone: status === "enabled" ? "accent" : "neutral"
                                }
                            }
                            Text {
                                text: scope
                                color: Theme.textMuted
                                font.pixelSize: Theme.typeCaption
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }
        }
    }
}
