import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Dialogs
import QtQuick.Layouts
import Protect3Theme
import "../components"

Item {
    id: root

    FileDialog {
        id: pickOrigDialog
        title: "Chọn file .so gốc để so sánh"
        nameFilters: ["Shared library (*.so)", "All files (*)"]
        onAccepted: vm.benchOrigPath = selectedFile.toString()
    }

    FileDialog {
        id: pickProtDialog
        title: "Chọn file .so đã bảo vệ để benchmark"
        nameFilters: ["Shared library (*.so)", "All files (*)"]
        onAccepted: vm.benchProtPath = selectedFile.toString()
    }

    FileDialog {
        id: pickLogDialog
        title: "Chọn file logcat (.txt / .log)"
        nameFilters: ["Log files (*.txt *.log)", "All files (*)"]
        onAccepted: vm.loadTriageFile(selectedFile.toString())
    }

    RowLayout {
        anchors.fill: parent
        spacing: Theme.sp12

        // Left Column: A04-A06 / A09 Static & Simplifier Benchmark
        StudioCard {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.preferredWidth: 1
            title: "Benchmark Khôi phục & Độ lệch Mã (A04–A06, A09)"
            subtitle: "Đo tỷ lệ lộ chuỗi .rodata, độ sai khác 4-gram .text, tỷ lệ sống sót prologue và gợi ý tối ưu"
            badgeText: vm.hasBenchResult ? "ĐÃ ĐO" : "CHỜ CHẠY"
            badgeTone: vm.hasBenchResult ? "accent" : "neutral"

            RowLayout {
                Layout.fillWidth: true
                spacing: 6
                StudioField {
                    Layout.fillWidth: true
                    label: "File .so gốc:"
                    monospace: true
                    text: vm.benchOrigPath
                    onAcceptedText: function(t) { vm.benchOrigPath = t }
                }
                StudioButton { text: "Chọn…"; Layout.alignment: Qt.AlignBottom; onClicked: pickOrigDialog.open() }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 6
                StudioField {
                    Layout.fillWidth: true
                    label: "File .so đã bảo vệ:"
                    monospace: true
                    text: vm.benchProtPath
                    onAcceptedText: function(t) { vm.benchProtPath = t }
                }
                StudioButton { text: "Chọn…"; Layout.alignment: Qt.AlignBottom; onClicked: pickProtDialog.open() }
            }

            StudioButton {
                text: "Chạy Benchmark A04–A06"
                variant: "primary"
                iconName: "gauge"
                enabled: !vm.busy
                onClicked: vm.runBenchmark()
            }

            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                contentWidth: availableWidth

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.sp12
                    visible: vm.hasBenchResult

                    readonly property var metrics: vm.benchResult.metrics || {}

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        columnSpacing: Theme.sp12
                        rowSpacing: 8

                        Rectangle {
                            Layout.fillWidth: true; implicitHeight: Math.round(74 * Math.min(1.25, Theme.fontScale)); radius: Theme.radSm; color: Theme.bgInput; border.width: 1; border.color: Theme.borderSubtle
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 10
                                Text { text: "text_4gram_divergence"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                                Text {
                                    text: Number((vm.benchResult.metrics || {}).text_4gram_divergence || 0).toFixed(3)
                                    color: Theme.accent; font.family: Theme.fontMono; font.pixelSize: Theme.typeHero; font.weight: Font.Bold
                                }
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true; implicitHeight: Math.round(74 * Math.min(1.25, Theme.fontScale)); radius: Theme.radSm; color: Theme.bgInput; border.width: 1; border.color: Theme.borderSubtle
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 10
                                Text { text: "plaintext_string_exposure"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                                Text {
                                    text: (Number((vm.benchResult.metrics || {}).plaintext_string_exposure_rate || 0) * 100).toFixed(1) + "%"
                                    color: ((vm.benchResult.metrics || {}).plaintext_string_exposure_rate || 0) === 0 ? Theme.accent : Theme.warn
                                    font.family: Theme.fontMono; font.pixelSize: Theme.typeHero; font.weight: Font.Bold
                                }
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true; implicitHeight: Math.round(74 * Math.min(1.25, Theme.fontScale)); radius: Theme.radSm; color: Theme.bgInput; border.width: 1; border.color: Theme.borderSubtle
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 10
                                Text { text: "function_entry_survival"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                                Text {
                                    text: (Number((vm.benchResult.metrics || {}).function_entry_survival_rate || 0) * 100).toFixed(1) + "%"
                                    color: Theme.info; font.family: Theme.fontMono; font.pixelSize: Theme.typeHero; font.weight: Font.Bold
                                }
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true; implicitHeight: Math.round(74 * Math.min(1.25, Theme.fontScale)); radius: Theme.radSm; color: Theme.bgInput; border.width: 1; border.color: Theme.borderSubtle
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 10
                                Text { text: "Opaque Const / Predicates"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                                Text {
                                    text: ((vm.benchResult.metrics || {}).opaque_constants_synthesized || 0) + " / " + ((vm.benchResult.metrics || {}).opaque_predicates_emitted || 0)
                                    color: Theme.violet; font.family: Theme.fontMono; font.pixelSize: Theme.typeHero; font.weight: Font.Bold
                                }
                            }
                        }
                    }

                    Text {
                        text: "Đề xuất từ Feedback Loop (A09):"
                        color: Theme.textSecondary
                        font.pixelSize: Theme.typeSmall
                        font.weight: Font.DemiBold
                    }

                    Repeater {
                        model: vm.benchResult.feedback_A09 || []
                        Rectangle {
                            Layout.fillWidth: true
                            height: recTxt.implicitHeight + 22
                            radius: Theme.radSm
                            color: Theme.bgInput
                            border.width: 1
                            border.color: Theme.borderSubtle
                            Text {
                                id: recTxt
                                anchors.fill: parent
                                anchors.margins: 8
                                text: {
                                    if (typeof modelData === "string") return "• " + modelData
                                    var line = "• [" + (modelData.action || "A09") + "] " + (modelData.reason || "")
                                    if (modelData.suggested_targets && modelData.suggested_targets.length > 0) {
                                        line += "\n  Gợi ý hàm: " + modelData.suggested_targets.join(", ")
                                    }
                                    return line
                                }
                                color: Theme.textPrimary
                                font.pixelSize: Theme.typeSmall
                                wrapMode: Text.WordWrap
                            }
                        }
                    }
                }
            }
        }

        // Right Column: Android Logcat Crash & Guard Triage
        StudioCard {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.preferredWidth: 1
            title: "Phân tích Logcat & Sự kiện Guard Android"
            subtitle: "Phân loại bằng chứng Protect3 guard_start..guard_return, UnsatisfiedLinkError & backtrace native (DEBUG/crash_dump64)"
            badgeText: vm.hasTriageResult ? ((vm.triageResult.findings || []).length + " phát hiện") : "LOGCAT TRIAGE"
            badgeTone: !vm.hasTriageResult ? "neutral" : ((vm.triageResult.findings || []).length > 0 ? "warn" : "accent")

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 8
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8
                    StudioField {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 110
                        label: "Package Android:"
                        monospace: true
                        text: vm.logPackageName
                        onEditedText: function(t) { vm.logPackageName = t }
                        onAcceptedText: function(t) { vm.logPackageName = t }
                    }
                    StudioField {
                        Layout.preferredWidth: 175
                        Layout.minimumWidth: 110
                        label: "Tên thư viện .so:"
                        monospace: true
                        text: vm.logLibName
                        onEditedText: function(t) { vm.logLibName = t }
                        onAcceptedText: function(t) { vm.logLibName = t }
                    }
                }
                Flow {
                    Layout.fillWidth: true
                    spacing: 8
                    StudioButton { text: "Nạp file log…"; iconName: "folder"; onClicked: pickLogDialog.open() }
                    StudioButton {
                        text: "Phân tích"
                        variant: "primary"
                        iconName: "bug"
                        enabled: !vm.busy
                        onClicked: vm.runAnalyzeLog(triageArea.text, pkgFieldFallback(), libFieldFallback())
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 160
                color: Theme.bgInput
                radius: Theme.radSm
                border.width: 1
                border.color: Theme.borderSubtle

                ScrollView {
                    anchors.fill: parent
                    anchors.margins: 6
                    TextArea {
                        id: triageArea
                        text: vm.triageInputText
                        placeholderText: "Dán nội dung adb logcat tại đây hoặc bấm 'Nạp file log…'..."
                        placeholderTextColor: Theme.textMuted
                        color: Theme.textPrimary
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeCaption
                        selectByMouse: true
                        wrapMode: TextEdit.NoWrap
                        background: Item {}
                    }
                }
            }

            // Results Summary
            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                contentWidth: availableWidth

                ColumnLayout {
                    width: parent.width
                    spacing: 8
                    visible: vm.hasTriageResult

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 6
                        StudioBadge {
                            text: "Guard events: " + ((vm.triageResult.guard_events || []).length)
                            tone: (vm.triageResult.guard_events || []).length > 0 ? "accent" : "neutral"
                        }
                        StudioBadge {
                            text: "PIDs: " + ((vm.triageResult.target_pids || []).join(", ") || "none")
                            tone: "info"
                            monospace: true
                        }
                    }

                    Text {
                        text: "Kết luận: " + (vm.triageResult.conclusion || "")
                        color: Theme.textSecondary
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeSmall
                        wrapMode: Text.WrapAnywhere
                        Layout.fillWidth: true
                    }

                    Repeater {
                        model: vm.triageResult.findings || []
                        Rectangle {
                            Layout.fillWidth: true
                            height: findCol.implicitHeight + 14
                            radius: Theme.radSm
                            color: Theme.warnDim
                            border.width: 1
                            border.color: Theme.warn
                            ColumnLayout {
                                id: findCol
                                anchors.fill: parent
                                anchors.margins: 8
                                spacing: 4
                                Text {
                                    text: modelData.category + " (" + modelData.confidence + ")"
                                    color: Theme.warn
                                    font.family: Theme.fontMono
                                    font.pixelSize: Theme.typeSmall
                                    font.weight: Font.Bold
                                }
                                Text {
                                    text: (modelData.evidence || []).slice(0, 6).join("\n")
                                    color: Theme.textPrimary
                                    font.family: Theme.fontMono
                                    font.pixelSize: Theme.typeCaption
                                    wrapMode: Text.WrapAnywhere
                                    Layout.fillWidth: true
                                }
                            }
                        }
                    }

                    Text {
                        visible: (vm.triageResult.guard_events || []).length > 0
                        text: "Protect3 Guard Timeline:"
                        color: Theme.accent
                        font.pixelSize: Theme.typeSmall
                        font.weight: Font.DemiBold
                    }

                    Rectangle {
                        visible: (vm.triageResult.guard_events || []).length > 0
                        Layout.fillWidth: true
                        height: Math.min(200, evTxt.implicitHeight + 14)
                        color: Theme.bgInput
                        radius: Theme.radSm
                        border.width: 1
                        border.color: Theme.borderSubtle
                        ScrollView {
                            anchors.fill: parent
                            anchors.margins: 6
                            TextArea {
                                id: evTxt
                                readOnly: true
                                selectByMouse: true
                                text: (vm.triageResult.guard_events || []).join("\n")
                                color: Theme.accent
                                font.family: Theme.fontMono
                                font.pixelSize: Theme.typeCaption
                                background: Item {}
                            }
                        }
                    }
                }
            }
        }
    }

    function pkgFieldFallback() { return vm.logPackageName }
    function libFieldFallback() { return vm.logLibName }
}
