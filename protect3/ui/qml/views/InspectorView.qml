import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts
import Protect3Theme
import "../components"

Item {
    id: root
    property string activeCategory: "all"
    property string searchQuery: ""

    signal requestBrowseInput()

    function updateFilter() {
        fnModel.applyFilter(searchField.text, root.activeCategory)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Theme.sp12

        // Empty State Onboarding Card
        StudioCard {
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: !vm.hasElf

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.alignment: Qt.AlignCenter
                spacing: Theme.sp12

                Item { Layout.fillHeight: true }

                StudioIcon {
                    name: "radar"
                    size: 44
                    color: Theme.accent
                    Layout.alignment: Qt.AlignHCenter
                }

                Text {
                    text: "Chưa có dữ liệu phân tích ELF ARM64"
                    color: Theme.textPrimary
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.typeTitle
                    font.weight: Font.DemiBold
                    Layout.alignment: Qt.AlignHCenter
                }

                Text {
                    text: "Kéo thả file .so vào cửa sổ hoặc chọn file ở thanh trên để Protect3 quét cấu trúc ELF, kiểm tra RELRO/NX/Canary và khôi phục bảng hàm từ .dynsym / .symtab / .eh_frame (F01)."
                    color: Theme.textSecondary
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.typeBody
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    Layout.maximumWidth: 540
                    Layout.alignment: Qt.AlignHCenter
                }

                RowLayout {
                    Layout.alignment: Qt.AlignHCenter
                    spacing: Theme.sp8
                    StudioButton {
                        text: "Chọn file .so..."
                        iconName: "folder"
                        variant: "primary"
                        onClicked: root.requestBrowseInput()
                    }
                    StudioButton {
                        text: "Phân tích đường dẫn hiện tại"
                        iconName: "radar"
                        enabled: vm.sourcePath !== "" && !vm.busy
                        onClicked: vm.inspectLibrary()
                    }
                }

                // Recent sources chips
                Flow {
                    visible: vm.recentSources.length > 0
                    Layout.maximumWidth: 640
                    Layout.alignment: Qt.AlignHCenter
                    spacing: Theme.sp8
                    Repeater {
                        model: vm.recentSources
                        StudioButton {
                            text: {
                                var parts = String(modelData).replace(/\\/g, "/").split("/")
                                return parts[parts.length - 1]
                            }
                            compact: true
                            variant: "ghost"
                            enabled: !vm.busy
                            onClicked: vm.selectSource(modelData)
                        }
                    }
                }

                Item { Layout.fillHeight: true }
            }
        }

        // Loaded Inspector & Function Explorer
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: vm.hasElf
            spacing: Theme.sp12

            // Top Summary & Hardening Posture Strip
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.sp12

                StudioCard {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    title: "Cấu trúc ELF & Export"
                    badgeText: (vm.elfSummary.architecture || "arm64") + (vm.elfSummary.protected ? " · ĐÃ BẢO VỆ" : " · GỐC")
                    badgeTone: vm.elfSummary.protected ? "warn" : "accent"

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 4
                        columnSpacing: Theme.sp16
                        rowSpacing: 6

                        Text { text: "SONAME"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                        Text { text: vm.elfSummary.soname || "(none)"; color: Theme.textPrimary; font.family: Theme.fontMono; font.pixelSize: Theme.typeMono; elide: Text.ElideRight; Layout.fillWidth: true }
                        Text { text: "Exports / JNI"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                        Text { text: (vm.elfSummary.export_count || 0) + " / " + ((vm.elfSummary.jni_exports || []).length) + " JNI"; color: Theme.textPrimary; font.family: Theme.fontMono; font.pixelSize: Theme.typeMono }

                        Text { text: "Segments"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                        Text { text: (vm.elfSummary.load_segments || 0) + " PT_LOAD" + (vm.elfSummary.elf_16k_alignment ? " (16K)" : " (4K)"); color: Theme.textPrimary; font.family: Theme.fontMono; font.pixelSize: Theme.typeMono }
                        Text { text: "Symbols"; color: Theme.textMuted; font.pixelSize: Theme.typeCaption }
                        Text { text: vm.elfSummary.has_symtab ? ".symtab + .dynsym" : "Chỉ .dynsym (stripped)"; color: Theme.textPrimary; font.family: Theme.fontMono; font.pixelSize: Theme.typeMono }
                    }

                    Flow {
                        Layout.fillWidth: true
                        spacing: 6
                        Repeater {
                            model: vm.elfSummary.needed || []
                            StudioBadge {
                                text: modelData
                                tone: "neutral"
                                monospace: true
                            }
                        }
                    }
                }

                StudioCard {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    title: "Kiểm tra Hardening gốc (chỉ đọc)"
                    badgeText: "Read-only Audit"
                    badgeTone: "info"

                    Flow {
                        Layout.fillWidth: true
                        spacing: 6

                        StudioBadge {
                            readonly property var relro: vm.hardeningSummary.relro || {}
                            text: "RELRO: " + (relro.segment_present ? (relro.bind_now ? "Full (BIND_NOW)" : "Partial") : "Absent")
                            tone: relro.segment_present && relro.bind_now ? "accent" : "warn"
                        }
                        StudioBadge {
                            text: "NX Stack: " + (vm.hardeningSummary.nonexecutable_stack || "?")
                            tone: vm.hardeningSummary.nonexecutable_stack === "observed" ? "accent" : "warn"
                        }
                        StudioBadge {
                            text: "Canary: " + (vm.hardeningSummary.stack_canary_import === "observed_not_function_coverage" ? "__stack_chk_fail" : "chưa thấy")
                            tone: vm.hardeningSummary.stack_canary_import === "observed_not_function_coverage" ? "info" : "neutral"
                        }
                        StudioBadge {
                            text: "FORTIFY: " + ((vm.hardeningSummary.fortify_imports || []).length) + " hàm"
                            tone: "neutral"
                        }
                        StudioBadge {
                            text: "GNU Property/BTI: " + (vm.hardeningSummary.gnu_property_note_present ? "Có" : "Không")
                            tone: "neutral"
                        }
                    }

                    Text {
                        text: vm.hardeningSummary.limits || ""
                        color: Theme.textMuted
                        font.pixelSize: Theme.typeCaption
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }

            // Virtualized Function Explorer
            StudioCard {
                Layout.fillWidth: true
                Layout.fillHeight: true
                title: "Danh sách hàm khôi phục (F01 / chấm điểm A03)"
                subtitle: "Bấm nút +VM / +Flat / +Obf / +Enc / +R07 để gắn pass trực tiếp cho hàm tương thích"
                badgeText: fnModel.filteredCount + " / " + fnModel.totalCount + " hàm"
                badgeTone: "accent"

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp8

                    StudioField {
                        id: searchField
                        Layout.preferredWidth: 260
                        placeholder: "Tìm tên hàm hoặc địa chỉ 0x..."
                        monospace: true
                        onTextChanged: root.updateFilter()
                    }

                    Flow {
                        Layout.fillWidth: true
                        spacing: 6
                        Repeater {
                            model: [
                                { id: "all", label: "Tất cả (" + fnModel.totalCount + ")" },
                                { id: "vm", label: "VM Ready (" + fnModel.vmCount + ")" },
                                { id: "relocatable", label: "Relocatable (" + fnModel.relocatableCount + ")" },
                                { id: "jni", label: "JNI (" + fnModel.jniCount + ")" },
                                { id: "exported", label: "Exports" },
                                { id: "fde", label: ".eh_frame FDE" },
                                { id: "assigned", label: "Đã gán pass" }
                            ]
                            StudioButton {
                                text: modelData.label
                                compact: true
                                variant: root.activeCategory === modelData.id ? "primary" : "secondary"
                                onClicked: {
                                    root.activeCategory = modelData.id
                                    root.updateFilter()
                                }
                            }
                        }
                        StudioButton {
                            text: "Gán nhanh top VM + Flatten"
                            compact: true
                            variant: "primary"
                            enabled: !vm.busy && vm.hasElf
                            onClicked: vm.autoPopulateFunctions()
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    visible: vm.planHasError
                    implicitHeight: inspectorConflictCol.implicitHeight + 18
                    Layout.minimumHeight: implicitHeight
                    radius: Theme.radSm
                    color: Theme.dangerDim
                    border.width: 1
                    border.color: Theme.danger

                    ColumnLayout {
                        id: inspectorConflictCol
                        anchors.fill: parent
                        anchors.margins: 9
                        spacing: 4

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.sp8
                            Text {
                                Layout.fillWidth: true
                                text: vm.planSummaryText
                                color: Theme.danger
                                font.family: Theme.fontUi
                                font.pixelSize: Theme.typeCaption
                                font.weight: Font.DemiBold
                                wrapMode: Text.WordWrap
                            }
                            StudioButton {
                                text: vm.hasElf ? "Tự chỉnh cho .so này" : "Tự gỡ xung đột"
                                compact: true
                                variant: "secondary"
                                onClicked: vm.adaptOptionsToLoadedElf()
                            }
                        }

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

                // Table Header
                Rectangle {
                    Layout.fillWidth: true
                    height: Math.round(34 * Math.min(1.25, Theme.fontScale))
                    color: Theme.bgElevated
                    radius: Theme.radSm
                    border.width: 1
                    border.color: Theme.borderSubtle

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        spacing: 8
                        Text { text: "VA"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; font.weight: Font.DemiBold; Layout.preferredWidth: 92 }
                        Text { text: "Tên hàm / FDE"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; font.weight: Font.DemiBold; Layout.fillWidth: true }
                        Text { text: "Size"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; font.weight: Font.DemiBold; Layout.preferredWidth: 66; horizontalAlignment: Text.AlignRight }
                        Text { text: "Nguồn"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; font.weight: Font.DemiBold; Layout.preferredWidth: 98 }
                        Text { text: "A03"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; font.weight: Font.DemiBold; Layout.preferredWidth: 44; horizontalAlignment: Text.AlignRight }
                        Text { text: "Khả năng & Gán nhanh"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; font.weight: Font.DemiBold; Layout.preferredWidth: Math.round(400 * Math.min(1.25, Theme.fontScale)) }
                    }
                }

                ListView {
                    id: fnListView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    cacheBuffer: 320
                    model: fnModel
                    boundsBehavior: Flickable.StopAtBounds
                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                    delegate: Rectangle {
                        width: fnListView.width
                        height: Math.round(42 * Math.min(1.25, Theme.fontScale))
                        color: index % 2 === 1 ? Theme.bgRowAlt : "transparent"

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 10
                            anchors.rightMargin: 10
                            spacing: 8

                            Text {
                                text: vaddrHex
                                color: Theme.info
                                font.family: Theme.fontMono
                                font.pixelSize: Theme.typeMono
                                Layout.preferredWidth: 92
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 6
                                Text {
                                    text: name
                                    color: isJni ? Theme.accent : (isExported ? Theme.textPrimary : Theme.textSecondary)
                                    font.family: Theme.fontMono
                                    font.pixelSize: Theme.typeMono
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                                StudioBadge {
                                    visible: assignedTag !== ""
                                    text: assignedTag
                                    tone: "accent"
                                    monospace: true
                                }
                            }

                            Text {
                                text: fnSize + " B"
                                color: Theme.textMuted
                                font.family: Theme.fontMono
                                font.pixelSize: Theme.typeCaption
                                Layout.preferredWidth: 66
                                horizontalAlignment: Text.AlignRight
                            }

                            Text {
                                text: source === "eh_frame_fde" ? "eh_frame" : source
                                color: Theme.textMuted
                                font.family: Theme.fontMono
                                font.pixelSize: Theme.typeCaption
                                Layout.preferredWidth: 98
                                elide: Text.ElideRight
                            }

                            Text {
                                text: sensitivity
                                color: sensitivity >= 40 ? Theme.warn : Theme.textSecondary
                                font.family: Theme.fontMono
                                font.pixelSize: Theme.typeMono
                                Layout.preferredWidth: 44
                                horizontalAlignment: Text.AlignRight
                            }

                            Row {
                                Layout.preferredWidth: Math.round(400 * Math.min(1.25, Theme.fontScale))
                                spacing: 4
                                StudioButton {
                                    text: "+VM"; compact: true; variant: "ghost"
                                    enabled: vmCompatible
                                    onClicked: vm.toggleFunctionAssignment(name, "virtualize_functions")
                                }
                                StudioButton {
                                    text: "+Flat"; compact: true; variant: "ghost"
                                    enabled: relocatable
                                    onClicked: vm.toggleFunctionAssignment(name, "flatten_functions")
                                }
                                StudioButton {
                                    text: "+Obf"; compact: true; variant: "ghost"
                                    enabled: relocatable
                                    onClicked: vm.toggleFunctionAssignment(name, "obfuscate_functions")
                                }
                                StudioButton {
                                    text: "+Enc"; compact: true; variant: "ghost"
                                    onClicked: vm.toggleFunctionAssignment(name, "encrypt_functions")
                                }
                                StudioButton {
                                    text: "+R07"; compact: true; variant: "ghost"
                                    enabled: relocatable
                                    onClicked: vm.toggleFunctionAssignment(name, "on_demand_functions")
                                }
                                StudioButton {
                                    text: "Deny"; compact: true; variant: "ghost"
                                    onClicked: vm.toggleFunctionAssignment(name, "denylist_functions")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
