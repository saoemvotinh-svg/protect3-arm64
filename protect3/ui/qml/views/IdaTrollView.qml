import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Dialogs
import QtQuick.Layouts
import Protect3Theme
import "../components"

Item {
    id: root
    property int selectedIndex: 0

    function syncFormFromSelection() {
        if (decoyModel.count <= 0) return
        if (root.selectedIndex < 0) root.selectedIndex = 0
        if (root.selectedIndex >= decoyModel.count) root.selectedIndex = decoyModel.count - 1
        var row = vm.getDecoy(root.selectedIndex)
        editNameField.text = row.name || ""
        editMainField.text = row.main || ""
        editAltField.text = row.alt || ""
        decoyList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
    }

    Connections {
        target: decoyModel
        function onModelReset() { root.syncFormFromSelection() }
        function onCountChanged() { root.syncFormFromSelection() }
    }

    Component.onCompleted: syncFormFromSelection()

    FileDialog {
        id: importDialog
        title: "Nạp danh sách hàm & chuỗi troll"
        nameFilters: ["Troll lists (*.json *.txt)", "All files (*)"]
        onAccepted: vm.importDecoysFile(selectedFile.toString())
    }

    FileDialog {
        id: exportDialog
        title: "Xuất danh sách hàm & chuỗi troll"
        fileMode: FileDialog.SaveFile
        defaultSuffix: "json"
        nameFilters: ["JSON (*.json)", "Text lines (*.txt)"]
        onAccepted: vm.exportDecoysFile(selectedFile.toString())
    }

    // Bulk text / JSON editor popup window
    Popup {
        id: bulkPopup
        anchors.centerIn: Overlay.overlay
        width: Math.min(820, root.width - 40)
        height: Math.min(540, root.height - 40)
        modal: true
        focus: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

        background: Rectangle {
            color: Theme.bgSurface
            radius: Theme.radLg
            border.width: 1
            border.color: Theme.borderStrong
        }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: Theme.sp16
            spacing: Theme.sp12

            Text {
                text: "Sửa nhanh hàng loạt (mỗi dòng: Ten_Ham | String chinh | String phu hoặc JSON)"
                color: Theme.textPrimary
                font.pixelSize: Theme.typeHeading
                font.weight: Font.DemiBold
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
                        id: bulkArea
                        color: Theme.textPrimary
                        font.family: Theme.fontMono
                        font.pixelSize: Theme.typeMono
                        wrapMode: TextEdit.WrapAnywhere
                        selectByMouse: true
                        background: Item {}
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                StudioButton { text: "Hủy"; onClicked: bulkPopup.close() }
                StudioButton {
                    text: "Áp dụng danh sách"
                    variant: "primary"
                    iconName: "check"
                    onClicked: {
                        vm.applyBulkDecoys(bulkArea.text)
                        bulkPopup.close()
                    }
                }
            }
        }
    }

    ScrollView {
        id: pageScroll
        anchors.fill: parent
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: pageScroll.availableWidth
            height: Math.max(implicitHeight, pageScroll.availableHeight)
            spacing: Theme.sp12

        // Top Mode Explanation + Barcode Randomizer Studio
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.sp12

            StudioCard {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                title: "Cơ chế chống soi IDA Pro / Decompiler & Hex-Rays F5"
                badgeText: vm.options.block_ida && vm.options.troll_ida ? "Ẩn code thật + Hiện bẫy F5" : (vm.options.troll_ida ? "Đổi tên mã vạch + Bẫy" : (vm.options.block_ida ? "Chỉ ẩn code (0 sub)" : "Đang tắt"))
                badgeTone: vm.options.troll_ida || vm.options.block_ida ? "accent" : "neutral"

                StudioSwitch {
                    title: "Troll IDA Pro: đổi tên hàm & bơm hàm bẫy F5 (--troll-ida)"
                    subtitle: "Tạo .symtab/.strtab với tên ngẫu nhiên + các hàm ARM64 trả về chuỗi troll khi người soi nhấn F5 / Ctrl+F5"
                    badgeText: "Decoys"
                    checked: !!vm.options.troll_ida
                    conflictText: (vm.optionConflicts && vm.optionConflicts["troll_ida"]) || ""
                    onToggled: function(v) { vm.setOption("troll_ida", v) }
                }

                StudioSwitch {
                    title: "Ẩn code thật trên IDA: xóa segment .text/.guard (--block-ida)"
                    subtitle: "Dùng section SHT_NOBITS+SHF_TLS làm IDA gộp code thật thành vùng .tls trống (Bionic/BlueStacks vẫn chạy bình thường). Tắt mục này nếu muốn IDA hiện danh sách hàng nghìn hàm mã vạch."
                    badgeText: "TLS Wipe"
                    badgeTone: "violet"
                    checked: !!vm.options.block_ida
                    conflictText: (vm.optionConflicts && vm.optionConflicts["block_ida"]) || ""
                    onToggled: function(v) { vm.setOption("block_ida", v) }
                }
            }

            StudioCard {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                title: "Tùy chỉnh chuỗi Random Mã vạch (tự xáo vị trí theo độ dài)"
                badgeText: "Length: " + (vm.options.troll_barcode_length || 0)
                badgeTone: "info"

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp8

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp8
                        StudioField {
                            Layout.fillWidth: true
                            label: "Bộ ký tự nguồn (vd: IlO0):"
                            monospace: true
                            text: vm.options.troll_barcode_chars !== undefined ? String(vm.options.troll_barcode_chars) : "IlO0"
                            conflictText: (vm.optionConflicts && vm.optionConflicts["troll_barcode_chars"]) || ""
                            onEditedText: function(t) { vm.setOption("troll_barcode_chars", t) }
                            onAcceptedText: function(t) { vm.setOption("troll_barcode_chars", t) }
                        }
                        StudioButton {
                            text: "Random thử"
                            iconName: "shuffle"
                            Layout.alignment: Qt.AlignBottom
                            onClicked: vm.shuffleBarcodePreview()
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Text {
                            text: "Độ dài chuỗi random (0 = tên trần):"
                            color: Theme.textSecondary
                            font.pixelSize: Theme.typeSmall
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8
                            Slider {
                                Layout.fillWidth: true
                                from: 0
                                to: 64
                                stepSize: 1
                                value: {
                                    var n = parseInt(vm.options.troll_barcode_length, 10)
                                    return isNaN(n) ? 0 : Math.max(0, Math.min(64, n))
                                }
                                onMoved: vm.setOption("troll_barcode_length", Math.round(value))
                            }
                            StudioField {
                                Layout.preferredWidth: 96
                                monospace: true
                                text: String(vm.options.troll_barcode_length !== undefined ? vm.options.troll_barcode_length : 17)
                                conflictText: (vm.optionConflicts && vm.optionConflicts["troll_barcode_length"]) || ""
                                onEditedText: function(t) { vm.setOption("troll_barcode_length", t) }
                                onAcceptedText: function(t) { vm.setOption("troll_barcode_length", t) }
                            }
                        }
                    }
                }

                Text {
                    text: "Xem trước tên hàm sẽ xuất hiện trong IDA Functions:"
                    color: Theme.textMuted
                    font.pixelSize: Theme.typeCaption
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4
                    Repeater {
                        model: vm.barcodePreviews
                        Rectangle {
                            Layout.fillWidth: true
                            height: Math.round(28 * Math.min(1.25, Theme.fontScale))
                            radius: Theme.radSm
                            color: Theme.bgInput
                            border.width: 1
                            border.color: Theme.borderSubtle
                            Text {
                                anchors.fill: parent
                                anchors.leftMargin: 8
                                anchors.rightMargin: 8
                                verticalAlignment: Text.AlignVCenter
                                text: modelData
                                color: Theme.accent
                                font.family: Theme.fontMono
                                font.pixelSize: Theme.typeMono
                                elide: Text.ElideRight
                            }
                        }
                    }
                }
            }
        }

        // Full Interactive Decoy Function & F5 Troll String Editor
        StudioCard {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.minimumHeight: Math.round(350 * Math.min(1.2, Theme.fontScale))
            title: "Danh sách tên hàm & chuỗi troll F5 (" + decoyModel.count + " mục)"
            subtitle: "Chọn 1 dòng để chỉnh sửa, thêm mới, sắp xếp thứ tự hoặc dán hàng loạt"
            badgeText: vm.customDecoysModified ? "ĐÃ TÙY CHỈNH" : (vm.defaultDecoysCount + " MẪU MẶC ĐỊNH")
            badgeTone: vm.customDecoysModified ? "warn" : "accent"

            RowLayout {
                Layout.fillWidth: true
                spacing: 6
                StudioButton {
                    text: "Sửa nhanh (Text/JSON)"
                    iconName: "terminal"
                    compact: true
                    onClicked: {
                        bulkArea.text = vm.exportDecoysBulkText()
                        bulkPopup.open()
                    }
                }
                StudioButton { text: "Nạp file (.txt/.json)"; iconName: "folder"; compact: true; onClicked: importDialog.open() }
                StudioButton { text: "Xuất file…"; iconName: "copy"; compact: true; onClicked: exportDialog.open() }
                Item { Layout.fillWidth: true }
                StudioButton {
                    text: "Khôi phục " + vm.defaultDecoysCount + " câu mặc định"
                    iconName: "refresh"
                    compact: true
                    onClicked: {
                        root.selectedIndex = 0
                        vm.resetDefaultDecoys()
                        root.syncFormFromSelection()
                    }
                }
            }

            // Decoy Table
            Rectangle {
                Layout.fillWidth: true
                height: Math.round(34 * Math.min(1.25, Theme.fontScale))
                radius: Theme.radSm
                color: Theme.bgElevated
                border.width: 1
                border.color: Theme.borderSubtle
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 10
                    anchors.rightMargin: 10
                    spacing: 10
                    Text { text: "#"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; Layout.preferredWidth: 26 }
                    Text { text: "Tên hàm (trong IDA Functions)"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; Layout.preferredWidth: 260 }
                    Text { text: "String troll chính (F5 nhánh else)"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; Layout.fillWidth: true }
                    Text { text: "String phụ (a1 == 1337)"; color: Theme.textSecondary; font.pixelSize: Theme.typeCaption; Layout.preferredWidth: 230 }
                }
            }

            ListView {
                id: decoyList
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: decoyModel
                currentIndex: root.selectedIndex
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                delegate: Rectangle {
                    id: rowDel
                    width: decoyList.width
                    height: 34
                    color: index === root.selectedIndex ? Theme.accentDim : (index % 2 === 1 ? Theme.bgRowAlt : "transparent")
                    border.width: index === root.selectedIndex ? 1 : 0
                    border.color: Theme.borderFocus

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        spacing: 10
                        Text { text: rowIndex; color: Theme.textMuted; font.family: Theme.fontMono; font.pixelSize: Theme.typeCaption; Layout.preferredWidth: 26 }
                        Text { text: decoyName; color: Theme.textPrimary; font.family: Theme.fontMono; font.pixelSize: Theme.typeMono; elide: Text.ElideRight; Layout.preferredWidth: 260 }
                        Text { text: mainMsg; color: Theme.textSecondary; font.family: Theme.fontMono; font.pixelSize: Theme.typeMono; elide: Text.ElideRight; Layout.fillWidth: true }
                        Text { text: altMsg; color: Theme.textMuted; font.family: Theme.fontMono; font.pixelSize: Theme.typeCaption; elide: Text.ElideRight; Layout.preferredWidth: 230 }
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            root.selectedIndex = index
                            editNameField.text = decoyName
                            editMainField.text = mainMsg
                            editAltField.text = altMsg
                        }
                    }

                    Component.onCompleted: {
                        if (index === root.selectedIndex && editNameField.text === "") {
                            editNameField.text = decoyName
                            editMainField.text = mainMsg
                            editAltField.text = altMsg
                        }
                    }
                }
            }

            // Inline Item Editor Strip
            Rectangle {
                Layout.fillWidth: true
                height: editCol.implicitHeight + 16
                color: Theme.bgInput
                radius: Theme.radSm
                border.width: 1
                border.color: Theme.borderSubtle

                ColumnLayout {
                    id: editCol
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 8

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8
                        StudioField {
                            id: editNameField
                            Layout.preferredWidth: 250
                            label: "Tên hàm:"
                            placeholder: "Ten_Ham_Troll_01"
                            monospace: true
                        }
                        StudioField {
                            id: editMainField
                            Layout.fillWidth: true
                            label: "String troll chính (F5):"
                            placeholder: "[Protect3] Chuoi hien trong F5..."
                            monospace: true
                        }
                        StudioField {
                            id: editAltField
                            Layout.preferredWidth: 240
                            label: "String nhánh a1 == 1337 (tùy chọn):"
                            placeholder: "Tự sinh nếu để trống"
                            monospace: true
                        }
                    }

                    Flow {
                        Layout.fillWidth: true
                        spacing: 6
                        StudioButton {
                            text: "Cập nhật dòng #" + (root.selectedIndex + 1)
                            variant: "primary"
                            iconName: "check"
                            compact: true
                            onClicked: vm.updateDecoy(root.selectedIndex, editNameField.text, editMainField.text, editAltField.text)
                        }
                        StudioButton {
                            text: "Thêm dòng mới"
                            iconName: "plus"
                            compact: true
                            onClicked: {
                                vm.addDecoy(editNameField.text, editMainField.text, editAltField.text)
                                root.selectedIndex = Math.max(0, decoyModel.count - 1)
                            }
                        }
                        StudioButton {
                            text: "Lên"
                            compact: true
                            enabled: root.selectedIndex > 0
                            onClicked: {
                                var target = root.selectedIndex - 1
                                root.selectedIndex = target
                                vm.moveDecoy(target + 1, -1)
                                root.syncFormFromSelection()
                            }
                        }
                        StudioButton {
                            text: "Xuống"
                            compact: true
                            enabled: root.selectedIndex < decoyModel.count - 1
                            onClicked: {
                                var target = root.selectedIndex + 1
                                root.selectedIndex = target
                                vm.moveDecoy(target - 1, 1)
                                root.syncFormFromSelection()
                            }
                        }
                        StudioButton {
                            text: "Xóa dòng"
                            variant: "danger"
                            iconName: "trash"
                            compact: true
                            enabled: decoyModel.count > 1
                            onClicked: {
                                var idx = root.selectedIndex
                                root.selectedIndex = Math.max(0, Math.min(idx, decoyModel.count - 2))
                                vm.deleteDecoy(idx)
                                root.syncFormFromSelection()
                            }
                        }
                    }
                }
            }
        }
    }
    }
}
