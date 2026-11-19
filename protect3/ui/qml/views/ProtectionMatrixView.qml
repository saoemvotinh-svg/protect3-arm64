import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts
import Protect3Theme
import "../components"

Item {
    id: root
    signal requestBrowseNdk()
    signal requestSaveProfile()
    signal requestLoadProfile()

    ColumnLayout {
        anchors.fill: parent
        spacing: Theme.sp12

        // Profile Presets & Live Conflict Status Strip
        StudioCard {
            Layout.fillWidth: true
            title: "Preset nhanh & Kiểm tra tương thích kế hoạch (F05)"
            badgeText: vm.planHasError ? "CÓ XUNG ĐỘT" : "KẾ HOẠCH HỢP LỆ"
            badgeTone: vm.planHasError ? "danger" : "accent"

            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.sp8

                Flow {
                    Layout.fillWidth: true
                    spacing: 6
                    Repeater {
                        model: [
                            { id: "bluestacks_safe", label: "BlueStacks / Test (Chỉ ghi log)" },
                            { id: "apk_anti_cheat", label: "Chặn GG & Dump RAM (APK Release)" },
                            { id: "anti_virbox", label: "Anti-Virbox (E09 Packer + O10)" },
                            { id: "compat", label: "Compat (E04/E05/E07)" },
                            { id: "balanced", label: "Balanced (O01-O06 + R02/R04)" },
                            { id: "anti-analysis", label: "Anti-Analysis (Full O07/O10/E03)" },
                            { id: "max", label: "Max (E09 Packer + VM Auto)" },
                            { id: "minimal", label: "Tối thiểu (Chỉ Guard)" }
                        ]
                        StudioButton {
                            text: modelData.label
                            compact: true
                            variant: (modelData.id === "bluestacks_safe" || modelData.id === "apk_anti_cheat" || modelData.id === "anti_virbox") ? "primary" : "secondary"
                            onClicked: vm.applyPreset(modelData.id)
                        }
                    }
                }

                StudioButton { text: "Lưu preset"; iconName: "copy"; compact: true; onClicked: root.requestSaveProfile() }
                StudioButton { text: "Nạp preset"; iconName: "folder"; compact: true; onClicked: root.requestLoadProfile() }
            }

            Rectangle {
                Layout.fillWidth: true
                implicitHeight: planCol.implicitHeight + 20
                Layout.minimumHeight: implicitHeight
                radius: Theme.radSm
                color: vm.planHasError ? Theme.dangerDim : Theme.bgInput
                border.width: 1
                border.color: vm.planHasError ? Theme.danger : Theme.borderSubtle

                ColumnLayout {
                    id: planCol
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 6

                    RowLayout {
                        id: planRow
                        Layout.fillWidth: true
                        spacing: Theme.sp8

                        Text {
                            id: planText
                            Layout.fillWidth: true
                            text: vm.planSummaryText
                            color: vm.planHasError ? Theme.danger : Theme.accent
                            font.family: Theme.fontUi
                            font.pixelSize: Theme.typeSmall
                            font.weight: vm.planHasError ? Font.DemiBold : Font.Normal
                            wrapMode: Text.WordWrap
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

            Rectangle {
                Layout.fillWidth: true
                visible: !!vm.options.report_only && (!!vm.options.anti_gg || !!vm.options.gg_honeypot || !!vm.options.debugger)
                implicitHeight: warnRow.implicitHeight + 16
                Layout.minimumHeight: implicitHeight
                radius: Theme.radSm
                color: Theme.warnDim
                border.width: 1
                border.color: Theme.warn

                RowLayout {
                    id: warnRow
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: Theme.sp8
                    Text {
                        Layout.fillWidth: true
                        text: "Cảnh báo: Đang bật 'Chỉ ghi log (report_only)' — app sẽ KHÔNG tự thoát khi GameGuardian quét RAM hay phát hiện debugger!"
                        color: Theme.warn
                        font.family: Theme.fontUi
                        font.pixelSize: Theme.typeCaption
                        font.weight: Font.DemiBold
                        wrapMode: Text.WordWrap
                    }
                    StudioButton {
                        text: "Bật Chặn Thật"
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
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth

            ColumnLayout {
                width: parent.width
                spacing: Theme.sp12

                // Row 1: Crypto (E01-E08) & Obfuscation/VM (O01-O09)
                GridLayout {
                    Layout.fillWidth: true
                    columns: width >= 880 ? 2 : 1
                    columnSpacing: Theme.sp12
                    rowSpacing: Theme.sp12

                    StudioCard {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignTop
                        title: "Mã hóa, Xác thực & Đóng gói (E01–E09)"
                        badgeText: "Crypto"
                        badgeTone: "info"

                        StudioSwitch {
                            title: "Nén DEFLATE & mã hóa toàn PT_LOAD/relocs/imports trong RAM"
                            subtitle: "Khuyến nghị #1: ẩn 100% chuỗi, FDE, import & thu nhỏ ~60% file; hỗ trợ cả C++ STT_OBJECT/RTTI (E09)"
                            badgeText: "E09"
                            badgeTone: "accent"
                            checked: !!vm.options.pack_elf
                            conflictText: (vm.optionConflicts && vm.optionConflicts["pack_elf"]) || ""
                            onToggled: function(v) { vm.setOption("pack_elf", v) }
                        }
                        StudioSwitch {
                            title: "Mã hóa toàn .text bằng ChaCha20"
                            subtitle: "Khôi phục code khi nạp; loại trừ hàm dùng chung với mã hóa theo danh sách"
                            badgeText: "E01"
                            checked: !!vm.options.encrypt_text
                            conflictText: (vm.optionConflicts && vm.optionConflicts["encrypt_text"]) || ""
                            onToggled: function(v) { vm.setOption("encrypt_text", v) }
                        }
                        StudioSwitch {
                            title: "Mã hóa vùng .rodata + .eh_frame/.gcc_except_table (chuỗi / hằng tĩnh)"
                            subtitle: "Giải mã có xác thực ở giai đoạn init"
                            badgeText: "E02"
                            checked: !!vm.options.encrypt_rodata
                            conflictText: (vm.optionConflicts && vm.optionConflicts["encrypt_rodata"]) || ""
                            onToggled: function(v) { vm.setOption("encrypt_rodata", v) }
                        }
                        StudioSwitch {
                            title: "Mã hóa vùng RW .data (bỏ qua pointer relocation tự động)"
                            subtitle: "Ẩn biến cấu hình/chuỗi nằm trong .data trên đĩa"
                            badgeText: "E02+"
                            checked: !!vm.options.encrypt_data
                            conflictText: (vm.optionConflicts && vm.optionConflicts["encrypt_data"]) || ""
                            onToggled: function(v) { vm.setOption("encrypt_data", v) }
                        }
                        StudioSwitch {
                            title: "String Vault giải mã lười khi thực thi"
                            subtitle: "Tách chuỗi vào trang 16 KiB riêng; tự tách khỏi .rodata nên bật song song E02 được"
                            badgeText: "E03"
                            checked: !!vm.options.encrypt_strings
                            conflictText: (vm.optionConflicts && vm.optionConflicts["encrypt_strings"]) || ""
                            onToggled: function(v) { vm.setOption("encrypt_strings", v) }
                        }
                        StudioSwitch {
                            title: "Xác thực HMAC-SHA256 trước khi mprotect/giải mã"
                            badgeText: "E04"
                            checked: !!vm.options.auth_encryption
                            conflictText: (vm.optionConflicts && vm.optionConflicts["auth_encryption"]) || ""
                            onToggled: function(v) { vm.setOption("auth_encryption", v) }
                        }
                        StudioSwitch {
                            title: "Ký & xác minh manifest bảo vệ trong guard"
                            badgeText: "E05"
                            checked: !!vm.options.sign_manifest
                            conflictText: (vm.optionConflicts && vm.optionConflicts["sign_manifest"]) || ""
                            onToggled: function(v) { vm.setOption("sign_manifest", v) }
                        }
                        StudioSwitch {
                            title: "Dẫn xuất khóa split-key HMAC KDF (giảm lộ key tĩnh)"
                            badgeText: "E07"
                            checked: !!vm.options.masked_key
                            conflictText: (vm.optionConflicts && vm.optionConflicts["masked_key"]) || ""
                            onToggled: function(v) { vm.setOption("masked_key", v) }
                        }
                        StudioSwitch {
                            title: "Xóa metadata .comment / .debug không cần chạy"
                            badgeText: "E06"
                            checked: !!vm.options.clean_metadata
                            conflictText: (vm.optionConflicts && vm.optionConflicts["clean_metadata"]) || ""
                            onToggled: function(v) { vm.setOption("clean_metadata", v) }
                        }
                        StudioSwitch {
                            title: "Xóa symbol/debug thừa bằng NDK llvm-strip"
                            subtitle: "Cần NDK; F01 vẫn phân tích ranh giới hàm trước khi strip"
                            badgeText: "NDK"
                            checked: !!vm.options.strip_symbols
                            conflictText: (vm.optionConflicts && vm.optionConflicts["strip_symbols"]) || ""
                            onToggled: function(v) { vm.setOption("strip_symbols", v) }
                        }
                        StudioSwitch {
                            title: "Bọc toàn bộ ELF trong wrapper .so (memfd/dlopen)"
                            subtitle: "Chỉ hỗ trợ C .so export hàm (STT_FUNC); KHÔNG hỗ trợ C++ RTTI/vtable STT_OBJECT (hãy dùng E09)"
                            badgeText: "E08"
                            checked: !!vm.options.wrap_elf
                            conflictText: (vm.optionConflicts && vm.optionConflicts["wrap_elf"]) || ""
                            onToggled: function(v) { vm.setOption("wrap_elf", v) }
                        }

                        StudioField {
                            Layout.fillWidth: true
                            label: "Mã hóa hàm/vùng cụ thể (E01, cách nhau dấu phẩy):"
                            placeholder: "vd: fde_73030, my_check_func"
                            monospace: true
                            text: String(vm.options.encrypt_functions || vm.options.encrypt_function || "")
                            conflictText: (vm.optionConflicts && (vm.optionConflicts["encrypt_functions"] || vm.optionConflicts["encrypt_function"])) || ""
                            onEditedText: function(t) { vm.setOption("encrypt_functions", t) }
                            onAcceptedText: function(t) { vm.setOption("encrypt_functions", t) }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.sp8
                            StudioField {
                                Layout.fillWidth: true
                                label: "Đường dẫn Android NDK (cho llvm-strip / wrap-elf / build-runtime):"
                                monospace: true
                                text: vm.ndkPath
                                conflictText: (vm.optionConflicts && vm.optionConflicts["ndk_path"]) || ""
                                onAcceptedText: function(t) { vm.ndkPath = t }
                            }
                            StudioButton {
                                text: "Chọn NDK…"
                                Layout.alignment: Qt.AlignBottom
                                onClicked: root.requestBrowseNdk()
                            }
                        }

                        StudioField {
                            Layout.fillWidth: true
                            label: "Lưu bản sao debug trước strip (E06 --keep-debug, tùy chọn):"
                            placeholder: "Để trống nếu không cần xuất bản unstripped backup"
                            monospace: true
                            text: String(vm.options.keep_debug || "")
                            conflictText: (vm.optionConflicts && vm.optionConflicts["keep_debug"]) || ""
                            onEditedText: function(t) { vm.setOption("keep_debug", t) }
                            onAcceptedText: function(t) { vm.setOption("keep_debug", t) }
                        }
                    }

                    StudioCard {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignTop
                        title: "Làm rối lệnh Native, Self-Obfuscation & ARM64 VM (O01–O10)"
                        badgeText: "Obfuscation & VM"
                        badgeTone: "violet"

                        StudioSwitch {
                            title: "Làm rối lệnh MBA, hằng ẩn, vị từ bất biến & xáo trộn khối"
                            badgeText: "O01–O06"
                            badgeTone: "violet"
                            checked: !!vm.options.obfuscate_ops
                            conflictText: (vm.optionConflicts && vm.optionConflicts["obfuscate_ops"]) || ""
                            onToggled: function(v) { vm.setOption("obfuscate_ops", v) }
                        }
                        StudioSwitch {
                            title: "Tự làm rối chính Guard Runtime & chèn bẫy <unknown>"
                            subtitle: "Di dời C helpers của guard kèm CFF/MBA/OPAQUE mỗi lần build (O10)"
                            badgeText: "O10"
                            badgeTone: "violet"
                            checked: !!vm.options.obfuscate_guard
                            conflictText: (vm.optionConflicts && vm.optionConflicts["obfuscate_guard"]) || ""
                            onToggled: function(v) { vm.setOption("obfuscate_guard", v) }
                        }
                        StudioSwitch {
                            title: "Control-Flow Flattening (biến đổi thành state-machine CSEL)"
                            badgeText: "O07"
                            badgeTone: "violet"
                            checked: !!vm.options.flatten_cfg
                            conflictText: (vm.optionConflicts && vm.optionConflicts["flatten_cfg"]) || ""
                            onToggled: function(v) { vm.setOption("flatten_cfg", v) }
                        }
                        StudioSwitch {
                            title: "Tự chọn hàm tương thích đưa vào ARM64 Bytecode VM"
                            subtitle: "Hoán vị opcode + mã hóa bytecode theo từng bản build (O09)"
                            badgeText: "O08/O09"
                            badgeTone: "violet"
                            checked: !!vm.options.virtualize_auto
                            conflictText: (vm.optionConflicts && vm.optionConflicts["virtualize_auto"]) || ""
                            onToggled: function(v) { vm.setOption("virtualize_auto", v) }
                        }
                        StudioSwitch {
                            title: "Bảo vệ JNI_OnLoad / Java_* sau thunk kiểm tra runtime"
                            badgeText: "JNI"
                            checked: !!vm.options.obfuscate_jni
                            conflictText: (vm.optionConflicts && vm.optionConflicts["obfuscate_jni"]) || ""
                            onToggled: function(v) { vm.setOption("obfuscate_jni", v) }
                        }
                        StudioSwitch {
                            title: "Tự chọn hàm theo bộ chấm điểm A03 sensitivity/cost"
                            badgeText: "A03"
                            checked: !!vm.options.auto_select_functions
                            conflictText: (vm.optionConflicts && vm.optionConflicts["auto_select_functions"]) || ""
                            onToggled: function(v) { vm.setOption("auto_select_functions", v) }
                        }

                        StudioField {
                            Layout.fillWidth: true
                            label: "Ảo hóa ARM64 VM theo tên (O08, tối đa 32 hàm):"
                            placeholder: "Chọn ở tab Phân tích hoặc gõ cách nhau dấu phẩy"
                            monospace: true
                            text: String(vm.options.virtualize_functions || "")
                            conflictText: (vm.optionConflicts && vm.optionConflicts["virtualize_functions"]) || ""
                            onEditedText: function(t) { vm.setOption("virtualize_functions", t) }
                            onAcceptedText: function(t) { vm.setOption("virtualize_functions", t) }
                        }
                        StudioField {
                            Layout.fillWidth: true
                            label: "Làm phẳng CFG theo tên (O07):"
                            placeholder: "vd: fde_73064"
                            monospace: true
                            text: String(vm.options.flatten_functions || "")
                            conflictText: (vm.optionConflicts && vm.optionConflicts["flatten_functions"]) || ""
                            onEditedText: function(t) { vm.setOption("flatten_functions", t) }
                            onAcceptedText: function(t) { vm.setOption("flatten_functions", t) }
                        }
                        StudioField {
                            Layout.fillWidth: true
                            label: "Làm rối O01–O06 theo tên:"
                            placeholder: "Cách nhau dấu phẩy"
                            monospace: true
                            text: String(vm.options.obfuscate_functions || "")
                            conflictText: (vm.optionConflicts && vm.optionConflicts["obfuscate_functions"]) || ""
                            onEditedText: function(t) { vm.setOption("obfuscate_functions", t) }
                            onAcceptedText: function(t) { vm.setOption("obfuscate_functions", t) }
                        }
                        StudioField {
                            Layout.fillWidth: true
                            label: "Giải mã theo nhu cầu & tái mã hóa sau return (R07):"
                            placeholder: "Chỉ dùng cho hàm không đệ quy / đơn luồng"
                            monospace: true
                            text: String(vm.options.on_demand_functions || "")
                            conflictText: (vm.optionConflicts && vm.optionConflicts["on_demand_functions"]) || ""
                            onEditedText: function(t) { vm.setOption("on_demand_functions", t) }
                            onAcceptedText: function(t) { vm.setOption("on_demand_functions", t) }
                        }
                        StudioField {
                            Layout.fillWidth: true
                            label: "Danh sách loại trừ Denylist (F05):"
                            placeholder: "Các hàm không được biến đổi"
                            monospace: true
                            text: String(vm.options.denylist_functions || "")
                            conflictText: (vm.optionConflicts && vm.optionConflicts["denylist_functions"]) || ""
                            onEditedText: function(t) { vm.setOption("denylist_functions", t) }
                            onAcceptedText: function(t) { vm.setOption("denylist_functions", t) }
                        }
                    }
                }

                // Row 2: Runtime Integrity & Environment Probes (R01-R08) + Verification/Reproducibility (A01, A08, F03)
                GridLayout {
                    Layout.fillWidth: true
                    columns: width >= 880 ? 2 : 1
                    columnSpacing: Theme.sp12
                    rowSpacing: Theme.sp12

                    StudioCard {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignTop
                        title: "Toàn vẹn Runtime, Chống Debug & Tương thích Nạp (R01–R08)"
                        badgeText: "Runtime Guard"
                        badgeTone: "accent"

                        StudioSwitch {
                            title: "Kiểm tra SHA-256 mã khi nạp (DT_INIT)"
                            badgeText: "Load"
                            checked: !!vm.options.integrity
                            conflictText: (vm.optionConflicts && vm.optionConflicts["integrity"]) || ""
                            onToggled: function(v) { vm.setOption("integrity", v) }
                        }
                        StudioSwitch {
                            title: "Kiểm tra toàn vẹn bộ nhớ tại cổng hàm lúc chạy"
                            badgeText: "R01"
                            checked: !!vm.options.runtime_integrity
                            conflictText: (vm.optionConflicts && vm.optionConflicts["runtime_integrity"]) || ""
                            onToggled: function(v) { vm.setOption("runtime_integrity", v) }
                        }
                        StudioSwitch {
                            title: "Kiểm tra byte prologue / inline hook trampoline"
                            badgeText: "R02"
                            checked: !!vm.options.prologue_check
                            conflictText: (vm.optionConflicts && vm.optionConflicts["prologue_check"]) || ""
                            onToggled: function(v) { vm.setOption("prologue_check", v) }
                        }
                        StudioSwitch {
                            title: "Kiểm tra chéo toàn vẹn chính mã & config của guard"
                            badgeText: "R06"
                            checked: !!vm.options.guard_self_check
                            conflictText: (vm.optionConflicts && vm.optionConflicts["guard_self_check"]) || ""
                            onToggled: function(v) { vm.setOption("guard_self_check", v) }
                        }
                        StudioSwitch {
                            title: "Kiểm tra phạm vi đích GOT/PLT (.got.plt)"
                            badgeText: "R03"
                            checked: !!vm.options.got_check
                            conflictText: (vm.optionConflicts && vm.optionConflicts["got_check"]) || ""
                            onToggled: function(v) { vm.setOption("got_check", v) }
                        }
                        StudioSwitch {
                            title: "Kiểm tra SHA-256 bảng con trỏ .data.rel.ro tĩnh"
                            badgeText: "R04"
                            checked: !!vm.options.relro_check
                            conflictText: (vm.optionConflicts && vm.optionConflicts["relro_check"]) || ""
                            onToggled: function(v) { vm.setOption("relro_check", v) }
                        }
                        StudioSwitch {
                            title: "Phát hiện debugger qua TracerPid / wchan (nạp & runtime)"
                            badgeText: "R05"
                            checked: !!vm.options.debugger
                            conflictText: (vm.optionConflicts && vm.optionConflicts["debugger"]) || ""
                            onToggled: function(v) { vm.setOption("debugger", v) }
                        }
                        StudioSwitch {
                            title: "Bật R05 Anti-debug tại cổng hàm runtime"
                            badgeText: "R05+"
                            checked: !!vm.options.runtime_anti_debug
                            conflictText: (vm.optionConflicts && vm.optionConflicts["runtime_anti_debug"]) || ""
                            onToggled: function(v) { vm.setOption("runtime_anti_debug", v) }
                        }
                        StudioSwitch {
                            title: "Honeypot bộ nhớ mồi chống GameGuardian sửa RAM"
                            subtitle: "Rải link & giá trị giả; phát hiện tức thì nếu bị sửa hoặc đóng băng"
                            badgeText: "R09"
                            badgeTone: "accent"
                            checked: !!vm.options.gg_honeypot
                            conflictText: (vm.optionConflicts && vm.optionConflicts["gg_honeypot"]) || ""
                            onToggled: function(v) { vm.setOption("gg_honeypot", v) }
                        }
                        StudioSwitch {
                            title: "Watchdog chống đóng băng SIGSTOP & dấu hiệu GG"
                            subtitle: "Bắt tạm dừng quét RAM bất thường; an toàn trên giả lập root"
                            badgeText: "R09+"
                            badgeTone: "accent"
                            checked: !!vm.options.anti_gg
                            conflictText: (vm.optionConflicts && vm.optionConflicts["anti_gg"]) || ""
                            onToggled: function(v) { vm.setOption("anti_gg", v) }
                        }
                        StudioSwitch {
                            title: "Tự tái mã hóa chuỗi String Vault sau khi dùng"
                            subtitle: "Xóa chuỗi khỏi RAM sau vài lần gọi; CẢNH BÁO: tắt nếu C++ giữ con trỏ tĩnh hoặc dùng ở ImGui 60fps"
                            badgeText: "E03+"
                            checked: !!vm.options.ephemeral_strings
                            conflictText: (vm.optionConflicts && vm.optionConflicts["ephemeral_strings"]) || ""
                            onToggled: function(v) { vm.setOption("ephemeral_strings", v) }
                        }
                        StudioSwitch {
                            title: "ELF tương thích BlueStacks / native bridge (libhoudini)"
                            subtitle: "Giữ vị trí bảng header & dynamic cho bộ dịch ARM64"
                            badgeText: "BlueStacks"
                            badgeTone: "accent"
                            checked: !!vm.options.compat_layout
                            conflictText: (vm.optionConflicts && vm.optionConflicts["compat_layout"]) || ""
                            onToggled: function(v) { vm.setOption("compat_layout", v) }
                        }
                        StudioSwitch {
                            title: "Ghi log giai đoạn native & sự kiện guard vào Android logcat"
                            checked: !!vm.options.diagnostics
                            conflictText: (vm.optionConflicts && vm.optionConflicts["diagnostics"]) || ""
                            onToggled: function(v) { vm.setOption("diagnostics", v) }
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignTop
                        spacing: Theme.sp12

                        StudioCard {
                            Layout.fillWidth: true
                            title: "Probe Môi trường & Chống Attach (cẩn trọng trên giả lập root)"
                            badgeText: "R08 Probes"
                            badgeTone: "warn"

                            StudioSwitch {
                                title: "Dấu hiệu Frida / Xposed trong maps"
                                badgeText: "R08"
                                badgeTone: "warn"
                                checked: !!vm.options.hooks
                                conflictText: (vm.optionConflicts && vm.optionConflicts["hooks"]) || ""
                                onToggled: function(v) { vm.setOption("hooks", v) }
                            }
                            StudioSwitch {
                                title: "Dấu hiệu Root / Magisk / Zygisk / KernelSU"
                                subtitle: "Giữ TẮT khi test trên giả lập đã root"
                                badgeText: "R08"
                                badgeTone: "warn"
                                checked: !!vm.options.root
                                conflictText: (vm.optionConflicts && vm.optionConflicts["root"]) || ""
                                onToggled: function(v) { vm.setOption("root", v) }
                            }
                            StudioSwitch {
                                title: "Dấu hiệu Emulator (qemu / goldfish / BlueStacks)"
                                subtitle: "Giữ TẮT nếu cần chạy trên giả lập"
                                badgeText: "R08"
                                badgeTone: "warn"
                                checked: !!vm.options.emulator
                                conflictText: (vm.optionConflicts && vm.optionConflicts["emulator"]) || ""
                                onToggled: function(v) { vm.setOption("emulator", v) }
                            }
                            StudioSwitch {
                                title: "Deep probes đa tín hiệu (/proc/self/comm, mountinfo)"
                                badgeText: "R08"
                                checked: !!vm.options.deep_probes
                                conflictText: (vm.optionConflicts && vm.optionConflicts["deep_probes"]) || ""
                                onToggled: function(v) { vm.setOption("deep_probes", v) }
                            }
                            StudioSwitch {
                                title: "Chỉ ghi cảnh báo khi phát hiện (KHÔNG thoát app)"
                                subtitle: "Cảnh báo: Bật mục này sẽ KHÔNG kill app khi GameGuardian/Debugger quét RAM! Tắt đi khi build bản chặn thật."
                                badgeText: !!vm.options.report_only ? "Chỉ Log" : "Chặn Thật"
                                badgeTone: !!vm.options.report_only ? "warn" : "accent"
                                checked: !!vm.options.report_only
                                conflictText: (vm.optionConflicts && vm.optionConflicts["report_only"]) || ""
                                onToggled: function(v) { vm.setOption("report_only", v) }
                            }
                            StudioSwitch {
                                title: "Dừng nếu không đọc được /proc/self/*"
                                checked: !!vm.options.strict_proc
                                conflictText: (vm.optionConflicts && vm.optionConflicts["strict_proc"]) || ""
                                onToggled: function(v) { vm.setOption("strict_proc", v) }
                            }
                            StudioSwitch {
                                title: "PR_SET_DUMPABLE=0 (chặn dump /proc/self/mem & attach không root)"
                                subtitle: "Chạy không cần root trong APK; chặn GG VirtualSpace/cùng UID. Tắt chỉ khi app tự đọc /proc/self/mem."
                                badgeText: "No-Root OK"
                                badgeTone: "accent"
                                checked: !!vm.options.deny_attach
                                conflictText: (vm.optionConflicts && vm.optionConflicts["deny_attach"]) || ""
                                onToggled: function(v) { vm.setOption("deny_attach", v) }
                            }
                        }

                        StudioCard {
                            Layout.fillWidth: true
                            title: "Profile, Seed, Watermark & Kiểm chứng (A01–A08, F03)"
                            badgeText: "Reproducibility"
                            badgeTone: "info"

                            StudioField {
                                Layout.fillWidth: true
                                label: "Composite Profile (--profile: rỗng | compat | balanced | anti-analysis | max):"
                                monospace: true
                                text: String(vm.options.profile || "")
                                conflictText: (vm.optionConflicts && vm.optionConflicts["profile"]) || ""
                                onEditedText: function(t) { vm.setOption("profile", t.trim()) }
                                onAcceptedText: function(t) { vm.setOption("profile", t.trim()) }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.sp8
                                StudioField {
                                    Layout.fillWidth: true
                                    label: "Seed đa dạng hóa (A01, để trống = ngẫu nhiên):"
                                    placeholder: "vd: 42 hoặc 0x1337"
                                    monospace: true
                                    text: String(vm.options.seed || "")
                                    conflictText: (vm.optionConflicts && vm.optionConflicts["seed"]) || ""
                                    onEditedText: function(t) { vm.setOption("seed", t) }
                                    onAcceptedText: function(t) { vm.setOption("seed", t) }
                                }
                                StudioField {
                                    Layout.fillWidth: true
                                    label: "Watermark offline (A08 tag):"
                                    placeholder: "vd: release-2026-v1"
                                    monospace: true
                                    text: String(vm.options.watermark || "")
                                    conflictText: (vm.optionConflicts && vm.optionConflicts["watermark"]) || ""
                                    onEditedText: function(t) { vm.setOption("watermark", t) }
                                    onAcceptedText: function(t) { vm.setOption("watermark", t) }
                                }
                            }

                            StudioSwitch {
                                title: "Kiểm chứng ngữ nghĩa bằng Unicorn trước khi lưu (F03)"
                                subtitle: vm.unicornAvailable
                                    ? "Unicorn ARM64 sẵn sàng — sẽ chạy đối chiếu hàm export trước/sau biến đổi"
                                    : "Môi trường chạy GUI này chưa cài package 'unicorn' (không ảnh hưởng build .so)"
                                badgeText: vm.unicornAvailable ? "F03 Ready" : "Optional"
                                badgeTone: vm.unicornAvailable ? "accent" : "neutral"
                                checked: !!vm.options.verify_semantics
                                interactive: vm.unicornAvailable || !!vm.options.verify_semantics
                                conflictText: (vm.optionConflicts && vm.optionConflicts["verify_semantics"]) || ""
                                onToggled: function(v) { vm.setOption("verify_semantics", v) }
                            }
                        }
                    }
                }
            }
        }
    }
}
