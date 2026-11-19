"""Qt list models for virtualized ELF function browsing, IDA troll decoys, and capability tracking."""

from PySide6.QtCore import QAbstractListModel, QModelIndex, Qt, Signal, Slot, Property


class FunctionListModel(QAbstractListModel):
    """Fast virtualized model storing discovered F01/A03 functions with live search & tag filtering."""

    countsChanged = Signal()

    NameRole = Qt.UserRole + 1
    VaddrHexRole = Qt.UserRole + 2
    VaddrRole = Qt.UserRole + 3
    SizeRole = Qt.UserRole + 4
    SourceRole = Qt.UserRole + 5
    RelocatableRole = Qt.UserRole + 6
    VmCompatibleRole = Qt.UserRole + 7
    IsExportedRole = Qt.UserRole + 8
    IsJniRole = Qt.UserRole + 9
    SensitivityRole = Qt.UserRole + 10
    CostRole = Qt.UserRole + 11
    SkipReasonsRole = Qt.UserRole + 12
    AssignedTagRole = Qt.UserRole + 13

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all = []
        self._filtered = []
        self._query = ""
        self._category = "all"
        self._vm_count = 0
        self._relocatable_count = 0
        self._jni_count = 0

    def roleNames(self):
        return {
            self.NameRole: b"name",
            self.VaddrHexRole: b"vaddrHex",
            self.VaddrRole: b"vaddr",
            self.SizeRole: b"fnSize",
            self.SourceRole: b"source",
            self.RelocatableRole: b"relocatable",
            self.VmCompatibleRole: b"vmCompatible",
            self.IsExportedRole: b"isExported",
            self.IsJniRole: b"isJni",
            self.SensitivityRole: b"sensitivity",
            self.CostRole: b"cost",
            self.SkipReasonsRole: b"skipReasons",
            self.AssignedTagRole: b"assignedTag",
        }

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._filtered)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._filtered)):
            return None
        row = self._filtered[index.row()]
        mapping = {
            self.NameRole: row["name"],
            self.VaddrHexRole: row["vaddrHex"],
            self.VaddrRole: row["vaddr"],
            self.SizeRole: row["size"],
            self.SourceRole: row["source"],
            self.RelocatableRole: row["relocatable"],
            self.VmCompatibleRole: row["vmCompatible"],
            self.IsExportedRole: row["isExported"],
            self.IsJniRole: row["isJni"],
            self.SensitivityRole: row["sensitivity"],
            self.CostRole: row["cost"],
            self.SkipReasonsRole: row["skipReasons"],
            self.AssignedTagRole: row["assignedTag"],
        }
        return mapping.get(role)

    @Property(int, notify=countsChanged)
    def totalCount(self):
        return len(self._all)

    @Property(int, notify=countsChanged)
    def filteredCount(self):
        return len(self._filtered)

    @Property(int, notify=countsChanged)
    def vmCount(self):
        return self._vm_count

    @Property(int, notify=countsChanged)
    def relocatableCount(self):
        return self._relocatable_count

    @Property(int, notify=countsChanged)
    def jniCount(self):
        return self._jni_count

    def set_functions(self, items, assignment_lookup=None):
        assignment_lookup = assignment_lookup or {}
        prepared = []
        vm_count = 0
        reloc_count = 0
        jni_count = 0
        for fn in items:
            reloc = bool(fn.relocatable)
            vm_ok = bool(fn.vm_compatible)
            is_jni = bool(fn.is_jni)
            if vm_ok:
                vm_count += 1
            if reloc:
                reloc_count += 1
            if is_jni:
                jni_count += 1
            prepared.append({
                "name": fn.name,
                "vaddrHex": f"0x{fn.vaddr:x}",
                "vaddr": fn.vaddr,
                "size": fn.size,
                "source": fn.source,
                "relocatable": reloc,
                "vmCompatible": vm_ok,
                "isExported": bool(fn.is_exported),
                "isJni": is_jni,
                "sensitivity": int(fn.sensitivity_score),
                "cost": int(fn.cost_score),
                "skipReasons": ", ".join(fn.skip_reasons) if fn.skip_reasons else "",
                "assignedTag": assignment_lookup.get(fn.name, assignment_lookup.get(f"0x{fn.vaddr:x}", "")),
            })
        self._all = prepared
        self._vm_count = vm_count
        self._relocatable_count = reloc_count
        self._jni_count = jni_count
        self._rebuild_filtered()
        self.countsChanged.emit()

    def update_assignments(self, assignment_lookup):
        for item in self._all:
            item["assignedTag"] = assignment_lookup.get(item["name"], assignment_lookup.get(item["vaddrHex"], ""))
        if self._category == "assigned":
            self._rebuild_filtered()
            self.countsChanged.emit()
        elif self._filtered:
            self.dataChanged.emit(self.index(0), self.index(len(self._filtered) - 1), [self.AssignedTagRole])

    @Slot(str, str)
    def applyFilter(self, query, category):
        self._query = (query or "").strip().lower()
        self._category = category or "all"
        self._rebuild_filtered()
        self.countsChanged.emit()

    def _rebuild_filtered(self):
        self.beginResetModel()
        q = self._query
        cat = self._category
        out = []
        for item in self._all:
            if cat == "exported" and not item["isExported"]:
                continue
            if cat == "jni" and not item["isJni"]:
                continue
            if cat == "vm" and not item["vmCompatible"]:
                continue
            if cat == "relocatable" and not item["relocatable"]:
                continue
            if cat == "fde" and item["source"] != "eh_frame_fde":
                continue
            if cat == "assigned" and not item["assignedTag"]:
                continue
            if q and q not in item["name"].lower() and q not in item["vaddrHex"].lower():
                continue
            out.append(item)
        self._filtered = out
        self.endResetModel()


class DecoyListModel(QAbstractListModel):
    """Editable list model backing customized IDA Pro F5 troll decoy functions & strings."""

    countChanged = Signal()

    NameRole = Qt.UserRole + 1
    MainMsgRole = Qt.UserRole + 2
    AltMsgRole = Qt.UserRole + 3
    IndexRole = Qt.UserRole + 4

    def __init__(self, items=None, parent=None):
        super().__init__(parent)
        self._items = [list(x) for x in (items or [])]

    def roleNames(self):
        return {
            self.NameRole: b"decoyName",
            self.MainMsgRole: b"mainMsg",
            self.AltMsgRole: b"altMsg",
            self.IndexRole: b"rowIndex",
        }

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._items)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._items)):
            return None
        row = self._items[index.row()]
        if role == self.NameRole:
            return row[0]
        if role == self.MainMsgRole:
            return row[1]
        if role == self.AltMsgRole:
            return row[2]
        if role == self.IndexRole:
            return index.row() + 1
        return None

    @Property(int, notify=countChanged)
    def count(self):
        return len(self._items)

    def set_items(self, items):
        self.beginResetModel()
        self._items = [list(x) for x in items]
        self.endResetModel()
        self.countChanged.emit()

    def items_copy(self):
        return [list(x) for x in self._items]


class CapabilitiesModel(QAbstractListModel):
    """Reactive model reflecting enabled/disabled/available state across all Protect3 capabilities."""

    FeatureRole = Qt.UserRole + 1
    StatusRole = Qt.UserRole + 2
    MaturityRole = Qt.UserRole + 3
    ScopeRole = Qt.UserRole + 4

    def __init__(self, parent=None):
        super().__init__(parent)
        self._items = []

    def roleNames(self):
        return {
            self.FeatureRole: b"feature",
            self.StatusRole: b"status",
            self.MaturityRole: b"maturity",
            self.ScopeRole: b"scope",
        }

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._items)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._items)):
            return None
        item = self._items[index.row()]
        return {
            self.FeatureRole: item.get("feature", ""),
            self.StatusRole: item.get("status", "available"),
            self.MaturityRole: item.get("maturity", ""),
            self.ScopeRole: item.get("scope", ""),
        }.get(role)

    def set_capabilities(self, caps):
        self.beginResetModel()
        self._items = list(caps)
        self.endResetModel()
