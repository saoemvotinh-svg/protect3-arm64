"""Create unprotected diagnostic ELF variants; never present these as protection."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from protect3.elf import ELF
from protect3.engine import Options, rewrite
from protect3.runtime import load_runtime


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("input",type=Path)
    parser.add_argument("--kind",choices=("layout","tailcall","tail","ordered","grow"),required=True)
    args=parser.parse_args()
    original=ELF(args.input.read_bytes())
    blob,meta=load_runtime()
    output,injection=rewrite(original,Options(compat_layout=True),blob,meta)
    data=bytearray(output)
    if args.kind=="tail":
        data=bytearray(original.data)+bytearray(4096)
        injection={"layout":"original_with_unreferenced_tail"}
    elif args.kind in ("layout","ordered","grow"):
        # Keep only the ELF-layout changes; no guard or altered initializers run.
        dynamic=original.dynamic_segment
        data[dynamic.offset:dynamic.offset+dynamic.filesz]=original.data[dynamic.offset:dynamic.offset+dynamic.filesz]
        for section in original.sections:
            if section.type==4:
                data[section.offset:section.offset+section.size]=original.section_data(section)
        if args.kind=="ordered":
            from protect3.engine import _safe_note_slot
            from protect3.elf import PHDR
            spare=next(i for i,s in enumerate(original.segments) if s.type==4 and _safe_note_slot(original,s))
            segment=ELF(data).loads[-1]
            headers=[s for i,s in enumerate(original.segments) if i!=spare]
            index=max(i for i,s in enumerate(headers) if s.type==1)+1
            headers.insert(index,segment)
            data[original.phoff:original.phoff+original.phnum*PHDR.size]=b''.join(s.pack() for s in headers)
            injection['layout']='contiguous_load_headers_original_phdr'
        if args.kind=="grow":
            from dataclasses import replace
            from protect3.engine import _safe_note_slot
            from protect3.elf import EHDR,PHDR,align
            boundary=original.phoff+original.phnum*PHDR.size
            note=next(s for s in original.segments if s.type==4 and _safe_note_slot(original,s)
                      and s.offset<=boundary and boundary+PHDR.size<=s.offset+s.filesz)
            guard=ELF(data).loads[-1]
            new_note_offset=align(len(data),16)
            new_note_vaddr=guard.vaddr+new_note_offset-guard.offset
            data.extend(bytes(new_note_offset-len(data)))
            data.extend(original.data[note.offset:note.offset+note.filesz])
            guard=replace(guard,filesz=len(data)-guard.offset,memsz=len(data)-guard.offset)
            headers=[]
            for segment in original.segments:
                if segment.type==6:
                    segment=replace(segment,filesz=(original.phnum+1)*PHDR.size,memsz=(original.phnum+1)*PHDR.size)
                if segment==note:
                    segment=replace(segment,offset=new_note_offset,vaddr=new_note_vaddr,paddr=new_note_vaddr)
                headers.append(segment)
            index=max(i for i,s in enumerate(headers) if s.type==1)+1
            headers.insert(index,guard)
            sections=[]
            for section in original.sections:
                if section.type==7 and note.offset<=section.offset and section.offset+section.size<=note.offset+note.filesz:
                    delta=section.offset-note.offset
                    section=replace(section,offset=new_note_offset+delta,addr=new_note_vaddr+delta if section.flags&2 else section.addr)
                sections.append(section)
            new_shoff=align(len(data),8)
            data.extend(bytes(new_shoff-len(data)))
            data.extend(b''.join(s.pack() for s in sections))
            header=original.header.copy()
            header[6],header[10]=new_shoff,len(headers)
            data[:EHDR.size]=EHDR.pack(*header)
            data[original.phoff:original.phoff+len(headers)*PHDR.size]=b''.join(s.pack() for s in headers)
            injection['layout']='original_phoff_retained_all_program_headers'
    else:
        hook=injection.get("initializer_hook")
        target=hook["original_function_vaddr"] if hook else original.dynamic_value(12)
        entry=injection["entry_vaddr"]
        delta=target-entry
        if not target or delta%4 or not -(1<<27)<=delta<(1<<27):
            raise RuntimeError("Cannot encode diagnostic tail branch.")
        struct.pack_into("<I",data,ELF(data).file_offset(entry,4),0x14000000|((delta>>2)&0x3FFFFFF))
    folder=ROOT/"output"/("diagnostic-nativebridge-"+args.kind)
    folder.mkdir(parents=True,exist_ok=True)
    destination=folder/args.input.name
    destination.write_bytes(data)
    (folder/"probe.json").write_text(json.dumps({"diagnostic_only":True,"protection_enabled":False,
        "kind":args.kind,"source_sha256":hashlib.sha256(original.data).hexdigest(),
        "probe_sha256":hashlib.sha256(data).hexdigest(),"injection":injection},indent=2)+"\n")
    print(destination)


if __name__=="__main__":
    main()
