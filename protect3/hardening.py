"""Read-only hardening inspection. Presence is not retrofitted protection."""


def audit_hardening(elf):
    symbols=elf.symbols()
    imports={s['name'] for s in symbols if not s['shndx']}
    stack=next((s for s in elf.segments if s.type==0x6474E551),None)
    relro=[s for s in elf.segments if s.type==0x6474E552]
    now=bool(elf.dynamic_value(30)&8 or elf.dynamic_value(0x6FFFFFFB)&1 or any(t==24 for t,_ in elf.dynamic))
    exports=elf.exported_symbols()
    return {
        'scope':'Read-only evidence; this command does not add compiler or linker hardening.',
        'relro':{'segment_present':bool(relro),'bind_now':now,
                 'assessment':'RELRO segment and eager binding observed; exact GOT coverage not verified' if relro and now else 'RELRO segment only' if relro else 'not_observed'},
        'nonexecutable_stack':'observed' if stack and not stack.flags&1 else 'executable' if stack else 'unspecified',
        'rwx_load_segments':[hex(s.vaddr) for s in elf.loads if s.flags&3==3],
        'stack_canary_import':'observed_not_function_coverage' if '__stack_chk_fail' in imports else 'not_observed_not_proof_absent',
        'fortify_imports':sorted(s for s in imports if s.endswith('_chk')),
        'export_count':len(exports),'exported_jni_names':[s[0] for s in exports if s[0].startswith('Java_')],
        'gnu_property_note_present':elf.section('.note.gnu.property') is not None,
        'limits':'Cannot add compiler CFI, stack canaries or full RELRO reliably to arbitrary compiled functions through metadata alone.'}
