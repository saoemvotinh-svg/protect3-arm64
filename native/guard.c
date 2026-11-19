/* Android AArch64 constructor guard, runtime verifier, stealth unpacker, and bytecode VM.
 * Zero dynamic imports, TLS, heap, or plaintext guard strings in the shipped binary.
 */
#include "crypto.h"
#include "guard_strings.h"

/* Clang may lower aggregate initialization/zeroing to memcpy/memset even when freestanding. */
__attribute__((visibility("hidden"))) void *memcpy(void *destination, const void *source, usize size) {
    volatile u8 *out = (volatile u8 *)destination;
    const u8 *in = (const u8 *)source;
    for (usize i = 0; i < size; ++i) out[i] = in[i];
    return destination;
}

__attribute__((visibility("hidden"))) void *memset(void *destination, int value, usize size) {
    volatile u8 *out = (volatile u8 *)destination;
    for (usize i = 0; i < size; ++i) out[i] = (u8)value;
    return destination;
}

static void wipe_buf(void *buf, usize size) {
    volatile u8 *p = (volatile u8 *)buf;
    for (usize i = 0; i < size; ++i) p[i] = 0;
}

#define INTEGRITY 1u
#define DEBUGGER 2u
#define HOOKS 4u
#define ROOT 8u
#define EMULATOR 16u
#define ENCRYPT 32u
#define STRICT_PROC 64u
#define REPORT_ONLY 128u
#define DENY_ATTACH 256u
#define ENCRYPT_RODATA 512u
#define DIAGNOSTICS 1024u

/* v0.3/v0.4 extended flags in p3_ext.ext_flags */
#define EXT_MASKED_KEY        (1u << 0)
#define EXT_AUTH_RANGES       (1u << 1)
#define EXT_MANIFEST_MAC      (1u << 2)
#define EXT_GUARD_SELF_CHECK  (1u << 3)
#define EXT_PROLOGUE_CHECK    (1u << 4)
#define EXT_GOT_CHECK         (1u << 5)
#define EXT_RELRO_CHECK       (1u << 6)
#define EXT_RUNTIME_GATE      (1u << 7)
#define EXT_RUNTIME_ANTIDEBUG (1u << 8)
#define EXT_VM_ENABLED        (1u << 9)
#define EXT_STRING_VAULT      (1u << 10)
#define EXT_ON_DEMAND         (1u << 11)
#define EXT_DEEP_PROBES       (1u << 12)
#define EXT_GG_HONEYPOT       (1u << 13)
#define EXT_EPHEMERAL_STRINGS (1u << 14)
#define EXT_ANTI_GG           (1u << 15)

#define RANGE_FLAG_CODE       (1u << 0)
#define RANGE_FLAG_AUTH       (1u << 1)
#define RANGE_FLAG_ON_DEMAND  (1u << 2)
#define RANGE_FLAG_STRING     (1u << 3)
#define RANGE_FLAG_CANARY     (1u << 4)

#define P3_MAX_ENC_RANGES 24u
#define P3_MAX_PROLOGUES  16u
#define P3_MAX_VM_PROGS   32u
#define P3_MAX_STRINGS    32u
#define P3_MAX_VM_INSNS   256u
#define P3_PACK_MAX_SEGS  8u
#define P3_PACK_MAX_SAVED 64u

struct span { u64 vaddr, size; u8 digest[32]; };
struct config {
    u8 magic[24];
    u32 version, flags;
    u64 self_vaddr, original_init;
    u32 count, reserved;
    u64 text_vaddr, text_size;
    u8 key[32], nonce[12];
    u32 counter;
    u64 rodata_vaddr, rodata_size;
    u8 rodata_digest[32];
    u32 rodata_prot, extra_reserved;
    struct span spans[32];
};

struct enc_range {
    u64 vaddr, size;
    u32 prot, flags;
    u8 nonce[12];
    u32 counter;
    u8 cipher_mac[32];
    u8 plain_digest[32];
};

struct prologue_guard {
    u64 vaddr;
    u32 size, flags;
    u8 expected[16];
};

struct vm_prog {
    u64 func_vaddr;
    u32 bytecode_offset, bytecode_size;
    u32 insn_count, flags;
    u8 nonce[12];
    u32 counter;
    u8 digest[32];
};

struct string_entry {
    u32 offset, size;
    u8 nonce[12];
    u8 digest[32];
};

struct ext_config {
    u8 magic[16];
    u32 ext_version, ext_flags;
    u32 enc_range_count, prologue_count;
    u32 vm_program_count, string_count;
    u64 build_seed;
    u8 watermark[16];
    u8 key_mask[32];
    u8 manifest_pubkey[32];
    u8 manifest_mac[32];
    u8 text_cipher_mac[32];
    u8 rodata_cipher_mac[32];
    u64 guard_code_vaddr, guard_code_size;
    u8 guard_code_digest[32];
    u64 got_vaddr, got_size;
    u64 valid_target_min, valid_target_max;
    u64 relro_vaddr, relro_size;
    u8 relro_digest[32];
    u64 vm_bytecode_vaddr, vm_bytecode_size;
    u64 string_vault_vaddr, string_vault_size;
    u8 vm_opcode_map[64];
    u8 vm_key[32];
    struct enc_range enc_ranges[P3_MAX_ENC_RANGES];
    struct prologue_guard prologues[P3_MAX_PROLOGUES];
    struct vm_prog vm_progs[P3_MAX_VM_PROGS];
    struct string_entry strings[P3_MAX_STRINGS];
};

struct sparse_data_cfg {
    u64 data_vaddr;
    u64 data_size;
    u64 skip_table_vaddr;
    u64 skip_table_size;
    u32 enabled;
    u32 reloc_width;
    u8  nonce[12];
    u32 flags;
    u8  cipher_mac[32];
    u8  plain_digest[32];
    u64 guard_ext_vaddr;
    u64 guard_ext_size;
    u8  guard_ext_digest[32];
};

struct pack_seg {
    u64 target_vaddr;
    u64 memsz;
    u64 comp_offset;
    u64 comp_size;
    u64 uncomp_size;
    u32 final_prot;
    u32 is_relro;
};

struct pack_cfg {
    u32 enabled;
    u32 version;
    u64 pack_shift;
    u64 blob_vaddr;
    u64 blob_size;
    u8  cipher_mac[32];
    u8  nonce[12];
    u32 seg_count;
    u64 reloc_offset;
    u64 reloc_comp_sz;
    u64 reloc_uncomp_sz;
    u64 reloc_count;
    u64 import_offset;
    u64 import_comp_sz;
    u64 import_uncomp_sz;
    u64 import_count;
    u64 needed_offset;
    u64 needed_size;
    u64 relro_vaddr;
    u64 relro_size;
    u64 rw_data_min;
    u64 orig_dt_init;
    u32 saved_slot_count;
    u32 reserved;
    u64 saved_slots[P3_PACK_MAX_SAVED];
    u8  seg0_plain_sha256[32];
    struct pack_seg segs[P3_PACK_MAX_SEGS];
};

__attribute__((section(".p3config"), used, visibility("hidden")))
const volatile struct config p3_config = {.magic="PROTECT3-GUARD-v2", .version=2};
_Static_assert(sizeof(struct config)==1712, "config format mismatch");

__attribute__((section(".p3config"), used, visibility("hidden")))
const volatile struct ext_config p3_ext = {.magic="PROTECT3-EXT-v3", .ext_version=0};
_Static_assert(sizeof(struct ext_config)==7456, "ext_config format mismatch");

__attribute__((section(".p3config"), used, visibility("hidden")))
const volatile struct p3_str_table p3_str_cfg = P3_STR_TABLE_INIT;

__attribute__((section(".p3config"), used, visibility("hidden")))
const volatile struct sparse_data_cfg p3_data_enc = {.enabled=0};
_Static_assert(sizeof(struct sparse_data_cfg)==168, "sparse_data_cfg size mismatch");

__attribute__((section(".p3config"), used, visibility("hidden")))
const volatile struct pack_cfg p3_pack = {.enabled=0};
_Static_assert(sizeof(struct pack_cfg)==1128, "pack_cfg size mismatch");

#define P3_SYS_MASK 0x3C91L
#define P3_SYS(n) ((long)((n) ^ P3_SYS_MASK))

static __attribute__((noinline)) long sys6(long enc_n,long a,long b,long c,long d,long e,long f) {
    register long k __asm__("x9") = (p3_config.version == 2u ? P3_SYS_MASK : 0L);
    __asm__ volatile("" : "+r"(k));
    register long x8 __asm__("x8")=enc_n ^ k;
    register long x0 __asm__("x0")=a;
    register long x1 __asm__("x1")=b;
    register long x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e;
    register long x5 __asm__("x5")=f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5) : "memory","cc");
    return x0;
}

static __attribute__((noinline)) void p3_spin_lock(volatile u32 *lk) {
    u32 spins = 0;
    while (__atomic_exchange_n(lk, 1u, __ATOMIC_ACQUIRE) != 0u) {
        if ((++spins & 63u) == 0u) sys6(P3_SYS(124), 0, 0, 0, 0, 0, 0);
    }
}

static __attribute__((noinline)) void p3_spin_unlock(volatile u32 *lk) {
    __atomic_store_n(lk, 0u, __ATOMIC_RELEASE);
}

static usize length(const char *s) { usize n=0;while(s[n])++n;return n; }

static const char *decode_str(u32 id, char *buf, usize cap) {
    if (!cap) return buf;
    if (id >= P3_STR_SLOTS) { buf[0] = 0; return buf; }
    u16 off = p3_str_cfg.offsets[id];
    u8 len = p3_str_cfg.lengths[id];
    if ((usize)off + len > P3_STR_BLOB_CAP) { buf[0] = 0; return buf; }
    usize n = len < (cap - 1u) ? len : (cap - 1u);
    u8 kbuf[16];
    for (unsigned j = 0; j < 16u; ++j) kbuf[j] = p3_str_cfg.key[j];
    u32 k0 = (u32)kbuf[0] | ((u32)kbuf[1] << 8) | ((u32)kbuf[2] << 16) | ((u32)kbuf[3] << 24);
    for (usize i = 0; i < n; ++i) {
        u8 kb = kbuf[(i + id) & 15u] ^ (u8)((k0 >> ((i & 3u) * 8u)) + (u32)i * 0x5Du + id * 17u);
        buf[i] = (char)(p3_str_cfg.blob[off + i] ^ kb);
    }
    buf[n] = 0;
    wipe_buf(kbuf, sizeof(kbuf));
    return buf;
}

static void android_log(const char *s) {
    long fd=sys6(P3_SYS(198),1,2|0x80000|0x800,0,0,0,0);
    if(fd<0)return;
    struct { unsigned short family; char path[108]; } address={1,{0}};
    decode_str(P3S_LOGDW, address.path, sizeof(address.path));
    if(sys6(P3_SYS(203),fd,(long)&address,sizeof(address),0,0,0)==0) {
        u8 packet[512];
        struct { long seconds,nanos; } now={0,0};
        sys6(P3_SYS(113),0,(long)&now,0,0,0,0);
        unsigned long tid=(unsigned long)sys6(P3_SYS(178),0,0,0,0,0,0);
        packet[0]=0;packet[1]=(u8)tid;packet[2]=(u8)(tid>>8);
        for(unsigned i=0;i<4;++i) {
            packet[3+i]=(u8)((unsigned long)now.seconds>>(i*8));
            packet[7+i]=(u8)((unsigned long)now.nanos>>(i*8));
        }
        packet[11]=4;
        char tag[24];
        decode_str(P3S_TAG, tag, sizeof(tag));
        usize n=12;
        for(usize i=0;tag[i]&&n<sizeof(packet)-4;++i)packet[n++]=(u8)tag[i];
        wipe_buf(tag, sizeof(tag));
        packet[n++]=0;
        for(usize i=0;s[i]&&n<sizeof(packet)-1;++i)packet[n++]=(u8)s[i];
        packet[n++]=0;
        sys6(P3_SYS(64),fd,(long)packet,(long)n,0,0,0);
    }
    wipe_buf(address.path, sizeof(address.path));
    sys6(P3_SYS(57),fd,0,0,0,0,0);
}
static void message(const char *s) {
    android_log(s);
    sys6(P3_SYS(64),2,(long)s,(long)length(s),0,0,0);
}
static void event_id(u32 str_id) {
    if (!(p3_config.flags & DIAGNOSTICS)) return;
    char buf[96];
    decode_str(str_id, buf, sizeof(buf));
    message(buf);
    wipe_buf(buf, sizeof(buf));
}
__attribute__((noreturn)) static void die(int code,const char *s) {
    char marker[32];
    decode_str(P3S_FATAL_FMT, marker, sizeof(marker));
    marker[17]=(char)('0'+code/100%10);
    marker[18]=(char)('0'+code/10%10);
    marker[19]=(char)('0'+code%10);
    message(marker);
    wipe_buf(marker, sizeof(marker));
    message(s);
    sys6(P3_SYS(94),code,0,0,0,0,0);
    for (;;) __asm__ volatile("brk #0");
}
__attribute__((noreturn)) static void die_id(int code, u32 str_id) {
    char msg[128];
    decode_str(str_id, msg, sizeof(msg));
    die(code, msg);
}
static void detected_id(u32 flags, int code, u32 str_id) {
    char msg[128];
    decode_str(str_id, msg, sizeof(msg));
    if (flags & REPORT_ONLY) message(msg);
    else die(code, msg);
    wipe_buf(msg, sizeof(msg));
}
static long open_read(const char *s) { return sys6(P3_SYS(56),-100,(long)s,0x80000,0,0,0); }
static long open_read_id(u32 id) {
    char p[80];
    decode_str(id, p, sizeof(p));
    long fd = open_read(p);
    wipe_buf(p, sizeof(p));
    return fd;
}
static long read_fd(long fd,void *p,usize n) { return sys6(P3_SYS(63),fd,(long)p,(long)n,0,0,0); }
static void close_fd(long fd) { sys6(P3_SYS(57),fd,0,0,0,0,0); }
static int exists_id(u32 id) {
    char p[80];
    decode_str(id, p, sizeof(p));
    int r = (sys6(P3_SYS(48),-100,(long)p,0,0,0,0) == 0);
    wipe_buf(p, sizeof(p));
    return r;
}

static int contains(const char *s,usize size,const char *word) {
    usize n=length(word);
    if(n>size)return 0;
    for(usize i=0;i<=size-n;++i) {
        usize j=0;
        while(j<n && s[i+j]==word[j])++j;
        if(j==n)return 1;
    }
    return 0;
}

static int contains_id(const char *s, usize size, u32 word_id) {
    char w[48];
    decode_str(word_id, w, sizeof(w));
    int hit = contains(s, size, w);
    wipe_buf(w, sizeof(w));
    return hit;
}

static int str_eq(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == 0 && *b == 0;
}

static usize module_bias(void) {
    return (usize)&p3_config - (usize)p3_config.self_vaddr;
}

/* Derive master key on stack (E07); supports raw v2 key or masked HMAC KDF v3 key. */
static void derive_master_key(u8 out[32]) {
    u8 raw[32];
    for (unsigned i = 0; i < 32; ++i) raw[i] = p3_config.key[i];
    if (p3_ext.ext_version == 3 && (p3_ext.ext_flags & EXT_MASKED_KEY)) {
        u8 mask[32];
        for (unsigned i = 0; i < 32; ++i) mask[i] = p3_ext.key_mask[i];
        p3_hmac_sha256(mask, 32, raw, 32, out);
        wipe_buf(mask, sizeof(mask));
    } else {
        for (unsigned i = 0; i < 32; ++i) out[i] = raw[i];
    }
    wipe_buf(raw, sizeof(raw));
}

/* 1=detected, 0=not observed, -1=unavailable; preserve overlap across reads. */
static int scan_fd(long fd, int kind) {
    if (fd < 0) return -1;
    char buffer[8192]; usize kept=0, total=0;
    int deep = (p3_ext.ext_version == 3 && (p3_ext.ext_flags & EXT_DEEP_PROBES));
    char tracer_kw[20];
    if (kind == 0) decode_str(P3S_TRACERPID, tracer_kw, sizeof(tracer_kw));
    for(;;) {
        long got=read_fd(fd,buffer+kept,sizeof(buffer)-kept);
        if(got<0) {close_fd(fd); if (kind==0) wipe_buf(tracer_kw, sizeof(tracer_kw)); return -1;}
        if(!got)break;
        usize n=kept+(usize)got;total+=(usize)got;
        int found=0;
        if(kind==0) {
            for(usize i=0;i+10<n;++i) {
                if(buffer[i]!=tracer_kw[0]||!contains(buffer+i,10,tracer_kw))continue;
                usize j=i+10;
                while(j<n&&(buffer[j]==' '||buffer[j]=='\t'))++j;
                while(j<n&&buffer[j]>='0'&&buffer[j]<='9') {
                    if(buffer[j]!='0')found=1;
                    ++j;
                }
            }
        } else if(kind==1) {
            found=contains_id(buffer,n,P3S_FRIDA_AGENT)||contains_id(buffer,n,P3S_FRIDA_GADGET)
                ||contains_id(buffer,n,P3S_LIBFRIDA)||contains_id(buffer,n,P3S_LIBGADGET)
                ||contains_id(buffer,n,P3S_LIBXPOSED)||contains_id(buffer,n,P3S_LIBLSPOSED)
                ||contains_id(buffer,n,P3S_LIBEDXPOSED)||contains_id(buffer,n,P3S_MEMFD_FRIDA);
            if(!found && deep) {
                found=contains_id(buffer,n,P3S_GUM_JS)||contains_id(buffer,n,P3S_POOL_FRIDA)
                    ||contains_id(buffer,n,P3S_LINJECTOR)||contains_id(buffer,n,P3S_LIBSUBSTRATE)
                    ||contains_id(buffer,n,P3S_LIBDOBBY)||contains_id(buffer,n,P3S_LIBSHADOWHOOK);
            }
        } else if(kind==2) {
            found=contains_id(buffer,n,P3S_ZYGISK)||contains_id(buffer,n,P3S_SLASH_MAGISK)
                ||contains_id(buffer,n,P3S_LIBMAGISK);
            if(!found && deep) {
                found=contains_id(buffer,n,P3S_KERNELSU)||contains_id(buffer,n,P3S_SLASH_KSU)
                    ||contains_id(buffer,n,P3S_APATCH)||contains_id(buffer,n,P3S_MAGISKD);
            }
        } else if(kind==3) {
            found=contains_id(buffer,n,P3S_GOLDFISH)||contains_id(buffer,n,P3S_RANCHU);
            if(!found && deep) {
                found=contains_id(buffer,n,P3S_BLUESTACKS)||contains_id(buffer,n,P3S_BSTMODS)
                    ||contains_id(buffer,n,P3S_LIBNB)||contains_id(buffer,n,P3S_LIBHOUDINI)
                    ||contains_id(buffer,n,P3S_VBOXGUEST);
            }
        } else if(kind==4) {
            found=contains_id(buffer,n,P3S_PTRACE_STOP);
        } else if(kind==5) {
            found=contains_id(buffer,n,P3S_GG_NAME)||contains_id(buffer,n,P3S_CATCH_ME)
                ||contains_id(buffer,n,P3S_GG_DAEMON)||contains_id(buffer,n,P3S_LIBGG)
                ||contains_id(buffer,n,P3S_CESERVER)||contains_id(buffer,n,P3S_MEMDUMPER);
        } else if(kind==6) {
            found=contains_id(buffer,n,P3S_STATE_T)||contains_id(buffer,n,P3S_TRACING_STOP);
        } else if(kind==7) {
            found=contains_id(buffer,n,P3S_FRIDA_PORT);
        }
        if(found) {close_fd(fd); if (kind==0) wipe_buf(tracer_kw, sizeof(tracer_kw)); return 1;}
        if(total>16*1024*1024) {close_fd(fd); if (kind==0) wipe_buf(tracer_kw, sizeof(tracer_kw)); return -1;}
        kept=n<96?n:96;
        for(usize i=0;i<kept;++i)buffer[i]=buffer[n-kept+i];
    }
    if (kind == 0) wipe_buf(tracer_kw, sizeof(tracer_kw));
    close_fd(fd);return 0;
}

static int scan_path(const char *path, int kind) { return scan_fd(open_read(path), kind); }
static int scan_id(u32 path_id, int kind) { return scan_fd(open_read_id(path_id), kind); }

static int root_files(void) {
    int basic = exists_id(P3S_BIN_SU)||exists_id(P3S_XBIN_SU)||exists_id(P3S_SBIN_SU)
        ||exists_id(P3S_SBIN_MAGISK)||exists_id(P3S_ADB_MAGISK)||exists_id(P3S_ADB_KSU);
    if (basic) return 1;
    if (p3_ext.ext_version == 3 && (p3_ext.ext_flags & EXT_DEEP_PROBES)) {
        if (exists_id(P3S_ADB_AP) || exists_id(P3S_SOCK_MAGISKD)) return 1;
        if (scan_id(P3S_PROC_MOUNTINFO, 2) == 1) return 1;
    }
    return 0;
}
static int emulator_files(void) {
    int basic = exists_id(P3S_DEV_QEMU)||exists_id(P3S_DEV_GOLDFISH)||exists_id(P3S_SOCK_QEMUD);
    if (basic) return 1;
    if (p3_ext.ext_version == 3 && (p3_ext.ext_flags & EXT_DEEP_PROBES)) {
        if (exists_id(P3S_DEV_BST_GPS) || exists_id(P3S_DEV_BSTMODS) || exists_id(P3S_DEV_VBOXGUEST)
                || exists_id(P3S_LIB_BSTFOLDER) || exists_id(P3S_LIB64_NB))
            return 1;
        if (scan_id(P3S_PROC_MAPS, 3) == 1) return 1;
    }
    return 0;
}

static usize page_size(void) {
    u64 entries[256];
    long fd=open_read_id(P3S_PROC_AUXV);
    if(fd<0)return 0;
    usize used=0;
    while(used<sizeof(entries)) {
        long got=read_fd(fd,(u8 *)entries+used,sizeof(entries)-used);
        if(got<0) {close_fd(fd);return 0;}
        if(!got)break;
        used+=(usize)got;
    }
    close_fd(fd);
    for(usize i=0;i+1<used/8;i+=2) {
        if(entries[i]==0)break;
        if(entries[i]==6) {
            u64 n=entries[i+1];
            return n>=4096&&n<=65536&&!(n&(n-1))?(usize)n:0;
        }
    }
    return 0;
}

static void clear_cache(usize start,usize end) {
    u64 ctr;
    __asm__ volatile("mrs %0, ctr_el0":"=r"(ctr));
    usize dc=(usize)4<<((ctr>>16)&15),ic=(usize)4<<(ctr&15);
    for(usize p=start&~(dc-1);p<end;p+=dc) __asm__ volatile("dc cvau, %0"::"r"(p):"memory");
    __asm__ volatile("dsb ish":::"memory");
    for(usize p=start&~(ic-1);p<end;p+=ic) __asm__ volatile("ic ivau, %0"::"r"(p):"memory");
    __asm__ volatile("dsb ish\nisb":::"memory");
}

static void verify_cipher_mac_explicit(const u8 key[32], u64 meta_va, u64 meta_sz, const u8 nonce[12], const u8 *ptr, usize len, const u8 expected[32]) {
    u8 meta[28], inner[32], actual[32];
    for (unsigned i = 0; i < 8; ++i) {
        meta[i] = (u8)(meta_va >> (i * 8));
        meta[8 + i] = (u8)(meta_sz >> (i * 8));
    }
    for (unsigned i = 0; i < 12; ++i) meta[16 + i] = nonce[i];
    p3_hmac_sha256(key, 32, meta, 28, inner);
    p3_hmac_sha256(inner, 32, ptr, len, actual);
    unsigned diff = 0;
    for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ expected[i];
    wipe_buf(inner, sizeof(inner));
    if (diff) die_id(175, P3S_ERR_CIPHER_MAC);
}

static void verify_cipher_mac(usize start, usize size, const u8 nonce[12], const u8 expected[32]) {
    u8 key[32];
    derive_master_key(key);
    u64 vaddr = (u64)(start - module_bias());
    verify_cipher_mac_explicit(key, vaddr, (u64)size, nonce, (const u8 *)start, size, expected);
    wipe_buf(key, sizeof(key));
}

static void decrypt_custom_range(usize start, usize size, unsigned prot, const u8 nonce[12], u32 counter) {
    usize page = page_size();
    if (!page) die_id(176, P3S_ERR_PAGE_SZ);
    if (!size || size > 1024ul*1024*1024) die_id(177, P3S_ERR_ENC_RANGE);
    usize low = start & ~(page - 1), high = (start + size + page - 1) & ~(page - 1);
    if (sys6(P3_SYS(226), (long)low, (long)(high - low), 3, 0, 0, 0))
        die_id(176, P3S_ERR_MPROT_RW);
    u8 key[32];
    derive_master_key(key);
    p3_chacha20((u8 *)start, size, key, nonce, counter);
    if (prot & 4) clear_cache(start, start + size);
    if (sys6(P3_SYS(226), (long)low, (long)(high - low), prot, 0, 0, 0))
        die_id(176, P3S_ERR_MPROT_REST);
    wipe_buf(key, sizeof(key));
}

static void decrypt_range(usize start,usize size,unsigned prot,int rodata) {
    u8 nonce[12];
    for(unsigned i=0;i<12;++i)nonce[i]=p3_config.nonce[i];
    if(rodata)nonce[11]^=0x80;
    if (p3_ext.ext_version == 3 && (p3_ext.ext_flags & EXT_AUTH_RANGES)) {
        u8 expected[32];
        for (unsigned i = 0; i < 32; ++i)
            expected[i] = rodata ? p3_ext.rodata_cipher_mac[i] : p3_ext.text_cipher_mac[i];
        verify_cipher_mac(start, size, nonce, expected);
        event_id(rodata ? P3S_EV_RODATA_MAC : P3S_EV_TEXT_MAC);
    }
    decrypt_custom_range(start, size, prot, nonce, p3_config.counter);
}

static void sha256_update_vol(struct p3_sha256_ctx *ctx, const volatile void *ptr, usize len) {
    u8 chunk[64];
    const volatile u8 *p = (const volatile u8 *)ptr;
    while (len > 0) {
        usize n = len < sizeof(chunk) ? len : sizeof(chunk);
        for (usize i = 0; i < n; ++i) chunk[i] = p[i];
        p3_sha256_update(ctx, chunk, n);
        p += n;
        len -= n;
    }
    wipe_buf(chunk, sizeof(chunk));
}

static void verify_manifest_and_self(usize bias) {
    if (p3_ext.ext_version != 3) return;
    u32 eflags = p3_ext.ext_flags;
    if (eflags & EXT_MANIFEST_MAC) {
        u8 pubkey[32], expected[32], actual[32], zero[32];
        for (unsigned i = 0; i < 32; ++i) {
            pubkey[i] = p3_ext.manifest_pubkey[i];
            expected[i] = p3_ext.manifest_mac[i];
            zero[i] = 0;
        }
        u8 kblock[64], ipad[64], opad[64], inner[32];
        for (unsigned i = 0; i < 64; ++i) {
            kblock[i] = i < 32 ? pubkey[i] : 0;
            ipad[i] = kblock[i] ^ 0x36;
            opad[i] = kblock[i] ^ 0x5c;
        }
        usize mac_off = (usize)&p3_ext.manifest_mac - (usize)&p3_ext;
        struct p3_sha256_ctx ctx;
        p3_sha256_init(&ctx);
        p3_sha256_update(&ctx, ipad, 64);
        sha256_update_vol(&ctx, &p3_config, sizeof(p3_config));
        sha256_update_vol(&ctx, &p3_ext, mac_off);
        p3_sha256_update(&ctx, zero, 32);
        sha256_update_vol(&ctx, (const volatile u8 *)&p3_ext + mac_off + 32, sizeof(p3_ext) - mac_off - 32);
        sha256_update_vol(&ctx, &p3_str_cfg, sizeof(p3_str_cfg));
        sha256_update_vol(&ctx, &p3_data_enc, sizeof(p3_data_enc));
        sha256_update_vol(&ctx, &p3_pack, sizeof(p3_pack));
        p3_sha256_final(&ctx, inner);

        p3_sha256_init(&ctx);
        p3_sha256_update(&ctx, opad, 64);
        p3_sha256_update(&ctx, inner, 32);
        p3_sha256_final(&ctx, actual);
        unsigned diff = 0;
        for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ expected[i];
        wipe_buf(kblock, sizeof(kblock));
        wipe_buf(ipad, sizeof(ipad));
        wipe_buf(opad, sizeof(opad));
        wipe_buf(inner, sizeof(inner));
        if (diff) die_id(175, P3S_ERR_MANIFEST_MAC);
        event_id(P3S_EV_MANIFEST_MAC);
    }
    if (eflags & EXT_GUARD_SELF_CHECK) {
        if (!p3_ext.guard_code_size || p3_ext.guard_code_size > 2u * 1024u * 1024u)
            die_id(177, P3S_ERR_SELF_RNG);
        u8 actual[32];
        unsigned diff = 0;
        p3_sha256((const u8 *)(bias + (usize)p3_ext.guard_code_vaddr), (usize)p3_ext.guard_code_size, actual);
        for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ p3_ext.guard_code_digest[i];
        if (diff) die_id(175, P3S_ERR_SELF_MIS);
        if (p3_data_enc.guard_ext_size > 0u) {
            if (p3_data_enc.guard_ext_size > 2u * 1024u * 1024u)
                die_id(177, P3S_ERR_SELF_RNG);
            p3_sha256((const u8 *)(bias + (usize)p3_data_enc.guard_ext_vaddr), (usize)p3_data_enc.guard_ext_size, actual);
            for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ p3_data_enc.guard_ext_digest[i];
            if (diff) die_id(175, P3S_ERR_SELF_MIS);
        }
        event_id(P3S_EV_SELF_CHK);
    }
}

static u64 read_uleb(const u8 **cur, const u8 *end) {
    u64 v = 0;
    unsigned sh = 0;
    while (*cur < end) {
        u8 b = *(*cur)++;
        v |= ((u64)(b & 0x7Fu)) << sh;
        if (!(b & 0x80u)) break;
        sh += 7u;
        if (sh >= 63u) break;
    }
    return v;
}

static long long read_sleb(const u8 **cur, const u8 *end) {
    u64 v = 0;
    unsigned sh = 0;
    u8 b = 0;
    while (*cur < end) {
        b = *(*cur)++;
        v |= ((u64)(b & 0x7Fu)) << sh;
        sh += 7u;
        if (!(b & 0x80u)) break;
        if (sh >= 63u) break;
    }
    if (sh < 64u && (b & 0x40u)) v |= (~0ULL) << sh;
    return (long long)v;
}

/* E02+: Decrypt non-relocated gaps inside RW .data preserving Bionic-patched pointers. */
static void decrypt_sparse_data(usize bias) {
    if (p3_data_enc.enabled != 0x50334441u || !p3_data_enc.data_size) return;
    usize dstart = bias + (usize)p3_data_enc.data_vaddr;
    usize dsize = (usize)p3_data_enc.data_size;
    u8 *data_ptr = (u8 *)dstart;
    const u8 *skip_cur = (const u8 *)(bias + (usize)p3_data_enc.skip_table_vaddr);
    const u8 *skip_end = skip_cur + (usize)p3_data_enc.skip_table_size;
    u32 rwidth = p3_data_enc.reloc_width ? p3_data_enc.reloc_width : 8u;

    u8 key[32], nonce[12];
    derive_master_key(key);
    for (unsigned i = 0; i < 12; ++i) nonce[i] = p3_data_enc.nonce[i];

    /* Optional E04 HMAC-SHA256 over ciphertext non-reloc bytes before decrypting */
    if (p3_data_enc.flags & 1u) {
        u8 meta[28], inner[32], actual[32];
        u64 va = p3_data_enc.data_vaddr, sz = p3_data_enc.data_size;
        for (unsigned i = 0; i < 8; ++i) {
            meta[i] = (u8)(va >> (i * 8));
            meta[8 + i] = (u8)(sz >> (i * 8));
        }
        for (unsigned i = 0; i < 12; ++i) meta[16 + i] = nonce[i];
        p3_hmac_sha256(key, 32, meta, 28, inner);

        u8 ipad[64], opad[64], h_in[32];
        for (unsigned i = 0; i < 64; ++i) {
            u8 kb = i < 32 ? inner[i] : 0u;
            ipad[i] = kb ^ 0x36u;
            opad[i] = kb ^ 0x5Cu;
        }
        struct p3_sha256_ctx hc;
        p3_sha256_init(&hc);
        p3_sha256_update(&hc, ipad, 64);

        const u8 *sc = skip_cur;
        usize nxt_s = sc < skip_end ? (usize)read_uleb(&sc, skip_end) : (usize)-1;
        usize cur_s = 0;
        for (usize pos = 0; pos < dsize;) {
            if (nxt_s != (usize)-1 && pos >= nxt_s) {
                pos += rwidth;
                cur_s = nxt_s;
                nxt_s = sc < skip_end ? (cur_s + (usize)read_uleb(&sc, skip_end)) : (usize)-1;
                continue;
            }
            usize stop = (nxt_s != (usize)-1 && nxt_s < dsize) ? nxt_s : dsize;
            if (stop > pos) p3_sha256_update(&hc, data_ptr + pos, stop - pos);
            pos = stop;
        }
        p3_sha256_final(&hc, h_in);
        p3_sha256_init(&hc);
        p3_sha256_update(&hc, opad, 64);
        p3_sha256_update(&hc, h_in, 32);
        p3_sha256_final(&hc, actual);
        unsigned diff = 0;
        for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ p3_data_enc.cipher_mac[i];
        wipe_buf(inner, sizeof(inner));
        wipe_buf(ipad, sizeof(ipad));
        wipe_buf(opad, sizeof(opad));
        if (diff) { wipe_buf(key, sizeof(key)); die_id(175, P3S_ERR_CIPHER_MAC); }
        event_id(P3S_EV_DATA_MAC);
    }

    struct p3_sha256_ctx pc;
    p3_sha256_init(&pc);
    const u8 *sc = skip_cur;
    usize nxt_s = sc < skip_end ? (usize)read_uleb(&sc, skip_end) : (usize)-1;
    usize cur_s = 0;
    u64 cached_blk = (u64)-1;
    u8 ks[64];
    for (usize pos = 0; pos < dsize; ) {
        if (nxt_s != (usize)-1 && pos >= nxt_s) {
            pos += rwidth;
            cur_s = nxt_s;
            nxt_s = sc < skip_end ? (cur_s + (usize)read_uleb(&sc, skip_end)) : (usize)-1;
            continue;
        }
        usize stop = (nxt_s != (usize)-1 && nxt_s < dsize) ? nxt_s : dsize;
        while (pos < stop) {
            u64 blk = (u64)(pos >> 6);
            if (blk != cached_blk) {
                p3_chacha20_block(key, nonce, 1u + (u32)blk, ks);
                cached_blk = blk;
            }
            data_ptr[pos] ^= ks[pos & 63u];
            p3_sha256_update(&pc, &data_ptr[pos], 1);
            ++pos;
        }
    }
    wipe_buf(ks, sizeof(ks));
    wipe_buf(key, sizeof(key));

    u8 actual[32];
    unsigned diff = 0;
    p3_sha256_final(&pc, actual);
    for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ p3_data_enc.plain_digest[i];
    if (diff) die_id(175, P3S_ERR_DATA_MIS);
    event_id(P3S_EV_DATA_DEC_OK);
}

static void verify_prologues_got_relro(usize bias) {
    if (p3_ext.ext_version != 3) return;
    u32 eflags = p3_ext.ext_flags;
    if (eflags & EXT_PROLOGUE_CHECK) {
        u32 n = p3_ext.prologue_count;
        if (n > P3_MAX_PROLOGUES) die_id(177, P3S_ERR_PROL_CNT);
        for (u32 i = 0; i < n; ++i) {
            u32 sz = p3_ext.prologues[i].size;
            if (!sz || sz > 16) die_id(177, P3S_ERR_PROL_SZ);
            const u8 *ptr = (const u8 *)(bias + (usize)p3_ext.prologues[i].vaddr);
            unsigned diff = 0;
            for (u32 j = 0; j < sz; ++j) diff |= ptr[j] ^ p3_ext.prologues[i].expected[j];
            if (diff) die_id(175, P3S_ERR_PROL_HOOK);
        }
        event_id(P3S_EV_PROLOGUE_CHK);
    }
    if (eflags & EXT_GOT_CHECK) {
        usize got_addr = bias + (usize)p3_ext.got_vaddr;
        usize got_sz = (usize)p3_ext.got_size;
        usize min_va = bias + (usize)p3_ext.valid_target_min;
        usize max_va = bias + (usize)p3_ext.valid_target_max;
        for (usize off = 0; off + 8 <= got_sz; off += 8) {
            u64 target = *(const u64 *)(got_addr + off);
            if (!target) continue;
            if (target >= bias && target < max_va && target < min_va)
                die_id(175, P3S_ERR_GOT_OOB);
        }
        event_id(P3S_EV_GOT_CHK);
    }
    if (eflags & EXT_RELRO_CHECK) {
        if (!p3_ext.relro_size || p3_ext.relro_size > 64 * 1024 * 1024)
            die_id(177, P3S_ERR_RELRO_SZ);
        u8 actual[32];
        unsigned diff = 0;
        p3_sha256((const u8 *)(bias + (usize)p3_ext.relro_vaddr), (usize)p3_ext.relro_size, actual);
        for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ p3_ext.relro_digest[i];
        if (diff) die_id(175, P3S_ERR_RELRO_MIS);
        event_id(P3S_EV_RELRO_CHK);
    }
}

static int reencrypt_vault_slots_locked(usize bias, u64 keep_id) {
    if (p3_ext.ext_version != 3 || !(p3_ext.ext_flags & EXT_EPHEMERAL_STRINGS)) return 0;
    u32 count = p3_ext.string_count;
    if (!count || count > P3_MAX_STRINGS || !p3_ext.string_vault_size) return 0;
    usize vault_base = bias + (usize)p3_ext.string_vault_vaddr;
    int any_action = 0;
    for (u32 i = 0; i < count; ++i) {
        if ((u64)i == keep_id) continue;
        struct string_entry se;
        for (usize k = 0; k < sizeof(se); ++k)
            ((u8 *)&se)[k] = ((const volatile u8 *)&p3_ext.strings[i])[k];
        if (!se.size || se.offset + 8 + se.size > p3_ext.string_vault_size) continue;
        const u8 *slot = (const u8 *)(vault_base + se.offset);
        u32 state = (u32)slot[0] | ((u32)slot[1] << 8) | ((u32)slot[2] << 16) | ((u32)slot[3] << 24);
        if (state == 0x50335344u) { any_action = 1; break; }
    }
    if (!any_action) return 0;
    usize page = page_size();
    if (!page) return 0;
    usize low = vault_base & ~(page - 1);
    usize high = (vault_base + (usize)p3_ext.string_vault_size + page - 1) & ~(page - 1);
    if (sys6(P3_SYS(226), (long)low, (long)(high - low), 3, 0, 0, 0))
        return -1;
    u8 key[32];
    derive_master_key(key);
    for (u32 i = 0; i < count; ++i) {
        if ((u64)i == keep_id) continue;
        struct string_entry se;
        for (usize k = 0; k < sizeof(se); ++k)
            ((u8 *)&se)[k] = ((const volatile u8 *)&p3_ext.strings[i])[k];
        if (!se.size || se.offset + 8 + se.size > p3_ext.string_vault_size) continue;
        u8 *slot = (u8 *)(vault_base + se.offset);
        u32 state = (u32)slot[0] | ((u32)slot[1] << 8) | ((u32)slot[2] << 16) | ((u32)slot[3] << 24);
        if (state != 0x50335344u) continue;
        if (keep_id != (u64)-1 && slot[4] < 16) {
            slot[4] += 1;
            continue;
        }
        p3_chacha20(slot + 8, se.size, key, se.nonce, 1);
        slot[0] = 0x45; slot[1] = 0x53; slot[2] = 0x33; slot[3] = 0x50;
        slot[4] = 0;
    }
    wipe_buf(key, sizeof(key));
    if (sys6(P3_SYS(226), (long)low, (long)(high - low), 1, 0, 0, 0))
        return -2;
    event_id(P3S_EV_VAULT_WIPED);
    return 1;
}

static int verify_honeypot_canaries(usize bias) {
    int checked_any = 0;
    u32 n = p3_ext.enc_range_count;
    if (n > P3_MAX_ENC_RANGES) die_id(177, P3S_ERR_HP_CNT);
    for (u32 i = 0; i < n; ++i) {
        struct enc_range r;
        for (usize k = 0; k < sizeof(r); ++k)
            ((u8 *)&r)[k] = ((const volatile u8 *)&p3_ext.enc_ranges[i])[k];
        if (!(r.flags & RANGE_FLAG_CANARY)) continue;
        if (!r.size || r.size > 1024 * 1024) die_id(177, P3S_ERR_HP_SZ);
        u8 actual[32];
        unsigned diff = 0;
        p3_sha256((const u8 *)(bias + (usize)r.vaddr), (usize)r.size, actual);
        for (unsigned j = 0; j < 32; ++j) diff |= actual[j] ^ r.plain_digest[j];
        if (diff) detected_id(p3_config.flags, 179, P3S_ERR_HP_TAMPER);
        checked_any = 1;
    }
    return checked_any;
}

static long long read_clock_ms(int clk_id) {
    struct { long sec, nsec; } ts = {0, 0};
    if (sys6(P3_SYS(113), clk_id, (long)&ts, 0, 0, 0, 0) != 0) return -1LL;
    return (long long)ts.sec * 1000LL + (long long)ts.nsec / 1000000LL;
}

static volatile long long *canary_state_ptr(usize bias) {
    u32 n = p3_ext.enc_range_count;
    if (n > P3_MAX_ENC_RANGES) return 0;
    for (u32 i = 0; i < n; ++i) {
        struct enc_range r;
        for (usize k = 0; k < sizeof(r); ++k)
            ((u8 *)&r)[k] = ((const volatile u8 *)&p3_ext.enc_ranges[i])[k];
        if (!(r.flags & RANGE_FLAG_CANARY)) continue;
        if (r.prot != 3) continue;
        return (volatile long long *)(bias + (usize)r.vaddr + (usize)r.size);
    }
    return 0;
}

static void init_honeypot_rw_and_state(usize bias) {
    if (p3_ext.ext_version != 3) return;
    u32 n = p3_ext.enc_range_count;
    if (n > P3_MAX_ENC_RANGES) return;
    for (u32 i = 0; i < n; ++i) {
        struct enc_range r;
        for (usize k = 0; k < sizeof(r); ++k)
            ((u8 *)&r)[k] = ((const volatile u8 *)&p3_ext.enc_ranges[i])[k];
        if (!(r.flags & RANGE_FLAG_CANARY) || r.prot != 3) continue;
        usize page = page_size();
        if (!page) die_id(176, P3S_ERR_HP_PAGE);
        usize start = bias + (usize)r.vaddr;
        usize low = start & ~(page - 1);
        usize high = (start + (usize)r.size + 4096u + page - 1) & ~(page - 1);
        if (sys6(P3_SYS(226), (long)low, (long)(high - low), 3, 0, 0, 0))
            die_id(176, P3S_ERR_HP_RW);
        volatile long long *st = (volatile long long *)(start + (usize)r.size);
        st[0] = read_clock_ms(1);
        st[1] = read_clock_ms(2);
        st[2] = 0x50335239LL;
        st[3] = 0;
        st[4] = st[0];
        for (unsigned k = 5; k < 32; ++k) st[k] = 0;
        __asm__ volatile("dmb ish" ::: "memory");
    }
}

static void build_task_path(char *dst, const char *tid, u32 leaf_id) {
    char prefix[32];
    char leaf[16];
    decode_str(P3S_PROC_TASK_PFX, prefix, sizeof(prefix));
    decode_str(leaf_id, leaf, sizeof(leaf));
    usize pos = 0;
    while (prefix[pos] && pos < 64) { dst[pos] = prefix[pos]; ++pos; }
    usize j = 0;
    while (tid[j] && pos < 80) dst[pos++] = tid[j++];
    dst[pos++] = '/';
    j = 0;
    while (leaf[j] && pos < 94) dst[pos++] = leaf[j++];
    dst[pos] = 0;
    wipe_buf(prefix, sizeof(prefix));
    wipe_buf(leaf, sizeof(leaf));
}

static void scan_task_threads_nonroot(void) {
    long dirfd = open_read_id(P3S_PROC_TASK);
    if (dirfd < 0) {
        if (scan_id(P3S_PROC_STATUS, 6) == 1 || scan_id(P3S_PROC_WCHAN, 4) == 1)
            detected_id(p3_config.flags, 180, P3S_ERR_TRACE_PAUSE);
        return;
    }
    char dirbuf[2048];
    unsigned visited = 0;
    for (;;) {
        long nread = sys6(P3_SYS(61), dirfd, (long)dirbuf, sizeof(dirbuf), 0, 0, 0);
        if (nread <= 0) break;
        long pos = 0;
        while (pos + 20 <= nread) {
            unsigned short reclen = (unsigned short)((unsigned char)dirbuf[pos + 16] | ((unsigned char)dirbuf[pos + 17] << 8));
            if (reclen < 20 || pos + reclen > nread) break;
            const char *name = dirbuf + pos + 19;
            pos += reclen;
            if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) continue;
            if (++visited > 64) break;
            char pbuf[96];
            build_task_path(pbuf, name, P3S_LEAF_STATUS);
            if (scan_path(pbuf, 0) == 1 || scan_path(pbuf, 6) == 1) {
                close_fd(dirfd);
                detected_id(p3_config.flags, 180, P3S_ERR_EXT_TRACER);
                return;
            }
            build_task_path(pbuf, name, P3S_LEAF_WCHAN);
            if (scan_path(pbuf, 4) == 1) {
                close_fd(dirfd);
                detected_id(p3_config.flags, 180, P3S_ERR_PTRACE_STOP);
                return;
            }
            build_task_path(pbuf, name, P3S_LEAF_COMM);
            if (scan_path(pbuf, 5) == 1) {
                close_fd(dirfd);
                detected_id(p3_config.flags, 180, P3S_ERR_SCANNER_THRD);
                return;
            }
        }
        if (visited > 64) break;
    }
    close_fd(dirfd);
}

static void check_anti_gg_fast(void) {
    if (exists_id(P3S_TMP_GG_DAEMON) || exists_id(P3S_TMP_LIBGG)
            || exists_id(P3S_TMP_CESERVER) || scan_id(P3S_PROC_COMM, 5) == 1
            || scan_id(P3S_PROC_CMDLINE, 5) == 1 || scan_id(P3S_PROC_ENVIRON, 5) == 1) {
        detected_id(p3_config.flags, 180, P3S_ERR_SCANNER_IND);
    }
}

static int verify_canary_and_anti_gg(usize bias, int runtime_phase, int run_heavy) {
    if (p3_ext.ext_version != 3) return 1;
    u32 eflags = p3_ext.ext_flags;
    if (!(eflags & (EXT_GG_HONEYPOT | EXT_ANTI_GG))) return run_heavy;

    struct { long sec, nsec; } t0 = {0, 0}, t1 = {0, 0}, c0 = {0, 0}, c1 = {0, 0};
    long rc_t0 = -1, rc_t1 = -1, rc_c0 = -1, rc_c1 = -1;
    if (runtime_phase && (eflags & EXT_ANTI_GG)) {
        rc_t0 = sys6(P3_SYS(113), 1, (long)&t0, 0, 0, 0, 0);
        rc_c0 = sys6(P3_SYS(113), 2, (long)&c0, 0, 0, 0, 0);
    }

    int checked_any = 0;
    if (eflags & EXT_GG_HONEYPOT) {
        checked_any = verify_honeypot_canaries(bias);
        if (checked_any) event_id(P3S_EV_HONEYPOT_OK);
    }

    volatile long long *st = canary_state_ptr(bias);
    int do_heavy = !runtime_phase || run_heavy || !st || st[2] != 0x50335239LL;
    if (runtime_phase && (eflags & EXT_ANTI_GG)) {
        if (!checked_any && do_heavy) {
            u8 actual[32];
            p3_sha256((const u8 *)&p3_config, sizeof(p3_config), actual);
        }
        rc_t1 = sys6(P3_SYS(113), 1, (long)&t1, 0, 0, 0, 0);
        rc_c1 = sys6(P3_SYS(113), 2, (long)&c1, 0, 0, 0, 0);
        if (rc_t0 == 0 && rc_t1 == 0 && rc_c0 == 0 && rc_c1 == 0) {
            long long wall_ms = (long long)(t1.sec - t0.sec) * 1000LL + (long long)(t1.nsec - t0.nsec) / 1000000LL;
            long long cpu_ms = (long long)(c1.sec - c0.sec) * 1000LL + (long long)(c1.nsec - c0.nsec) / 1000000LL;
            if (wall_ms > 2500LL && cpu_ms < 250LL)
                detected_id(p3_config.flags, 180, P3S_ERR_FREEZE_PAUSE);
        }
        if (st && st[2] == 0x50335239LL) {
            volatile u32 *st_lock = (volatile u32 *)&st[7];
            p3_spin_lock(st_lock);
            long long now_w = read_clock_ms(1);
            long long now_c = read_clock_ms(2);
            long long prev_w = st[0];
            long long prev_c = st[1];
            int hit_freeze = 0;
            if (now_w >= 0 && now_c >= 0 && prev_w >= 0 && prev_c >= 0) {
                long long wd = now_w - prev_w;
                long long cd = now_c - prev_c;
                if (wd > 3500LL && wd < 45000LL && cd >= 0 && cd < 25LL) {
                    hit_freeze = 1;
                }
            }
            if (st[3] == 0 || (now_w >= 0 && st[4] >= 0 && (now_w - st[4] >= 1000LL))) {
                do_heavy = 1;
                st[4] = now_w;
            }
            st[0] = now_w;
            st[1] = now_c;
            st[3] += 1;
            p3_spin_unlock(st_lock);
            if (hit_freeze) {
                scan_task_threads_nonroot();
                detected_id(p3_config.flags, 180, P3S_ERR_XCALL_PAUSE);
            }
        }
    } else if (runtime_phase && st && st[2] == 0x50335239LL) {
        volatile u32 *st_lock = (volatile u32 *)&st[7];
        p3_spin_lock(st_lock);
        long long now_w = read_clock_ms(1);
        if (st[3] == 0 || (now_w >= 0 && st[4] >= 0 && (now_w - st[4] >= 1000LL))) {
            do_heavy = 1;
            st[4] = now_w;
        }
        st[3] += 1;
        p3_spin_unlock(st_lock);
    }

    if ((eflags & EXT_ANTI_GG) && do_heavy) {
        check_anti_gg_fast();
        scan_task_threads_nonroot();
        if (scan_id(P3S_PROC_MAPS, 5) == 1 || scan_id(P3S_PROC_MOUNTINFO, 5) == 1 || scan_id(P3S_PROC_NET_UNIX, 5) == 1) {
            detected_id(p3_config.flags, 180, P3S_ERR_SCANNER_IND);
        }
        event_id(P3S_EV_ANTI_GG_OK);
    }
    return do_heavy;
}

__attribute__((visibility("hidden"), used))
void p3_runtime_check(u64 gate_id) {
    usize bias = module_bias();
    if (p3_config.version != 2) die_id(177, P3S_ERR_GATE_STATE);
    int do_heavy = verify_canary_and_anti_gg(bias, 1, 0);
    if (do_heavy) verify_manifest_and_self(bias);
    verify_prologues_got_relro(bias);
    if (p3_ext.ext_version == 3 && (p3_ext.ext_flags & EXT_RUNTIME_ANTIDEBUG)) {
        int res = scan_id(P3S_PROC_STATUS, 0);
        if (res == 1 || (do_heavy && scan_id(P3S_PROC_WCHAN, 4) == 1))
            detected_id(p3_config.flags, 171, P3S_ERR_DBG_GATE);
    }
    u32 count = p3_config.count;
    if (count > 0 && count <= 32 && (p3_config.flags & (INTEGRITY | ENCRYPT))) {
        u32 idx = (u32)(gate_id % count);
        usize span_sz = (usize)p3_config.spans[idx].size;
        if (do_heavy || span_sz <= 65536u) {
            u8 actual[32];
            unsigned diff = 0;
            p3_sha256((const u8 *)(bias + (usize)p3_config.spans[idx].vaddr), span_sz, actual);
            for (unsigned j = 0; j < 32; ++j) diff |= actual[j] ^ p3_config.spans[idx].digest[j];
            if (diff) die_id(175, P3S_ERR_RT_CODE_MIS);
        }
    }
    event_id(P3S_EV_RT_GATE_OK);
}

__attribute__((visibility("hidden"), used))
const char *p3_resolve_string(u64 string_id) {
    if (p3_ext.ext_version != 3 || string_id >= p3_ext.string_count || p3_ext.string_count > P3_MAX_STRINGS)
        die_id(177, P3S_ERR_VAULT_REF);
    usize bias = module_bias();
    struct string_entry se;
    for (usize i = 0; i < sizeof(se); ++i)
        ((u8 *)&se)[i] = ((const volatile u8 *)&p3_ext.strings[string_id])[i];
    if (!se.size || se.offset + 8 + se.size > p3_ext.string_vault_size)
        die_id(177, P3S_ERR_VAULT_OOB);
    usize vault_base = bias + (usize)p3_ext.string_vault_vaddr;
    u8 *slot = (u8 *)(vault_base + se.offset);

    volatile long long *st = canary_state_ptr(bias);
    volatile u32 *lock = st ? (volatile u32 *)&st[5] : 0;
    if (lock) p3_spin_lock(lock);

    int did_decrypt = 0;
    int reenc_rc = 0;
    u32 die_sig = 0;
    u32 die_str = 0;
    u32 state = (u32)slot[0] | ((u32)slot[1] << 8) | ((u32)slot[2] << 16) | ((u32)slot[3] << 24);
    if (state != 0x50335344u) {
        if (state != 0x50335345u) {
            die_sig = 175; die_str = P3S_ERR_VAULT_HDR;
        } else {
            usize page = page_size();
            if (!page) {
                die_sig = 176; die_str = P3S_ERR_PAGE_SZ;
            } else {
                usize low = (usize)slot & ~(page - 1);
                usize high = ((usize)slot + 8 + se.size + page - 1) & ~(page - 1);
                if (sys6(P3_SYS(226), (long)low, (long)(high - low), 3, 0, 0, 0)) {
                    die_sig = 176; die_str = P3S_ERR_VAULT_RW;
                } else {
                    u8 key[32];
                    derive_master_key(key);
                    p3_chacha20(slot + 8, se.size, key, se.nonce, 1);
                    wipe_buf(key, sizeof(key));
                    u8 actual[32];
                    unsigned diff = 0;
                    p3_sha256(slot + 8, se.size, actual);
                    for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ se.digest[i];
                    if (diff) {
                        die_sig = 175; die_str = P3S_ERR_VAULT_MIS;
                    } else {
                        slot[0] = 0x44; slot[1] = 0x53; slot[2] = 0x33; slot[3] = 0x50;
                        slot[4] = 0;
                        if (sys6(P3_SYS(226), (long)low, (long)(high - low), 1, 0, 0, 0)) {
                            die_sig = 176; die_str = P3S_ERR_VAULT_REST;
                        } else {
                            did_decrypt = 1;
                        }
                    }
                }
            }
        }
    } else if (p3_ext.ext_flags & EXT_EPHEMERAL_STRINGS) {
        if (slot[4] != 0) {
            usize page = page_size();
            if (!page) {
                die_sig = 176; die_str = P3S_ERR_PAGE_SZ;
            } else {
                usize low = (usize)slot & ~(page - 1);
                usize high = ((usize)slot + 8 + se.size + page - 1) & ~(page - 1);
                if (!sys6(P3_SYS(226), (long)low, (long)(high - low), 3, 0, 0, 0)) {
                    slot[4] = 0;
                    sys6(P3_SYS(226), (long)low, (long)(high - low), 1, 0, 0, 0);
                }
            }
        }
    }
    if (!die_sig) {
        reenc_rc = reencrypt_vault_slots_locked(bias, string_id);
        if (reenc_rc == -1) { die_sig = 176; die_str = P3S_ERR_EPH_RW; }
        else if (reenc_rc == -2) { die_sig = 176; die_str = P3S_ERR_EPH_REST; }
    }
    if (lock) p3_spin_unlock(lock);

    if (die_sig) die_id(die_sig, die_str);
    if (did_decrypt) {
        verify_canary_and_anti_gg(bias, 1, 0);
        event_id(P3S_EV_STR_DEC_OK);
    }
    return (const char *)(slot + 8);
}

__attribute__((visibility("hidden"), used))
void p3_on_demand_toggle(u64 range_index, u64 entering) {
    if (p3_ext.ext_version != 3 || range_index >= p3_ext.enc_range_count || p3_ext.enc_range_count > P3_MAX_ENC_RANGES)
        die_id(177, P3S_ERR_OD_IDX);
    struct enc_range r;
    for (usize i = 0; i < sizeof(r); ++i)
        ((u8 *)&r)[i] = ((const volatile u8 *)&p3_ext.enc_ranges[range_index])[i];
    if (!(r.flags & RANGE_FLAG_ON_DEMAND))
        die_id(177, P3S_ERR_OD_CFG);
    usize bias = module_bias();
    usize start = bias + (usize)r.vaddr;
    volatile long long *st = canary_state_ptr(bias);
    volatile u32 *od_lock = st ? (volatile u32 *)&st[6] : 0;
    volatile u32 *od_refs = st ? (volatile u32 *)&st[8] : 0;
    if (od_lock) p3_spin_lock(od_lock);
    u32 cur_ref = od_refs ? od_refs[range_index] : 0u;
    if (entering) {
        if (!od_refs || cur_ref == 0u) {
            decrypt_custom_range(start, (usize)r.size, r.prot, r.nonce, r.counter);
            u8 actual[32];
            unsigned diff = 0;
            p3_sha256((const u8 *)start, (usize)r.size, actual);
            for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ r.plain_digest[i];
            if (diff) {
                if (od_lock) p3_spin_unlock(od_lock);
                die_id(175, P3S_ERR_OD_MIS);
            }
            event_id(P3S_EV_OD_DEC_OK);
        }
        if (od_refs) od_refs[range_index] = cur_ref + 1u;
    } else {
        if (!od_refs || cur_ref <= 1u) {
            if (od_refs) od_refs[range_index] = 0u;
            decrypt_custom_range(start, (usize)r.size, r.prot, r.nonce, r.counter);
            event_id(P3S_EV_OD_REENC_OK);
        } else {
            od_refs[range_index] = cur_ref - 1u;
        }
    }
    if (od_lock) p3_spin_unlock(od_lock);
}

/* O08/O09: Stack-isolated ARM64 Bytecode Virtual Machine Interpreter. */
struct vm_insn {
    u8 op, rd, rn, rm;
    u8 width, cond;
    u16 aux;
    u64 imm;
};
_Static_assert(sizeof(struct vm_insn) == 16, "vm_insn size mismatch");

enum vm_op {
    VM_OP_NOP = 0,
    VM_OP_MOV_IMM = 1,
    VM_OP_MOVK = 2,
    VM_OP_MOV_REG = 3,
    VM_OP_ADD = 4,
    VM_OP_SUB = 5,
    VM_OP_AND = 6,
    VM_OP_ORR = 7,
    VM_OP_EOR = 8,
    VM_OP_BIC = 9,
    VM_OP_ORN = 10,
    VM_OP_EON = 11,
    VM_OP_LSL = 12,
    VM_OP_LSR = 13,
    VM_OP_ASR = 14,
    VM_OP_ROR = 15,
    VM_OP_MADD = 16,
    VM_OP_MSUB = 17,
    VM_OP_UDIV = 18,
    VM_OP_SDIV = 19,
    VM_OP_CSEL = 20,
    VM_OP_BFM = 21,
    VM_OP_ADR = 22,
    VM_OP_LDR = 23,
    VM_OP_STR = 24,
    VM_OP_LDP = 25,
    VM_OP_STP = 26,
    VM_OP_B = 27,
    VM_OP_BCOND = 28,
    VM_OP_CBZ = 29,
    VM_OP_TBZ = 30,
    VM_OP_CALL = 31,
    VM_OP_RET = 32,
    VM_OP_MRS_TPIDR = 33,
    VM_OP_LDR_REG = 34,
    VM_OP_STR_REG = 35,
    VM_OP_ADD_EXT = 36,
    VM_OP_SUB_EXT = 37
};

static u64 vm_mask(u64 val, u8 width) {
    return width == 1 ? (val & 0xFFFFFFFFULL) : val;
}

static long long vm_sext(u64 val, u8 width) {
    return width == 1 ? (long long)(int)(u32)val : (long long)val;
}

static u64 vm_extend_val(u64 val, u8 opt, u8 width) {
    switch (opt & 7u) {
        case 0: return val & 0xFFULL;
        case 1: return val & 0xFFFFULL;
        case 2: return val & 0xFFFFFFFFULL;
        case 3: return width == 1 ? (val & 0xFFFFFFFFULL) : val;
        case 4: return vm_mask((u64)(long long)(signed char)(val & 0xFFULL), width);
        case 5: return vm_mask((u64)(long long)(short)(val & 0xFFFFULL), width);
        case 6: return vm_mask((u64)(long long)(int)(u32)val, width);
        default: return vm_mask((u64)(long long)val, width);
    }
}

static u64 vm_shift_val(u64 val, u8 width, u8 kind, unsigned amount) {
    unsigned limit = width == 1 ? 31u : 63u;
    amount &= limit;
    val = vm_mask(val, width);
    if (!amount) return val;
    if (kind == 0) return vm_mask(val << amount, width);
    if (kind == 1) return val >> amount;
    if (kind == 2) {
        if (width == 1) return (u64)(u32)(((int)(u32)val) >> amount);
        return (u64)(((long long)val) >> amount);
    }
    unsigned bits = width == 1 ? 32u : 64u;
    return vm_mask((val >> amount) | (val << (bits - amount)), width);
}

static u32 vm_flags_add(u64 a, u64 b, u64 res, u8 width) {
    u64 msb = width == 1 ? (1ULL << 31) : (1ULL << 63);
    u32 n = (res & msb) ? 8u : 0u;
    u32 z = (vm_mask(res, width) == 0) ? 4u : 0u;
    u32 c = (vm_mask(res, width) < vm_mask(a, width)) ? 2u : 0u;
    u32 v = ((~(a ^ b) & (a ^ res)) & msb) ? 1u : 0u;
    return n | z | c | v;
}

static u32 vm_flags_sub(u64 a, u64 b, u64 res, u8 width) {
    u64 msb = width == 1 ? (1ULL << 31) : (1ULL << 63);
    u32 n = (res & msb) ? 8u : 0u;
    u32 z = (vm_mask(res, width) == 0) ? 4u : 0u;
    u32 c = (vm_mask(a, width) >= vm_mask(b, width)) ? 2u : 0u;
    u32 v = (((a ^ b) & (a ^ res)) & msb) ? 1u : 0u;
    return n | z | c | v;
}

static int vm_eval_cond(u8 cond, u32 nzcv) {
    u32 n = (nzcv >> 3) & 1u, z = (nzcv >> 2) & 1u, c = (nzcv >> 1) & 1u, v = nzcv & 1u;
    unsigned base = (cond >> 1) & 7u;
    int r = 0;
    if (base == 0) r = (z == 1);
    else if (base == 1) r = (c == 1);
    else if (base == 2) r = (n == 1);
    else if (base == 3) r = (v == 1);
    else if (base == 4) r = (c == 1 && z == 0);
    else if (base == 5) r = (n == v);
    else if (base == 6) r = (z == 0 && n == v);
    else r = 1;
    if ((cond & 1u) && cond < 14u) r = !r;
    return r;
}

extern void p3_vm_call_trampoline(usize target, u64 *vregs, usize stack_copy_bytes) __attribute__((visibility("hidden")));

__attribute__((visibility("hidden"), used))
void p3_vm_exec(u64 prog_index, u64 *regs) {
    if (p3_ext.ext_version != 3 || !(p3_ext.ext_flags & EXT_VM_ENABLED)
            || prog_index >= p3_ext.vm_program_count || p3_ext.vm_program_count > P3_MAX_VM_PROGS)
        die_id(177, P3S_ERR_VM_IDX);
    usize bias = module_bias();
    if (p3_ext.ext_flags & EXT_RUNTIME_GATE)
        p3_runtime_check(prog_index);
    struct vm_prog prog;
    for (usize i = 0; i < sizeof(prog); ++i)
        ((u8 *)&prog)[i] = ((const volatile u8 *)&p3_ext.vm_progs[prog_index])[i];
    struct vm_insn code[P3_MAX_VM_INSNS];
    if (!prog.insn_count || prog.insn_count > P3_MAX_VM_INSNS
            || prog.bytecode_size != prog.insn_count * sizeof(struct vm_insn)
            || prog.bytecode_offset + prog.bytecode_size > p3_ext.vm_bytecode_size)
        die_id(177, P3S_ERR_VM_DESC);
    const u8 *src = (const u8 *)(bias + (usize)p3_ext.vm_bytecode_vaddr + prog.bytecode_offset);
    for (usize i = 0; i < prog.bytecode_size; ++i)
        ((u8 *)code)[i] = src[i];
    u8 vkey[32];
    for (unsigned i = 0; i < 32; ++i) vkey[i] = p3_ext.vm_key[i];
    p3_chacha20((u8 *)code, prog.bytecode_size, vkey, prog.nonce, prog.counter);
    wipe_buf(vkey, sizeof(vkey));
    u8 actual[32];
    unsigned diff = 0;
    p3_sha256((const u8 *)code, prog.bytecode_size, actual);
    for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ prog.digest[i];
    if (diff) die_id(175, P3S_ERR_VM_MIS);

    u8 vm_stack[4096] __attribute__((aligned(16)));
    for (unsigned i = 0; i < sizeof(vm_stack); ++i) vm_stack[i] = 0;
    u64 vregs[32];
    for (unsigned i = 0; i < 31; ++i) vregs[i] = regs[i];
    vregs[31] = (u64)(usize)(vm_stack + sizeof(vm_stack));
    u32 nzcv = 0;
    u32 pc = 0;
    u32 steps = 0;

    while (pc < prog.insn_count) {
        if (++steps > 65536u) die_id(177, P3S_ERR_VM_STEPS);
        struct vm_insn ins = code[pc++];
        u8 op = p3_ext.vm_opcode_map[ins.op & 63u];
        u8 rd = ins.rd & 31u, rn = ins.rn & 31u, rm = ins.rm & 31u;
        u8 w = ins.width;
        u64 a = (rn == 31u && !(ins.aux & 0x4000u)) ? 0ULL : vregs[rn];
        u64 b = (ins.aux & 0x8000u)
            ? ins.imm
            : vm_shift_val((rm == 31u) ? 0ULL : vregs[rm], w, ins.cond & 3u, ins.aux & 63u);
        a = vm_mask(a, w);
        b = vm_mask(b, w);

        if (op == VM_OP_NOP) {
            continue;
        } else if (op == VM_OP_MOV_IMM) {
            if (rd != 31u) vregs[rd] = vm_mask(ins.imm, w);
        } else if (op == VM_OP_MOVK) {
            if (rd != 31u) {
                unsigned shift = ins.aux & 48u;
                u64 cur = vregs[rd] & ~(0xFFFFULL << shift);
                vregs[rd] = vm_mask(cur | ((ins.imm & 0xFFFFULL) << shift), w);
            }
        } else if (op == VM_OP_MOV_REG) {
            u64 src_val = (rn == 31u && (ins.aux & 1u)) ? vregs[31] : (rn == 31u ? 0ULL : vregs[rn]);
            if (rd == 31u) {
                if (ins.aux & 1u) vregs[31] = vm_mask(src_val, w);
            } else {
                vregs[rd] = vm_mask(src_val, w);
            }
        } else if (op == VM_OP_ADD || op == VM_OP_ADD_EXT) {
            u64 rhs = (op == VM_OP_ADD_EXT)
                ? vm_mask(vm_extend_val((rm == 31u) ? 0ULL : vregs[rm], ins.cond & 7u, w) << (ins.aux & 7u), w)
                : b;
            u64 res = vm_mask(a + rhs, w);
            if (ins.cond & 0x80u) nzcv = vm_flags_add(a, rhs, res, w);
            if (rd == 31u) {
                if (!(ins.cond & 0x80u)) vregs[31] = res;
            } else vregs[rd] = res;
        } else if (op == VM_OP_SUB || op == VM_OP_SUB_EXT) {
            u64 rhs = (op == VM_OP_SUB_EXT)
                ? vm_mask(vm_extend_val((rm == 31u) ? 0ULL : vregs[rm], ins.cond & 7u, w) << (ins.aux & 7u), w)
                : b;
            u64 res = vm_mask(a - rhs, w);
            if (ins.cond & 0x80u) nzcv = vm_flags_sub(a, rhs, res, w);
            if (rd == 31u) {
                if (!(ins.cond & 0x80u)) vregs[31] = res;
            } else vregs[rd] = res;
        } else if (op == VM_OP_AND) {
            u64 res = vm_mask(a & b, w);
            if (ins.cond & 0x80u) {
                u64 msb = w == 1 ? (1ULL << 31) : (1ULL << 63);
                nzcv = ((res & msb) ? 8u : 0u) | (res == 0 ? 4u : 0u);
            }
            if (rd != 31u) vregs[rd] = res;
        } else if (op == VM_OP_ORR) {
            if (rd != 31u) vregs[rd] = vm_mask(a | b, w);
        } else if (op == VM_OP_EOR) {
            if (rd != 31u) vregs[rd] = vm_mask(a ^ b, w);
        } else if (op == VM_OP_BIC) {
            if (rd != 31u) vregs[rd] = vm_mask(a & ~b, w);
        } else if (op == VM_OP_ORN) {
            if (rd != 31u) vregs[rd] = vm_mask(a | ~b, w);
        } else if (op == VM_OP_EON) {
            if (rd != 31u) vregs[rd] = vm_mask(a ^ ~b, w);
        } else if (op == VM_OP_LSL) {
            if (rd != 31u) vregs[rd] = vm_shift_val(a, w, 0, (unsigned)b);
        } else if (op == VM_OP_LSR) {
            if (rd != 31u) vregs[rd] = vm_shift_val(a, w, 1, (unsigned)b);
        } else if (op == VM_OP_ASR) {
            if (rd != 31u) vregs[rd] = vm_shift_val(a, w, 2, (unsigned)b);
        } else if (op == VM_OP_ROR) {
            if (rd != 31u) vregs[rd] = vm_shift_val(a, w, 3, (unsigned)b);
        } else if (op == VM_OP_MADD || op == VM_OP_MSUB) {
            u8 ra = ins.aux & 31u;
            u64 acc = (ra == 31u) ? 0ULL : vm_mask(vregs[ra], w);
            u64 prod = vm_mask(a * b, w);
            if (rd != 31u) vregs[rd] = vm_mask(op == VM_OP_MADD ? (acc + prod) : (acc - prod), w);
        } else if (op == VM_OP_UDIV) {
            if (rd != 31u) vregs[rd] = b == 0 ? 0ULL : vm_mask(a / b, w);
        } else if (op == VM_OP_SDIV) {
            if (rd != 31u) {
                long long sa = vm_sext(a, w), sb = vm_sext(b, w);
                long long q = 0;
                if (sb != 0) {
                    if (w == 1 && sa == (-2147483647LL - 1LL) && sb == -1LL) q = sa;
                    else if (w == 0 && (u64)sa == (1ULL << 63) && sb == -1LL) q = sa;
                    else q = sa / sb;
                }
                vregs[rd] = vm_mask((u64)q, w);
            }
        } else if (op == VM_OP_CSEL) {
            u64 tv = (rn == 31u) ? 0ULL : vm_mask(vregs[rn], w);
            u64 fv = (rm == 31u) ? 0ULL : vm_mask(vregs[rm], w);
            unsigned kind = ins.aux & 3u;
            if (kind == 1) fv = vm_mask(fv + 1, w);
            else if (kind == 2) fv = vm_mask(~fv, w);
            else if (kind == 3) fv = vm_mask(-fv, w);
            if (rd != 31u) vregs[rd] = vm_eval_cond(ins.cond & 15u, nzcv) ? tv : fv;
        } else if (op == VM_OP_BFM) {
            unsigned immr = (ins.aux >> 6) & 63u, imms = ins.aux & 63u;
            unsigned bits = w == 1 ? 32u : 64u;
            u64 src_v = (rn == 31u) ? 0ULL : vm_mask(vregs[rn], w);
            u64 dst_v = (rd == 31u) ? 0ULL : vm_mask(vregs[rd], w);
            u64 res = 0;
            if (imms >= immr) {
                unsigned len = imms - immr + 1u;
                u64 mask = len >= 64u ? ~0ULL : ((1ULL << len) - 1ULL);
                res = (src_v >> immr) & mask;
                if (ins.cond == 0 && ((src_v >> imms) & 1ULL)) {
                    u64 smask = len >= 64u ? 0ULL : (~0ULL << len);
                    res |= smask;
                } else if (ins.cond == 1) {
                    res = (dst_v & ~mask) | res;
                }
            } else {
                unsigned shift = bits - immr;
                unsigned len = imms + 1u;
                u64 mask = len >= 64u ? ~0ULL : ((1ULL << len) - 1ULL);
                res = ((src_v & mask) << shift);
                if (ins.cond == 0 && ((src_v >> imms) & 1ULL)) {
                    u64 smask = (shift + len) >= 64u ? 0ULL : (~0ULL << (shift + len));
                    res |= smask;
                } else if (ins.cond == 1) {
                    res = (dst_v & ~(mask << shift)) | res;
                }
            }
            if (rd != 31u) vregs[rd] = vm_mask(res, w);
        } else if (op == VM_OP_ADR) {
            if (rd != 31u) vregs[rd] = (u64)bias + ins.imm;
        } else if (op == VM_OP_MRS_TPIDR) {
            u64 tp = 0;
            __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
            if (rd != 31u) vregs[rd] = tp;
        } else if (op == VM_OP_LDR || op == VM_OP_STR || op == VM_OP_LDR_REG || op == VM_OP_STR_REG) {
            u64 base = vregs[rn];
            u64 addr = 0;
            int is_reg = (op == VM_OP_LDR_REG || op == VM_OP_STR_REG);
            int is_load = (op == VM_OP_LDR || op == VM_OP_LDR_REG);
            if (is_reg) {
                u64 idx_raw = (rm == 31u) ? 0ULL : vregs[rm];
                u8 opt = (u8)((ins.aux >> 3) & 7u);
                u64 idx = vm_extend_val(idx_raw, opt, 0);
                addr = base + (idx << (ins.aux & 7u));
            } else {
                addr = (ins.cond & 4u) ? base : (u64)((long long)base + (long long)ins.imm);
            }
            if (is_load) {
                u64 val = 0;
                if (w == 1) val = *(const u8 *)(usize)addr;
                else if (w == 2) val = *(const unsigned short *)(usize)addr;
                else if (w == 4) val = *(const u32 *)(usize)addr;
                else val = *(const u64 *)(usize)addr;
                if (ins.cond & 1u) {
                    if (w == 1) val = (u64)(long long)*(const signed char *)(usize)addr;
                    else if (w == 2) val = (u64)(long long)*(const short *)(usize)addr;
                    else if (w == 4) val = (u64)(long long)*(const int *)(usize)addr;
                    if (is_reg ? (ins.cond & 2u) : (ins.aux & 1u)) val &= 0xFFFFFFFFULL;
                }
                if (rd != 31u) vregs[rd] = val;
            } else {
                u64 val = (rd == 31u) ? 0ULL : vregs[rd];
                if (w == 1) *(u8 *)(usize)addr = (u8)val;
                else if (w == 2) *(unsigned short *)(usize)addr = (unsigned short)val;
                else if (w == 4) *(u32 *)(usize)addr = (u32)val;
                else *(u64 *)(usize)addr = val;
            }
            if (!is_reg && (ins.cond & 6u)) vregs[rn] = (u64)((long long)base + (long long)ins.imm);
        } else if (op == VM_OP_LDP || op == VM_OP_STP) {
            u64 base = vregs[rn];
            u64 addr = (ins.cond & 4u) ? base : (u64)((long long)base + (long long)ins.imm);
            if (op == VM_OP_LDP) {
                if (w == 4) {
                    u64 v1 = *(const u32 *)(usize)addr;
                    u64 v2 = *(const u32 *)(usize)(addr + 4);
                    if (ins.cond & 1u) {
                        v1 = (u64)(long long)(int)v1;
                        v2 = (u64)(long long)(int)v2;
                    }
                    if (rd != 31u) vregs[rd] = v1;
                    if (rm != 31u) vregs[rm] = v2;
                } else {
                    u64 v1 = *(const u64 *)(usize)addr;
                    u64 v2 = *(const u64 *)(usize)(addr + 8);
                    if (rd != 31u) vregs[rd] = v1;
                    if (rm != 31u) vregs[rm] = v2;
                }
            } else {
                u64 v1 = (rd == 31u) ? 0ULL : vregs[rd];
                u64 v2 = (rm == 31u) ? 0ULL : vregs[rm];
                if (w == 4) {
                    *(u32 *)(usize)addr = (u32)v1;
                    *(u32 *)(usize)(addr + 4) = (u32)v2;
                } else {
                    *(u64 *)(usize)addr = v1;
                    *(u64 *)(usize)(addr + 8) = v2;
                }
            }
            if (ins.cond & 6u) vregs[rn] = (u64)((long long)base + (long long)ins.imm);
        } else if (op == VM_OP_B) {
            if (ins.imm >= prog.insn_count) die_id(177, P3S_ERR_VM_BR);
            pc = (u32)ins.imm;
        } else if (op == VM_OP_BCOND) {
            if (vm_eval_cond(ins.cond & 15u, nzcv)) {
                if (ins.imm >= prog.insn_count) die_id(177, P3S_ERR_VM_CBR);
                pc = (u32)ins.imm;
            }
        } else if (op == VM_OP_CBZ) {
            u64 v = (rd == 31u) ? 0ULL : vm_mask(vregs[rd], w);
            if ((v == 0) == (ins.cond == 0)) {
                if (ins.imm >= prog.insn_count) die_id(177, P3S_ERR_VM_CBZ);
                pc = (u32)ins.imm;
            }
        } else if (op == VM_OP_TBZ) {
            u64 v = (rd == 31u) ? 0ULL : vregs[rd];
            unsigned bit = ins.aux & 63u;
            if ((((v >> bit) & 1ULL) == 0) == (ins.cond == 0)) {
                if (ins.imm >= prog.insn_count) die_id(177, P3S_ERR_VM_TBZ);
                pc = (u32)ins.imm;
            }
        } else if (op == VM_OP_CALL) {
            usize target = (ins.cond == 1) ? (usize)vregs[rn] : (bias + (usize)ins.imm);
            usize stack_top = (usize)(vm_stack + sizeof(vm_stack));
            usize vsp = (usize)vregs[31];
            usize avail = (vsp >= (usize)vm_stack && vsp < stack_top) ? (stack_top - vsp) : 0u;
            if (avail > 128u) avail = 128u;
            avail &= ~(usize)15u;
            p3_vm_call_trampoline(target, vregs, avail);
        } else if (op == VM_OP_RET) {
            break;
        } else {
            die_id(177, P3S_ERR_VM_OP);
        }
    }

    for (unsigned i = 0; i < 30; ++i) regs[i] = vregs[i];
    wipe_buf(code, sizeof(code));
    event_id(P3S_EV_VM_OK);
}

/* ---------------- RFC 1951 Streaming ChaCha20 + Inflate (E09) ---------------- */
struct dec_stream {
    const u8 *src;
    usize len, pos;
    int encrypted;
    u8 key[32];
    u8 nonce[12];
    u64 cached_blk;
    u8 ks[64];
    u32 bitbuf;
    int bitcnt;
};

struct inf_tree {
    u16 table[16];
    u16 trans[288];
};

static inline int stream_next_byte(struct dec_stream *st) {
    if (st->pos >= st->len) return -1;
    u8 raw = st->src[st->pos];
    if (st->encrypted) {
        u64 blk = (u64)(st->pos >> 6);
        if (blk != st->cached_blk) {
            p3_chacha20_block(st->key, st->nonce, 1u + (u32)blk, st->ks);
            st->cached_blk = blk;
        }
        raw ^= st->ks[st->pos & 63u];
    }
    st->pos++;
    return (int)raw;
}

static inline int fill_bits(struct dec_stream *st, int need) {
    while (st->bitcnt < need) {
        int b = stream_next_byte(st);
        if (b < 0) return 0;
        st->bitbuf |= ((u32)b) << st->bitcnt;
        st->bitcnt += 8;
    }
    return 1;
}

static inline int get_bits(struct dec_stream *st, int n) {
    if (!n) return 0;
    if (!fill_bits(st, n)) return -1;
    int v = (int)(st->bitbuf & ((1u << n) - 1u));
    st->bitbuf >>= n;
    st->bitcnt -= n;
    return v;
}

static void inf_build_tree(struct inf_tree *t, const u8 *lengths, unsigned num) {
    u16 offs[16];
    for (unsigned i = 0; i < 16u; ++i) t->table[i] = 0;
    for (unsigned i = 0; i < num; ++i) {
        if (lengths[i] < 16u) t->table[lengths[i]]++;
    }
    t->table[0] = 0;
    u16 sum = 0;
    for (unsigned i = 0; i < 16u; ++i) {
        offs[i] = sum;
        sum += t->table[i];
    }
    for (unsigned i = 0; i < num; ++i) {
        if (lengths[i] && lengths[i] < 16u) t->trans[offs[lengths[i]]++] = (u16)i;
    }
}

static inline int inf_decode_sym(struct dec_stream *st, const struct inf_tree *t) {
    int sum = 0, cur = 0, len = 0;
    if (st->bitcnt < 15 && st->pos + 2 <= st->len) fill_bits(st, 16);
    do {
        if (st->bitcnt == 0 && !fill_bits(st, 1)) return -1;
        int bit = (int)(st->bitbuf & 1u);
        st->bitbuf >>= 1;
        st->bitcnt--;
        cur = (cur << 1) | bit;
        len++;
        if (len >= 16) return -1;
        int cnt = (int)t->table[len];
        cur -= cnt;
        sum += cnt;
    } while (cur >= 0);
    int idx = sum + cur;
    if (idx < 0 || idx >= 288) return -1;
    return (int)t->trans[idx];
}

static long p3_inflate_stream(struct dec_stream *st, u8 *dst, usize cap) {
    static const u16 len_base[29] = {
        3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
    };
    static const u8 len_bits[29] = {
        0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
    };
    static const u16 dist_base[30] = {
        1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
        1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
    };
    static const u8 dist_bits[30] = {
        0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
    };
    static const u8 clcidx[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};

    usize out_pos = 0;
    struct inf_tree ltree, dtree;
    u8 lengths[320];

    for (;;) {
        int bfinal = get_bits(st, 1);
        int btype = get_bits(st, 2);
        if (bfinal < 0 || btype < 0 || btype == 3) return -1;
        if (btype == 0) {
            /* Align to next byte boundary */
            int drop = st->bitcnt & 7;
            if (drop) {
                st->bitbuf >>= drop;
                st->bitcnt -= drop;
            }
            int l0 = get_bits(st, 8);
            int l1 = get_bits(st, 8);
            int n0 = get_bits(st, 8);
            int n1 = get_bits(st, 8);
            if (l0 < 0 || l1 < 0 || n0 < 0 || n1 < 0) return -1;
            u32 len = (u32)l0 | ((u32)l1 << 8);
            u32 nlen = (u32)n0 | ((u32)n1 << 8);
            if ((len ^ 0xFFFFu) != nlen || out_pos + len > cap) return -1;
            for (u32 i = 0; i < len; ++i) {
                int ch = get_bits(st, 8);
                if (ch < 0) return -1;
                dst[out_pos++] = (u8)ch;
            }
        } else {
            if (btype == 1) {
                for (unsigned i = 0; i < 144u; ++i) lengths[i] = 8u;
                for (unsigned i = 144u; i < 256u; ++i) lengths[i] = 9u;
                for (unsigned i = 256u; i < 280u; ++i) lengths[i] = 7u;
                for (unsigned i = 280u; i < 288u; ++i) lengths[i] = 8u;
                inf_build_tree(&ltree, lengths, 288u);
                for (unsigned i = 0; i < 32u; ++i) lengths[i] = 5u;
                inf_build_tree(&dtree, lengths, 32u);
            } else {
                int hlit_r = get_bits(st, 5);
                int hdist_r = get_bits(st, 5);
                int hclen_r = get_bits(st, 4);
                if (hlit_r < 0 || hdist_r < 0 || hclen_r < 0) return -1;
                unsigned hlit = (unsigned)hlit_r + 257u;
                unsigned hdist = (unsigned)hdist_r + 1u;
                unsigned hclen = (unsigned)hclen_r + 4u;
                if (hlit > 286u || hdist > 30u || hlit + hdist > sizeof(lengths)) return -1;
                for (unsigned i = 0; i < 19u; ++i) lengths[i] = 0u;
                for (unsigned i = 0; i < hclen; ++i) {
                    int b = get_bits(st, 3);
                    if (b < 0) return -1;
                    lengths[clcidx[i]] = (u8)b;
                }
                inf_build_tree(&ltree, lengths, 19u);
                unsigned num = 0;
                while (num < hlit + hdist) {
                    int sym = inf_decode_sym(st, &ltree);
                    if (sym < 0) return -1;
                    if (sym < 16) {
                        lengths[num++] = (u8)sym;
                    } else {
                        u8 prev = (sym == 16 && num > 0) ? lengths[num - 1u] : 0u;
                        int rep = 0;
                        if (sym == 16) {
                            if (num == 0) return -1;
                            int ex = get_bits(st, 2); if (ex < 0) return -1;
                            rep = 3 + ex;
                        } else if (sym == 17) {
                            int ex = get_bits(st, 3); if (ex < 0) return -1;
                            rep = 3 + ex;
                        } else {
                            int ex = get_bits(st, 7); if (ex < 0) return -1;
                            rep = 11 + ex;
                        }
                        if (num + (unsigned)rep > hlit + hdist) return -1;
                        for (int k = 0; k < rep; ++k) lengths[num++] = prev;
                    }
                }
                inf_build_tree(&ltree, lengths, hlit);
                inf_build_tree(&dtree, lengths + hlit, hdist);
            }
            for (;;) {
                int sym = inf_decode_sym(st, &ltree);
                if (sym < 0) return -1;
                if (sym == 256) break;
                if (sym < 256) {
                    if (out_pos >= cap) return -1;
                    dst[out_pos++] = (u8)sym;
                } else {
                    int lidx = sym - 257;
                    if (lidx < 0 || lidx >= 29) return -1;
                    int lex = len_bits[lidx] ? get_bits(st, len_bits[lidx]) : 0;
                    if (lex < 0) return -1;
                    u32 mlen = (u32)len_base[lidx] + (u32)lex;
                    int dsym = inf_decode_sym(st, &dtree);
                    if (dsym < 0 || dsym >= 30) return -1;
                    int dex = dist_bits[dsym] ? get_bits(st, dist_bits[dsym]) : 0;
                    if (dex < 0) return -1;
                    u32 mdist = (u32)dist_base[dsym] + (u32)dex;
                    if (mdist == 0 || mdist > out_pos || out_pos + mlen > cap) return -1;
                    for (u32 k = 0; k < mlen; ++k) dst[out_pos + k] = dst[out_pos - mdist + k];
                    out_pos += mlen;
                }
            }
        }
        if (bfinal) break;
    }
    return (long)out_pos;
}

__attribute__((visibility("hidden"), used))
long p3_inflate_mem(const u8 *src, usize src_len, u8 *dst, usize dst_cap) {
    struct dec_stream st;
    st.src = src; st.len = src_len; st.pos = 0;
    st.encrypted = 0; st.cached_blk = (u64)-1;
    st.bitbuf = 0; st.bitcnt = 0;
    return p3_inflate_stream(&st, dst, dst_cap);
}

static long inf_dec_chunk(const u8 *src, usize src_len, const u8 key[32], const u8 base_nonce[12], u32 stream_idx, u8 *dst, usize dst_cap) {
    struct dec_stream st;
    st.src = src; st.len = src_len; st.pos = 0;
    st.encrypted = 1;
    for (unsigned i = 0; i < 32u; ++i) st.key[i] = key[i];
    for (unsigned i = 0; i < 12u; ++i) st.nonce[i] = base_nonce[i];
    st.nonce[8] ^= (u8)stream_idx;
    st.nonce[9] ^= (u8)(stream_idx >> 8);
    st.nonce[10] ^= (u8)(stream_idx >> 16);
    st.nonce[11] ^= (u8)(stream_idx >> 24);
    st.cached_blk = (u64)-1;
    st.bitbuf = 0; st.bitcnt = 0;
    long got = p3_inflate_stream(&st, dst, dst_cap);
    wipe_buf(&st, sizeof(st));
    return got;
}

/* Zero-import runtime libdl.so parser via /proc/self/maps (handles GNU_HASH and SysV HASH). */
static int hex_line_val(const char *s, usize *out_pos, u64 *out_val) {
    usize i = *out_pos;
    u64 v = 0;
    int any = 0;
    for (;;) {
        char c = s[i];
        u64 d;
        if (c >= '0' && c <= '9') d = (u64)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (u64)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (u64)(c - 'A' + 10);
        else break;
        v = (v << 4) | d;
        any = 1;
        ++i;
    }
    *out_pos = i;
    *out_val = v;
    return any;
}

static usize fix_dyn_ptr(u64 val, usize base, usize span) {
    if (val >= base && val < base + span) return (usize)val;
    return base + (usize)val;
}

static usize lookup_elf_sym_mem(usize base, const char *target) {
    if (*(const u32 *)base != 0x464C457Fu) return 0;
    const u8 *hdr = (const u8 *)base;
    if (hdr[4] != 2u || *(const u16 *)(hdr + 18) != 183u) return 0;
    u64 e_phoff = *(const u64 *)(hdr + 32);
    u16 e_phentsize = *(const u16 *)(hdr + 54);
    u16 e_phnum = *(const u16 *)(hdr + 56);

    usize min_va = (usize)-1, max_va = 0, dyn_va = 0;
    for (u16 i = 0; i < e_phnum; ++i) {
        const u8 *ph = hdr + e_phoff + (usize)i * e_phentsize;
        u32 p_type = *(const u32 *)ph;
        u64 p_va = *(const u64 *)(ph + 16);
        u64 p_msz = *(const u64 *)(ph + 40);
        if (p_type == 1u) {
            if ((usize)p_va < min_va) min_va = (usize)p_va;
            if ((usize)(p_va + p_msz) > max_va) max_va = (usize)(p_va + p_msz);
        } else if (p_type == 2u) {
            dyn_va = (usize)p_va;
        }
    }
    if (!dyn_va || min_va == (usize)-1) return 0;
    usize bias = base - min_va;
    usize span = max_va - min_va;
    const u64 *dyn = (const u64 *)(bias + dyn_va);
    usize strtab = 0, symtab = 0, hash = 0, gnu_hash = 0;
    for (usize i = 0; dyn[i] != 0; i += 2) {
        u64 tag = dyn[i], val = dyn[i + 1];
        if (tag == 5u) strtab = fix_dyn_ptr(val, base, span);
        else if (tag == 6u) symtab = fix_dyn_ptr(val, base, span);
        else if (tag == 4u) hash = fix_dyn_ptr(val, base, span);
        else if (tag == 0x6ffffef5ULL) gnu_hash = fix_dyn_ptr(val, base, span);
    }
    if (!strtab || !symtab) return 0;

    if (gnu_hash) {
        u32 h = 5381u;
        for (const char *p = target; *p; ++p) h = (h << 5) + h + (u8)*p;
        const u32 *ht = (const u32 *)gnu_hash;
        u32 nbuckets = ht[0], symoffset = ht[1], bloom_sz = ht[2];
        const u64 *bloom = (const u64 *)(ht + 4);
        const u32 *buckets = (const u32 *)(bloom + bloom_sz);
        const u32 *chains = buckets + nbuckets;
        if (nbuckets) {
            u32 idx = buckets[h % nbuckets];
            if (idx >= symoffset) {
                for (;;) {
                    u32 cval = chains[idx - symoffset];
                    if ((cval | 1u) == (h | 1u)) {
                        const u8 *sym = (const u8 *)symtab + (usize)idx * 24u;
                        u32 st_name = *(const u32 *)sym;
                        u16 st_shndx = *(const u16 *)(sym + 6);
                        u64 st_val = *(const u64 *)(sym + 8);
                        if (st_shndx != 0u && str_eq((const char *)(strtab + st_name), target))
                            return bias + (usize)st_val;
                    }
                    if (cval & 1u) break;
                    idx++;
                }
            }
        }
    }
    if (hash) {
        u32 h = 0, g;
        for (const char *p = target; *p; ++p) {
            h = (h << 4) + (u8)*p;
            g = h & 0xF0000000u;
            if (g) h ^= g >> 24;
            h &= ~g;
        }
        const u32 *ht = (const u32 *)hash;
        u32 nbuckets = ht[0];
        const u32 *buckets = ht + 2;
        const u32 *chains = buckets + nbuckets;
        if (nbuckets) {
            for (u32 idx = buckets[h % nbuckets]; idx != 0; idx = chains[idx]) {
                const u8 *sym = (const u8 *)symtab + (usize)idx * 24u;
                u32 st_name = *(const u32 *)sym;
                u16 st_shndx = *(const u16 *)(sym + 6);
                u64 st_val = *(const u64 *)(sym + 8);
                if (st_shndx != 0u && str_eq((const char *)(strtab + st_name), target))
                    return bias + (usize)st_val;
            }
        }
    }
    return 0;
}

static int find_libdl_resolvers(void *(**out_dlsym)(void *, const char *), void *(**out_dlopen)(const char *, int)) {
    long fd = open_read_id(P3S_PROC_MAPS);
    if (fd < 0) return 0;
    char suffix[16], n_dlsym[16], n_dlopen[16];
    decode_str(P3S_LIBDL_SO, suffix, sizeof(suffix));
    decode_str(P3S_SYM_DLSYM, n_dlsym, sizeof(n_dlsym));
    decode_str(P3S_SYM_DLOPEN, n_dlopen, sizeof(n_dlopen));
    usize sfx_len = length(suffix);

    char line[600];
    usize lpos = 0;
    usize found_dlsym = 0, found_dlopen = 0;
    char buf[2048];
    for (;;) {
        long got = read_fd(fd, buf, sizeof(buf));
        if (got <= 0) break;
        for (long i = 0; i < got; ++i) {
            char ch = buf[i];
            if (ch == '\n' || lpos + 1 >= sizeof(line)) {
                line[lpos] = 0;
                while (lpos > 0 && (line[lpos - 1] == ' ' || line[lpos - 1] == '\r')) line[--lpos] = 0;
                if (lpos >= sfx_len && str_eq(line + lpos - sfx_len, suffix)) {
                    usize k = 0;
                    u64 mstart = 0, mend = 0, foff = 0;
                    if (hex_line_val(line, &k, &mstart) && line[k] == '-' && (k++, hex_line_val(line, &k, &mend))) {
                        while (line[k] == ' ') ++k;
                        char rperm = line[k];
                        while (line[k] && line[k] != ' ') ++k;
                        while (line[k] == ' ') ++k;
                        if (rperm == 'r' && hex_line_val(line, &k, &foff) && foff == 0ULL && mstart != 0ULL) {
                            usize ds = lookup_elf_sym_mem((usize)mstart, n_dlsym);
                            usize dp = lookup_elf_sym_mem((usize)mstart, n_dlopen);
                            if (ds) {
                                found_dlsym = ds;
                                found_dlopen = dp;
                                break;
                            }
                        }
                    }
                }
                lpos = 0;
            } else {
                line[lpos++] = ch;
            }
        }
        if (found_dlsym) break;
    }
    close_fd(fd);
    wipe_buf(suffix, sizeof(suffix));
    wipe_buf(n_dlsym, sizeof(n_dlsym));
    wipe_buf(n_dlopen, sizeof(n_dlopen));
    *out_dlsym = (void *(*)(void *, const char *))found_dlsym;
    *out_dlopen = (void *(*)(const char *, int))found_dlopen;
    return found_dlsym != 0;
}

static void run_env_and_security_probes(u32 flags) {
    if (flags & DEBUGGER) {
        int result = scan_id(P3S_PROC_STATUS, 0);
        if (result == 0 && p3_ext.ext_version == 3 && (p3_ext.ext_flags & EXT_DEEP_PROBES)) {
            if (scan_id(P3S_PROC_WCHAN, 4) == 1) result = 1;
        }
        event_id(result == 1 ? P3S_CHK_DBG_DET : result < 0 ? P3S_CHK_DBG_UNAV : P3S_CHK_DBG_NO);
        if (result == 1) detected_id(flags, 171, P3S_ERR_DBG_LOAD);
        if (result < 0) {
            if (flags & STRICT_PROC) die_id(178, P3S_ERR_DBG_UNAV);
            char u[80]; decode_str(P3S_ERR_DBG_UNAV, u, sizeof(u)); message(u); wipe_buf(u, sizeof(u));
        }
    } else event_id(P3S_CHK_DBG_DIS);

    if (flags & HOOKS) {
        int result = scan_id(P3S_PROC_MAPS, 1);
        if (result == 0 && p3_ext.ext_version == 3 && (p3_ext.ext_flags & EXT_DEEP_PROBES)) {
            if (scan_id(P3S_PROC_COMM, 1) == 1) result = 1;
            if (result == 0 && (scan_id(P3S_PROC_NET_TCP, 7) == 1 || scan_id(P3S_PROC_NET_TCP6, 7) == 1))
                result = 1;
        }
        event_id(result == 1 ? P3S_CHK_HK_DET : result < 0 ? P3S_CHK_HK_UNAV : P3S_CHK_HK_NO);
        if (result == 1) detected_id(flags, 172, P3S_ERR_HOOKS_LOAD);
        if (result < 0) {
            if (flags & STRICT_PROC) die_id(178, P3S_ERR_MAPS_UNAV);
            char u[80]; decode_str(P3S_ERR_MAPS_UNAV, u, sizeof(u)); message(u); wipe_buf(u, sizeof(u));
        }
    } else event_id(P3S_CHK_HK_DIS);

    if (flags & ROOT) {
        int result = scan_id(P3S_PROC_MAPS, 2);
        int found = root_files() || result == 1;
        event_id(found ? P3S_CHK_RT_DET : result < 0 ? P3S_CHK_RT_UNAV : P3S_CHK_RT_NO);
        if (found) detected_id(flags, 173, P3S_ERR_ROOT_LOAD);
        if (result < 0 && (flags & STRICT_PROC)) die_id(178, P3S_ERR_ROOT_UNAV);
    } else event_id(P3S_CHK_RT_DIS);

    if (flags & EMULATOR) {
        int result = scan_id(P3S_PROC_CPUINFO, 3);
        int found = emulator_files() || result == 1;
        event_id(found ? P3S_CHK_EM_DET : result < 0 ? P3S_CHK_EM_UNAV : P3S_CHK_EM_NO);
        if (found) detected_id(flags, 174, P3S_ERR_EMU_LOAD);
        if (result < 0 && (flags & STRICT_PROC)) die_id(178, P3S_ERR_CPU_UNAV);
    } else event_id(P3S_CHK_EM_DIS);

    if (flags & DENY_ATTACH) {
        if (sys6(P3_SYS(167), 4, 0, 0, 0, 0, 0)) detected_id(flags, 178, P3S_ERR_DUMPABLE);
    }
}

/* E09 Compressed Packed ELF Entry Point (runs in DT_INIT before .init_array). */
__attribute__((visibility("hidden"), section(".text.p3_pack")))
void p3_pack_entry(int argc, char **argv, char **envp) {
    u32 flags = p3_config.flags;
    if (p3_config.version != 2u || p3_pack.enabled != 0x5033504Bu || !p3_pack.seg_count || p3_pack.seg_count > P3_PACK_MAX_SEGS)
        die_id(177, P3S_ERR_CFG_INV);
    usize bias = module_bias();
    event_id(P3S_EV_GUARD_START);
    verify_manifest_and_self(bias);
    run_env_and_security_probes(flags);

    usize page = page_size();
    if (!page) die_id(176, P3S_ERR_PAGE_SZ);
    u8 key[32];
    derive_master_key(key);

    /* E04: Pre-decryption HMAC-SHA256 over the entire LOAD_PACK ciphertext */
    const u8 *blob_ptr = (const u8 *)(bias + (usize)p3_pack.blob_vaddr);
    u8 pk_nonce[12], expected_mac[32];
    for (unsigned i = 0; i < 12u; ++i) pk_nonce[i] = p3_pack.nonce[i];
    for (unsigned i = 0; i < 32u; ++i) expected_mac[i] = p3_pack.cipher_mac[i];
    verify_cipher_mac_explicit(key, p3_pack.pack_shift, p3_pack.blob_size, pk_nonce, blob_ptr, (usize)p3_pack.blob_size, expected_mac);

    /* Save any pre-applied linker slots (e.g. kept TLS relocations) before overwriting NOBITS segments */
    u64 saved_vals[P3_PACK_MAX_SAVED];
    u32 n_saved = p3_pack.saved_slot_count;
    if (n_saved > P3_PACK_MAX_SAVED) die_id(177, P3S_ERR_CFG_INV);
    for (u32 i = 0; i < n_saved; ++i)
        saved_vals[i] = *(const volatile u64 *)(bias + (usize)p3_pack.saved_slots[i]);

    /* Stream-decrypt + inflate every compressed PT_LOAD directly into shifted VMAs */
    for (u32 i = 0; i < p3_pack.seg_count; ++i) {
        struct pack_seg sg;
        for (usize k = 0; k < sizeof(sg); ++k)
            ((u8 *)&sg)[k] = ((const volatile u8 *)&p3_pack.segs[i])[k];
        if (!sg.memsz) continue;
        usize dst = bias + (usize)sg.target_vaddr;
        usize low = dst & ~(page - 1u);
        usize high = (dst + (usize)sg.memsz + page - 1u) & ~(page - 1u);
        if (sys6(P3_SYS(226), (long)low, (long)(high - low), 3, 0, 0, 0)) {
            wipe_buf(key, sizeof(key));
            die_id(176, P3S_ERR_MPROT_RW);
        }
        if (sg.uncomp_size > 0u) {
            long got = inf_dec_chunk(blob_ptr + (usize)sg.comp_offset, (usize)sg.comp_size, key, pk_nonce, 1u + i, (u8 *)dst, (usize)sg.uncomp_size);
            if (got != (long)sg.uncomp_size) {
                wipe_buf(key, sizeof(key));
                die_id(175, P3S_ERR_PACK_DEC);
            }
        }
        if (i == 0u && sg.uncomp_size > 0u) {
            u8 actual[32];
            unsigned diff = 0;
            p3_sha256((const u8 *)dst, (usize)sg.uncomp_size, actual);
            for (unsigned j = 0; j < 32u; ++j) diff |= actual[j] ^ p3_pack.seg0_plain_sha256[j];
            if (diff) { wipe_buf(key, sizeof(key)); die_id(175, P3S_ERR_CODE_MIS); }
        }
    }

    /* Restore pre-applied TLS/symbolic slots saved before segment inflation */
    for (u32 i = 0; i < n_saved; ++i)
        *(volatile u64 *)(bias + (usize)p3_pack.saved_slots[i]) = saved_vals[i];

    /* Apply compressed ULEB128/SLEB128 R_AARCH64_RELATIVE relocation table via temp anonymous mmap */
    if (p3_pack.reloc_count > 0u && p3_pack.reloc_uncomp_sz > 0u) {
        usize map_sz = ((usize)p3_pack.reloc_uncomp_sz + page - 1u) & ~(page - 1u);
        long tmp = sys6(P3_SYS(222), 0, (long)map_sz, 3, 0x22, -1, 0);
        if (tmp < 0 || (u64)tmp >= 0xFFFFFFFFFFFFF000ULL) {
            wipe_buf(key, sizeof(key));
            die_id(176, P3S_ERR_MPROT_RW);
        }
        u8 *rbuf = (u8 *)(usize)tmp;
        long got = inf_dec_chunk(blob_ptr + (usize)p3_pack.reloc_offset, (usize)p3_pack.reloc_comp_sz,
                                 key, pk_nonce, 0x100u, rbuf, (usize)p3_pack.reloc_uncomp_sz);
        if (got != (long)p3_pack.reloc_uncomp_sz) {
            wipe_buf(rbuf, map_sz);
            sys6(P3_SYS(215), (long)tmp, (long)map_sz, 0, 0, 0, 0);
            wipe_buf(key, sizeof(key));
            die_id(175, P3S_ERR_PACK_DEC);
        }
        const u8 *cur = rbuf;
        const u8 *end = rbuf + (usize)p3_pack.reloc_uncomp_sz;
        u64 r_off = 0;
        long long r_add = 0;
        usize eff_bias = bias + (usize)p3_pack.pack_shift;
        for (u64 idx = 0; idx < p3_pack.reloc_count; ++idx) {
            r_off += read_uleb(&cur, end);
            r_add += read_sleb(&cur, end);
            *(u64 *)(eff_bias + (usize)r_off) = (u64)(eff_bias + (usize)r_add);
        }
        wipe_buf(rbuf, map_sz);
        sys6(P3_SYS(215), (long)tmp, (long)map_sz, 0, 0, 0, 0);
    }

    /* Apply compressed internal + external dynamic symbol relocations (.got.plt/.got/.data/.data.rel.ro) */
    if (p3_pack.import_count > 0u && p3_pack.import_uncomp_sz > 0u) {
        usize map_sz = ((usize)p3_pack.import_uncomp_sz + page - 1u) & ~(page - 1u);
        long tmp = sys6(P3_SYS(222), 0, (long)map_sz, 3, 0x22, -1, 0);
        if (tmp < 0 || (u64)tmp >= 0xFFFFFFFFFFFFF000ULL) {
            wipe_buf(key, sizeof(key));
            die_id(176, P3S_ERR_MPROT_RW);
        }
        u8 *ibuf = (u8 *)(usize)tmp;
        long got = inf_dec_chunk(blob_ptr + (usize)p3_pack.import_offset, (usize)p3_pack.import_comp_sz,
                                 key, pk_nonce, 0x200u, ibuf, (usize)p3_pack.import_uncomp_sz);
        if (got != (long)p3_pack.import_uncomp_sz) {
            wipe_buf(ibuf, map_sz);
            sys6(P3_SYS(215), (long)tmp, (long)map_sz, 0, 0, 0, 0);
            wipe_buf(key, sizeof(key));
            die_id(175, P3S_ERR_PACK_DEC);
        }

        void *(*fn_dlsym)(void *, const char *) = 0;
        void *(*fn_dlopen)(const char *, int) = 0;
        void *needed_handles[32];
        u32 n_handles = 0;
        int dl_checked = 0;

        /* Also decode needed library list (plaintext tiny encrypted block if needed_size > 0) */
        u8 nbuf[1024];
        usize nlen = 0;
        if (p3_pack.needed_size > 0u && p3_pack.needed_size <= sizeof(nbuf)) {
            for (usize k = 0; k < (usize)p3_pack.needed_size; ++k)
                nbuf[k] = blob_ptr[(usize)p3_pack.needed_offset + k];
            u8 n_nonce[12];
            for (unsigned j = 0; j < 12u; ++j) n_nonce[j] = pk_nonce[j];
            n_nonce[8] ^= 0x55u;
            p3_chacha20(nbuf, (usize)p3_pack.needed_size, key, n_nonce, 1u);
            nlen = (usize)p3_pack.needed_size;
        }

        const u8 *cur = ibuf;
        const u8 *end = ibuf + (usize)p3_pack.import_uncomp_sz;
        usize eff_bias = bias + (usize)p3_pack.pack_shift;
        u64 r_off = 0;
        for (u64 idx = 0; idx < p3_pack.import_count; ++idx) {
            u64 flags_s = read_uleb(&cur, end);
            r_off += read_uleb(&cur, end);
            long long val_or_add = read_sleb(&cur, end);
            if (flags_s & 1u) {
                /* SYM_INTERNAL: defined inside the packed library itself */
                *(u64 *)(eff_bias + (usize)r_off) = (u64)(eff_bias + (usize)val_or_add);
            } else {
                const char *sym_name = (const char *)cur;
                while (cur < end && *cur) ++cur;
                if (cur < end) ++cur;
                if (!dl_checked) {
                    dl_checked = 1;
                    find_libdl_resolvers(&fn_dlsym, &fn_dlopen);
                    if (fn_dlopen && nlen > 0u) {
                        usize np = 0;
                        while (np < nlen && n_handles < 32u) {
                            const char *libn = (const char *)(nbuf + np);
                            while (np < nlen && nbuf[np]) ++np;
                            ++np;
                            if (libn[0]) {
                                void *h = fn_dlopen(libn, 4 | 2); /* RTLD_NOLOAD | RTLD_NOW */
                                if (h) needed_handles[n_handles++] = h;
                            }
                        }
                    }
                }
                void *resolved = 0;
                if (fn_dlsym) {
                    resolved = fn_dlsym((void *)0 /* RTLD_DEFAULT */, sym_name);
                    for (u32 hi = 0; !resolved && hi < n_handles; ++hi)
                        resolved = fn_dlsym(needed_handles[hi], sym_name);
                }
                if (!resolved) {
                    if (flags_s & 2u) {
                        *(u64 *)(eff_bias + (usize)r_off) = 0ULL;
                    } else {
                        wipe_buf(nbuf, sizeof(nbuf));
                        wipe_buf(ibuf, map_sz);
                        sys6(P3_SYS(215), (long)tmp, (long)map_sz, 0, 0, 0, 0);
                        wipe_buf(key, sizeof(key));
                        die_id(177, P3S_ERR_PACK_SYM);
                    }
                } else {
                    *(u64 *)(eff_bias + (usize)r_off) = (u64)((usize)resolved + (long long)val_or_add);
                }
            }
        }
        wipe_buf(nbuf, sizeof(nbuf));
        wipe_buf(ibuf, map_sz);
        sys6(P3_SYS(215), (long)tmp, (long)map_sz, 0, 0, 0, 0);
    }

    wipe_buf(key, sizeof(key));

    /* Restore final page permissions per segment (with cache flush for X) and re-lock RELRO */
    for (u32 i = 0; i < p3_pack.seg_count; ++i) {
        struct pack_seg sg;
        for (usize k = 0; k < sizeof(sg); ++k)
            ((u8 *)&sg)[k] = ((const volatile u8 *)&p3_pack.segs[i])[k];
        if (!sg.memsz || sg.is_relro) continue;
        usize dst = bias + (usize)sg.target_vaddr;
        if (sg.final_prot & 4u) clear_cache(dst, dst + (usize)sg.memsz);
        usize low = dst & ~(page - 1u);
        usize high = (dst + (usize)sg.memsz + page - 1u) & ~(page - 1u);
        /* Note: if page is shared with rw_data_min on 16K devices, keep final_prot RW if sg is RX? No, RX precedes RW by segment gap. */
        if (sys6(P3_SYS(226), (long)low, (long)(high - low), (long)sg.final_prot, 0, 0, 0))
            die_id(176, P3S_ERR_MPROT_REST);
    }
    if (p3_pack.relro_size > 0u) {
        usize rel_start = bias + (usize)p3_pack.relro_vaddr;
        usize rel_low = rel_start & ~(page - 1u);
        usize rel_high = (rel_start + (usize)p3_pack.relro_size + page - 1u) & ~(page - 1u);
        if (p3_pack.rw_data_min) {
            usize data_page = (bias + (usize)p3_pack.rw_data_min) & ~(page - 1u);
            if (rel_high > data_page) rel_high = data_page;
        }
        if (rel_high > rel_low) {
            if (sys6(P3_SYS(226), (long)rel_low, (long)(rel_high - rel_low), 1 /* PROT_READ */, 0, 0, 0))
                die_id(176, P3S_ERR_MPROT_REST);
        }
    }

    /* Anti-Dump: discard & PROT_NONE lock the compressed LOAD_PACK container so dumpers cannot recover it from RAM */
    if (p3_pack.blob_size > 0u) {
        usize pk_low = (bias + (usize)p3_pack.blob_vaddr) & ~(page - 1u);
        usize pk_high = (bias + (usize)p3_pack.blob_vaddr + (usize)p3_pack.blob_size + page - 1u) & ~(page - 1u);
        if (pk_high > pk_low) {
            sys6(P3_SYS(233), (long)pk_low, (long)(pk_high - pk_low), 4 /* MADV_DONTNEED */, 0, 0, 0);
            sys6(P3_SYS(226), (long)pk_low, (long)(pk_high - pk_low), 0 /* PROT_NONE */, 0, 0, 0);
        }
    }

    event_id(P3S_EV_PACK_OK);
    if (p3_pack.orig_dt_init) {
        typedef void (*constructor)(int, char **, char **);
        event_id(P3S_EV_INIT_BEG);
        ((constructor)(bias + (usize)p3_pack.pack_shift + (usize)p3_pack.orig_dt_init))(argc, argv, envp);
        event_id(P3S_EV_INIT_RET);
    }
    event_id(P3S_EV_GUARD_RET);
}

/* Assembly bridges for VM entry, runtime gate, and call forwarding. */
__asm__(
    ".section .text.p3_bridges, \"ax\", @progbits\n"
    ".balign 16\n"
    ".global p3_vm_call_trampoline\n"
    ".hidden p3_vm_call_trampoline\n"
    ".type p3_vm_call_trampoline, %function\n"
    "p3_vm_call_trampoline:\n"
    "hint #34\n"
    "sub sp, sp, #160\n"
    "stp x29, x30, [sp, #128]\n"
    "str x1, [sp, #144]\n"
    "mov x16, x0\n"
    "mov x17, x1\n"
    "cbz x2, 2f\n"
    "ldr x9, [x17, #248]\n"
    "mov x10, sp\n"
    "1:\n"
    "ldp x11, x12, [x9], #16\n"
    "stp x11, x12, [x10], #16\n"
    "subs x2, x2, #16\n"
    "b.hi 1b\n"
    "2:\n"
    "ldp x0, x1, [x17, #0]\n"
    "ldp x2, x3, [x17, #16]\n"
    "ldp x4, x5, [x17, #32]\n"
    "ldp x6, x7, [x17, #48]\n"
    "ldr x8, [x17, #64]\n"
    "blr x16\n"
    "ldr x17, [sp, #144]\n"
    "stp x0, x1, [x17, #0]\n"
    "ldp x29, x30, [sp, #128]\n"
    "add sp, sp, #160\n"
    "ret\n"

    ".balign 16\n"
    ".global p3_vm_bridge\n"
    ".hidden p3_vm_bridge\n"
    ".type p3_vm_bridge, %function\n"
    "p3_vm_bridge:\n"
    "hint #34\n"
    "sub sp, sp, #256\n"
    "stp x0, x1, [sp, #0]\n"
    "stp x2, x3, [sp, #16]\n"
    "stp x4, x5, [sp, #32]\n"
    "stp x6, x7, [sp, #48]\n"
    "stp x8, x9, [sp, #64]\n"
    "stp x10, x11, [sp, #80]\n"
    "stp x12, x13, [sp, #96]\n"
    "stp x14, x15, [sp, #112]\n"
    "stp x16, x17, [sp, #128]\n"
    "stp x18, x19, [sp, #144]\n"
    "stp x20, x21, [sp, #160]\n"
    "stp x22, x23, [sp, #176]\n"
    "stp x24, x25, [sp, #192]\n"
    "stp x26, x27, [sp, #208]\n"
    "stp x28, x29, [sp, #224]\n"
    "str x30, [sp, #240]\n"
    "mov x0, x16\n"
    "mov x1, sp\n"
    "bl p3_vm_exec\n"
    "ldp x0, x1, [sp, #0]\n"
    "ldp x2, x3, [sp, #16]\n"
    "ldp x4, x5, [sp, #32]\n"
    "ldp x6, x7, [sp, #48]\n"
    "ldp x8, x9, [sp, #64]\n"
    "ldp x18, x19, [sp, #144]\n"
    "ldp x20, x21, [sp, #160]\n"
    "ldp x22, x23, [sp, #176]\n"
    "ldp x24, x25, [sp, #192]\n"
    "ldp x26, x27, [sp, #208]\n"
    "ldp x28, x29, [sp, #224]\n"
    "ldr x30, [sp, #240]\n"
    "add sp, sp, #256\n"
    "ret\n"

    ".balign 16\n"
    ".global p3_gate_bridge\n"
    ".hidden p3_gate_bridge\n"
    ".type p3_gate_bridge, %function\n"
    "p3_gate_bridge:\n"
    "hint #34\n"
    "sub sp, sp, #176\n"
    "stp x0, x1, [sp, #0]\n"
    "stp x2, x3, [sp, #16]\n"
    "stp x4, x5, [sp, #32]\n"
    "stp x6, x7, [sp, #48]\n"
    "stp x8, x9, [sp, #64]\n"
    "stp x10, x11, [sp, #80]\n"
    "stp x12, x13, [sp, #96]\n"
    "stp x14, x15, [sp, #112]\n"
    "stp x16, x17, [sp, #128]\n"
    "stp x18, x29, [sp, #144]\n"
    "mrs x15, nzcv\n"
    "stp x15, x30, [sp, #160]\n"
    "mov x0, x16\n"
    "bl p3_runtime_check\n"
    "ldp x15, x30, [sp, #160]\n"
    "msr nzcv, x15\n"
    "ldp x0, x1, [sp, #0]\n"
    "ldp x2, x3, [sp, #16]\n"
    "ldp x4, x5, [sp, #32]\n"
    "ldp x6, x7, [sp, #48]\n"
    "ldp x8, x9, [sp, #64]\n"
    "ldp x10, x11, [sp, #80]\n"
    "ldp x12, x13, [sp, #96]\n"
    "ldp x14, x15, [sp, #112]\n"
    "ldp x16, x17, [sp, #128]\n"
    "ldp x18, x29, [sp, #144]\n"
    "add sp, sp, #176\n"
    "ret\n"
);

__attribute__((visibility("hidden"), section(".text.p3_entry")))
void p3_entry(int argc,char **argv,char **envp) {
    u32 flags=p3_config.flags,count=p3_config.count;
    if(p3_config.version!=2||count>32||!count)
        die_id(177, P3S_ERR_CFG_INV);
    usize bias=(usize)&p3_config-(usize)p3_config.self_vaddr;
    event_id(P3S_EV_GUARD_START);
    verify_manifest_and_self(bias);
    run_env_and_security_probes(flags);
    if(flags&ENCRYPT) {
        event_id(P3S_EV_TEXT_DEC_BEG);
        decrypt_range(bias+(usize)p3_config.text_vaddr,(usize)p3_config.text_size,5,0);
        event_id(P3S_EV_TEXT_DEC_OK);
    }
    if(flags&ENCRYPT_RODATA) {
        event_id(P3S_EV_RO_DEC_BEG);
        unsigned prot=p3_config.rodata_prot;
        if(prot!=1&&prot!=5)die_id(177, P3S_ERR_RO_PROT);
        decrypt_range(bias+(usize)p3_config.rodata_vaddr,(usize)p3_config.rodata_size,prot,1);
        u8 actual[32];unsigned difference=0;
        p3_sha256((const u8 *)(bias+(usize)p3_config.rodata_vaddr),(usize)p3_config.rodata_size,actual);
        for(unsigned j=0;j<32;++j)difference|=actual[j]^p3_config.rodata_digest[j];
        if(difference)die_id(175, P3S_ERR_RO_MIS);
        event_id(P3S_EV_RO_DEC_OK);
    }
    decrypt_sparse_data(bias);
    if (p3_ext.ext_version == 3 && p3_ext.enc_range_count > 0) {
        if (p3_ext.enc_range_count > P3_MAX_ENC_RANGES) die_id(177, P3S_ERR_MULTI_CNT);
        for (u32 i = 0; i < p3_ext.enc_range_count; ++i) {
            struct enc_range r;
            for (usize k = 0; k < sizeof(r); ++k)
                ((u8 *)&r)[k] = ((const volatile u8 *)&p3_ext.enc_ranges[i])[k];
            usize rstart = bias + (usize)r.vaddr;
            if (r.flags & (RANGE_FLAG_ON_DEMAND | RANGE_FLAG_CANARY)) continue;
            if (r.flags & RANGE_FLAG_AUTH) {
                verify_cipher_mac(rstart, (usize)r.size, r.nonce, r.cipher_mac);
            }
            decrypt_custom_range(rstart, (usize)r.size, r.prot, r.nonce, r.counter);
            u8 actual[32];
            unsigned diff = 0;
            p3_sha256((const u8 *)rstart, (usize)r.size, actual);
            for (unsigned j = 0; j < 32; ++j) diff |= actual[j] ^ r.plain_digest[j];
            if (diff) die_id(175, P3S_ERR_RNG_MIS);
        }
        event_id(P3S_EV_MULTI_OK);
    }
    if(flags&(INTEGRITY|ENCRYPT)) {
        for(u32 i=0;i<count;++i) {
            u8 actual[32];unsigned difference=0;
            usize address=bias+(usize)p3_config.spans[i].vaddr;
            p3_sha256((const u8 *)address,(usize)p3_config.spans[i].size,actual);
            for(unsigned j=0;j<32;++j)difference|=actual[j]^p3_config.spans[i].digest[j];
            if(difference)die_id(175, P3S_ERR_CODE_MIS);
        }
    }
    verify_prologues_got_relro(bias);
    init_honeypot_rw_and_state(bias);
    verify_canary_and_anti_gg(bias, 0, 1);
    event_id(P3S_EV_INT_DONE);
    if(p3_config.original_init) {
        typedef void (*constructor)(int,char **,char **);
        event_id(P3S_EV_INIT_BEG);
        ((constructor)(bias+(usize)p3_config.original_init))(argc,argv,envp);
        event_id(P3S_EV_INIT_RET);
    }
    event_id(P3S_EV_GUARD_RET);
}
