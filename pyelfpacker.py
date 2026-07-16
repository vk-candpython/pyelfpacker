#=================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 17.07.2026
#     PROJECT  : PY-ELF-PACKER
#     PLATFORM : LIN64
#=================================#




import sys


if not sys.platform.startswith('linux'):
    raise SystemError(f'OS NOT SUPPORTED ({sys.platform})')




import gc
import os
import mmap
import shutil
import secrets as rand

from subprocess import run as sp_run
from platform   import machine
from time       import time




mem   = memoryview
array = bytearray

_argv = set(sys.argv[1 :])




# Supported feature switches
_ELFLDR_FLAGS = (
    '--help',
    '--obf',
    '--debug',
    '--vm'
)

# Parse active flags from CLI arguments
FLAG_HELP  : bool = _ELFLDR_FLAGS[0] in _argv
FLAG_OBF   : bool = _ELFLDR_FLAGS[1] in _argv
FLAG_DEBUG : bool = _ELFLDR_FLAGS[2] in _argv
FLAG_VM    : bool = _ELFLDR_FLAGS[3] in _argv


for f in _ELFLDR_FLAGS: _argv.discard(f)
del f,   _ELFLDR_FLAGS




PATH_DIR      : bytes = b'./_mk_pyelfpacker-%x' % int(time())

PATH_LINK_LD  : bytes = PATH_DIR + b'/link.ld'
PATH_PAYLOAD  : bytes = PATH_DIR + b'/payload.bin'
PATH_LOADER_C : bytes = PATH_DIR + b'/loader.c'
PATH_ELFSTRIP : bytes = PATH_DIR + b'/elfstrip'

PATH_OUTPUT   : bytes = b'./pyelfpacker-%b'
PATH_LABEL    : bytes = b'/*--GENERATED_BY_PYELFPACKER_FOR_FILE(%b)--*/'




CHUNK : int = os.sysconf('SC_PAGE_SIZE')

KSZ   : tuple[int] = (16, 32, 64, 128) # (n % 2) == 0
X64   : tuple[mem] = (mem(b'x86_64'), mem(b'x64'), mem(b'amd64'))

FZLIM : int = 4 << 30
MELF  : mem = mem(b'\x7FELF\x02')

FBADR : int = 0x400000 # Base download address
FL_RE : int = 5        # Flag R+E for linker
FL_RW : int = 6        # Flag R+W for linker

PST   : mem = mem(b'/proc/self/status')




MUSL : bytes = shutil.which(b'musl-gcc') # or None
GCC  : bytes = shutil.which(b'gcc')      # or None


CC    : bytes = MUSL or GCC              # or None
PARAM : tuple[bytes] = (
    b'-m64',
    b'-mtune=generic',

    b'-Wl,-z,noseparate-code',
    b'-Wl,-z,noexecstack',

    b'-nostdlib',
    b'-fno-builtin',
    b'-ffreestanding',
    b'-static-pie',

    b'-O3',
    b'-Wl,-O3',
    b'-flto',
    b'-flto-partition=one',
    b'-fipa-pta',
    b'-fstrict-aliasing',
    b'-fomit-frame-pointer',

    b'-Wl,--gc-sections',
    b'-fdata-sections',
    b'-fmerge-all-constants',
    b'-ffunction-sections',
    b'-fno-keep-static-consts',
    b'-fno-keep-inline-functions',

    b'-fvisibility=hidden',
    b'-fno-semantic-interposition',
    b'-fno-plt',
    b'-fno-gnu-unique',
    b'-fno-common',

    b'-fno-stack-check',
    b'-fno-stack-protector',
    b'-fno-stack-clash-protection',

    b'-fno-unwind-tables',
    b'-fno-asynchronous-unwind-tables',
    b'-Wl,--no-eh-frame-hdr',

    b'-Wl,--build-id=none',
    b'-fno-ident',
    b'-g0',
    b'-s',
)




MSG: dict[bytes, bytes] = {
    b'prev' : (
        b'\nerror: no input files'
        b'\nshow more details "--help"\n'
    ),
    b'info' : (
        b'\n(C) Vladislav Khudash, 2026'
        b'\n(P) GitHub: https://github.com/vk-candpython/pyelfpacker'
        b'\n(!) Only for x64 Linux\n\n'

        b'\n(Usage): python%d %b <elf1> [elf2 ...]\n\n'

        b'\n(Flags):\n'
        b'  --help   ->  Show help menu\n'
        b'  --obf    ->  Enable polymorphic obfuscation\n'
        b'  --debug  ->  Enable anti-debug\n'
        b'  --vm     ->  Enable anti-vm\n'

        b'\n\n(Features):\n'
        b'  - RLE compression\n'
        b'  - XOR stream cipher\n'
        b'  - Polymorphic stub generation\n'
        b'  - Fileless execution\n'
        b'  - Protection & Anti-Debug & Anti-VM\n'
        b'  - Extreme strip ELF metadata\n'
        b'  - Polyglot signatures\n'
    ),


    b'valid_arch'    : b'[  OK  ]: architecture is valid (%b)',
    b'fail_arch'     : b'[ FAIL ]: target architecture must be (x64)  |  found: (%b)',


    b'use_compiler'  : b'[  OK  ]: using compiler(%b)',
    b'fail_compiler' : b'[ FAIL ]: no suitable compiler found (tried: %b)',
    b'use_flag'      : b'[  OK  ]: using flag(%b)',

    b'sproc'         : b'[ INFO ]: Start processing -> %s\n',
    b'eproc'         : b'\n[ INFO ]: End processing -> %s',
    b'start'         : b'[ INFO ]: building ELF(%b)',
    b'out'           : b'[  OK  ]: outfile(%b, %d bytes)',
    b'end'           : b'[  OK  ]: building completed ELF(%b)',


    b'fail_open'     : b'[ FAIL ]: cannot open file(%b)',
    b'fail_sz'       : b'[ FAIL ]: ELF(%b) size is larger limit(%d GiB)',
    b'fail_mmap'     : b'[ FAIL ]: mmap failed for file(%b)',
    b'is_not_elf'    : b'[ FAIL ]: file(%b) is not ELF(x64)',


    b'ok_dir'        : b'[  OK  ]: make build dir(%b)',
    b'ok_file'       : b'[ BUILD ]: file(%b)',
    b'ok_cleanup'    : b'[  OK  ]: cleanup build dir(%b)',
    b'fail_cleanup'  : b'[ FAIL ]: failed to cleanup build dir(%b)',


    b'fail_dir'      : b'[ FAIL ]: failed to make dir(./%b)',
    b'fail_file'     : b'[ FAIL ]: failed to make file(./%b)',


    b'bar_compress'  : b'[ INFO ]: compressing:',
    b'bar_enc'       : b'[ INFO ]: encrypting: ',
    b'bar_done'      : b'  (DONE)',


    b'compress'      : b'[  OK  ]: compressed:  (%d -> %d) bytes  |  saved: %d bytes (%.1f%%)',
    b'compile'       : b'[  OK  ]: compiled  .................',
    b'fail_compile'  : b'[ FAIL ]: compilation failed (exit code: %d)',
    b'strip_payload' : b'[  OK  ]: stripped payload ELF  |  (%d -> %d) bytes  &  saved: %d bytes (%.1f%%)',
    b'elfstrip'      : b'[  OK  ]: stripped  .................',
    b'time'          : b'[ INFO ]: time      .................  (%.2fs)',


    b'error'         : b'\n[ ERROR ]: %b(%b)'
}



if FLAG_OBF: SIGN: tuple[mem] = (
    mem(b''),

    mem(
b'''
        o = .;
        BYTE(0x6F); BYTE(0x0D); BYTE(0x0D);
                    BYTE(0x0A);

        LONG(1);    QUAD(0);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x7F); BYTE(0x45); BYTE(0x4C);
        BYTE(0x46); BYTE(0x02); BYTE(0x01);
            BYTE(0x01); BYTE(0x00);

        QUAD(0);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        SHORT(0x5A4D);

        . = o + 60;
        LONG(0x00000080); LONG(0x00004550);

        BYTE(0x0E); BYTE(0x1F); BYTE(0xBA);
        BYTE(0x0E); BYTE(0x00); BYTE(0xB4);
        BYTE(0x09); BYTE(0xCD); BYTE(0x21);
        BYTE(0xB8); BYTE(0x01); BYTE(0x4C);
                BYTE(0xCD); BYTE(0x21);

        . = ALIGN(8);
        BYTE(0x54); BYTE(0x68); BYTE(0x69);
        BYTE(0x73); BYTE(0x20); BYTE(0x70);
        BYTE(0x72); BYTE(0x6F); BYTE(0x67);
        BYTE(0x72); BYTE(0x61); BYTE(0x6D);
        BYTE(0x20); BYTE(0x63); BYTE(0x61);
        BYTE(0x6E); BYTE(0x6E); BYTE(0x6F);
        BYTE(0x74); BYTE(0x20); BYTE(0x62);
        BYTE(0x65); BYTE(0x20); BYTE(0x72);
        BYTE(0x75); BYTE(0x6E); BYTE(0x20);
        BYTE(0x69); BYTE(0x6E); BYTE(0x20);
        BYTE(0x44); BYTE(0x4F); BYTE(0x53);
        BYTE(0x20); BYTE(0x6D); BYTE(0x6F);
        BYTE(0x64); BYTE(0x65); BYTE(0x2E);
        BYTE(0x0D); BYTE(0x0D); BYTE(0x0A);
        BYTE(0x24); BYTE(0x00); BYTE(0x00);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0xFE); BYTE(0xED); BYTE(0xFA);
        BYTE(0xCE); BYTE(0x01); BYTE(0x00);
            BYTE(0x00); BYTE(0x01);

        QUAD(0);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x21); BYTE(0x3C); BYTE(0x61);
        BYTE(0x72); BYTE(0x63); BYTE(0x68);
            BYTE(0x3E); BYTE(0x0A);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        LONG(0xBEBAFECA);

        SHORT(0); SHORT(55);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x23); BYTE(0x21); BYTE(0x2F);
        BYTE(0x62); BYTE(0x69); BYTE(0x6E);
        BYTE(0x2F); BYTE(0x62); BYTE(0x61);
        BYTE(0x73); BYTE(0x68); BYTE(0x0A);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(b'''
        o = .;
        BYTE(0x55); BYTE(0x50); BYTE(0x58);
                    BYTE(0x21);

        LONG(0x0000000D); LONG(0x00000000);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0xFD); BYTE(0x37); BYTE(0x7A);
        BYTE(0x58); BYTE(0x5A); BYTE(0x00);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        LONG(0xFD2FB528);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x50); BYTE(0x4B); BYTE(0x03);
                    BYTE(0x04);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x1F); BYTE(0x8B); BYTE(0x08);
                    BYTE(0x00);

        LONG(0);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x37); BYTE(0x7A); BYTE(0xBC);
        BYTE(0xAF); BYTE(0x27); BYTE(0x1C);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x42); BYTE(0x4D);

        LONG(0);    LONG(0);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(b'''
        o = .;
        BYTE(0x89); BYTE(0x50); BYTE(0x4E);
        BYTE(0x47); BYTE(0x0D); BYTE(0x0A);
            BYTE(0x1A); BYTE(0x0A);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0xFF); BYTE(0xD8); BYTE(0xFF);
                    BYTE(0xE0);

        SHORT(0);

        BYTE(0x4A); BYTE(0x46); BYTE(0x49);
            BYTE(0x46); BYTE(0x00);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x49); BYTE(0x44); BYTE(0x33);
        BYTE(0x03); BYTE(0x00); BYTE(0x00);

        QUAD(0);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        LONG(0x00000018);

        BYTE(0x66); BYTE(0x74); BYTE(0x79);
        BYTE(0x70); BYTE(0x69); BYTE(0x73);
            BYTE(0x6F); BYTE(0x6D);

        LONG(0x00000200);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x25); BYTE(0x50); BYTE(0x44);
        BYTE(0x46); BYTE(0x2D); BYTE(0x31);
        BYTE(0x2E); BYTE(0x37); BYTE(0x0A);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x3C); BYTE(0x3F); BYTE(0x78);
        BYTE(0x6D); BYTE(0x6C); BYTE(0x20);
        BYTE(0x76); BYTE(0x65); BYTE(0x72);
        BYTE(0x73); BYTE(0x69); BYTE(0x6F);
        BYTE(0x6E); BYTE(0x3D); BYTE(0x22);
        BYTE(0x31); BYTE(0x2E); BYTE(0x30);
        BYTE(0x22); BYTE(0x3F); BYTE(0x3E);
                    BYTE(0x0A);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x3C); BYTE(0x21); BYTE(0x44);
        BYTE(0x4F); BYTE(0x43); BYTE(0x54);
        BYTE(0x59); BYTE(0x50); BYTE(0x45);
        BYTE(0x20); BYTE(0x68); BYTE(0x74);
        BYTE(0x6D); BYTE(0x6C); BYTE(0x3E);
                    BYTE(0x0A);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x53); BYTE(0x51); BYTE(0x4C);
        BYTE(0x69); BYTE(0x74); BYTE(0x65);
        BYTE(0x20); BYTE(0x66); BYTE(0x6F);
        BYTE(0x72); BYTE(0x6D); BYTE(0x61);
        BYTE(0x74); BYTE(0x20); BYTE(0x33);
                    BYTE(0x00);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0xD0); BYTE(0xCF); BYTE(0x11);
        BYTE(0xE0); BYTE(0xA1); BYTE(0xB1);
            BYTE(0x1A); BYTE(0xE1);

        QUAD(0);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x00); BYTE(0x01); BYTE(0x00);
        BYTE(0x00); BYTE(0x00); BYTE(0x0D);
            BYTE(0x00); BYTE(0x80);

        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x00); BYTE(0x61); BYTE(0x73);
        BYTE(0x6D); BYTE(0x01); BYTE(0x00);
            BYTE(0x00); BYTE(0x00);

        QUAD(0);
        . = ALIGN(16);
        c = .;
\n'''
    ),

    mem(
b'''
        o = .;
        BYTE(0x99); BYTE(0x01);

        SHORT(0);   QUAD(0);
        . = ALIGN(16);
        c = .;
\n'''
    )
)



EXIT: tuple[mem] = (
    mem(b'SYSCALL(SYS_MPROTECT, &argc, CHUNK, 1, NULL, NULL, NULL); *(int*)NULL = NULL;'),
    mem(b'SYSCALL(SYS_READ, &envp, argv, (long)&argc & 0xFFFFF, NULL, NULL, NULL); __asm__ volatile ("ud2");'),
    mem(b'SYSCALL(SYS_OPENAT, AT_FDCWD, "/dev/null", &argc, NULL, NULL, NULL); __asm__ volatile ("int3"); EXIT();'),
    mem(b'while (1) __asm__ volatile ("pause"); EXIT();'),
    mem(b'EXIT();')
)



if FLAG_OBF:
    JKFCAL: tuple[mem] = (
        mem(b'"\\n"'),
        mem(b'"call main\\n"'),
        mem(b'"call _start\\n"')
    )


    JUNK: tuple[mem] = [
        mem(b''),

        mem(b'nop'),
        mem(b'rep nop'),
        mem(b'nop\\n\\tnop'),
        mem(b'nop\\n\\tnop\\n\\tnop'),

        mem(b'fnop'),
        mem(b'fnop\\n\\tfnop'),
        mem(b'fnop\\n\\tfnop\\n\\tfnop'),

        mem(b'wait'),
        mem(b'wait\\n\\twait'),
        mem(b'wait\\n\\twait\\n\\twait'),

        mem(b'pause'),
        mem(b'pause\\n\\tpause'),
        mem(b'pause\\n\\tpause\\n\\tpause'),

        mem(b'cld'),
        mem(b'std\\n\\tcld'),

        mem(b'clc'),
        mem(b'stc\\n\\tclc'),

        mem(b'pushfq\\n\\tpopfq'),

        mem(b'mfence'),
        mem(b'lfence'),
        mem(b'mfence\\n\\tlfence'),
        mem(b'lfence\\n\\tmfence'),

        mem(b'endbr64')
    ]


    _tmp = (
        b'nopl (%b)',
        b'nopl 0x00(%b, %b, 1)',

        b'or   %b, %b',
        b'and  %b, %b',
        b'not  %b\\n\\tnot %b',
        b'neg  %b\\n\\tneg %b',
        b'test %b, %b',

        b'bt   $0, %b',
        b'btc  $0, %b\\n\\tbtc $0, %b',
        b'add  $0, %b',
        b'sub  $0, %b',
        b'shl  $0, %b',
        b'shr  $0, %b',
        b'shld $0, %b, %b',
        b'shrd $0, %b, %b',
        b'sar  $0, %b',
        b'sal  $0, %b',
        b'rol  $0, %b',
        b'ror  $0, %b',

        b'mov %b,    %b',
        b'push %b\\n\\tpop %b',
        b'lea (%b),  %b',
        b'lea 0(%b), %b',
        b'lea 0x0(,  %b, 1), %b',

        b'xchg  %b, %b',
        b'bswap %b\\n\\tbswap %b',

        b'cmovz  %b, %b',
        b'cmovnz %b, %b',
        b'cmovc  %b, %b',
        b'cmovnc %b, %b',
        b'cmovo  %b, %b',
        b'cmovno %b, %b',
        b'cmovs  %b, %b',
        b'cmovns %b, %b',
        b'cmovpe %b, %b',
        b'cmovpo %b, %b',
        b'cmovb  %b, %b',
        b'cmovae %b, %b',
        b'cmovbe %b, %b',
        b'cmova  %b, %b',
        b'cmovge %b, %b',
        b'cmovle %b, %b',

        b'prefetcht0 (%b)',
        b'prefetcht1 (%b)',
        b'prefetcht2 (%b)',
        b'prefetchw  (%b)'
    )


    _regs = (
        b'%%rax',    b'%%rbx',    b'%%rcx',
        b'%%rdx',    b'%%rsi',    b'%%rdi',
        b'%%r8',     b'%%r9',     b'%%r10',
                     b'%%r11'
    )


    _b = b'%b'

    JUNK += (
        mem(f.replace(_b, r))
            for r in _regs
                for f in _tmp
    )


    del _tmp, _regs, _b
    JUNK = tuple(JUNK)
else:
    JKFCAL = ( mem(b'"\\n"'), )
    JUNK   = ( mem(b''),      )



color = type(
    'color', (),
    {
        '__slots__' : (),
        '__call__'  : lambda t, c, b: (
            t._ch.get(b.__hash__()) or
            t._ch.setdefault(b.__hash__(),
                mem(getattr(
                    t,
                    c if t._ty else 'white'
                )(b))
            )
        ),


        '_ch' : {},
        '_ty' : sys.stdout.isatty(),


        sys.intern('white')  : b'%b\n'.__mod__,
        sys.intern('green')  : b'\033[92m%b\033[0m\n'.__mod__,
        sys.intern('yellow') : b'\033[93m%b\033[0m\n'.__mod__,
        sys.intern('red')    : b'\033[91m%b\033[0m\n'.__mod__,
        sys.intern('bar')    : b'\r\033[93m%b\033[0m'.__mod__
    }
)()




def log(
    msg : mem,
    err : bool=False,
    *,
    _out=sys.stdout.buffer,
    _err=sys.stderr.buffer
) -> None:
    o = _err if err else _out
    o.write(msg)
    o.flush()




def logbar(
    txt : mem,
    cur : int,
    tol : int,
    *,
    _el=mem(b'-' * 20),
    _fm=b'%b {%-20b} %3d%%'.__mod__,
    _mm=mem,
    _cl=color,
    _lg=log,
    _ch=[None]
) -> None:
    p = (cur * 20) // tol

    if p == _ch[0]:
        return


    _ch[0] = p
    b      = _el[0 : p]

    _lg(_cl('bar', _mm(
        _fm((txt, b, p * 5))
    )))




def gen_chars(
    *,
    _b=rand.randbelow,
    _g=rand.choice,
    _c=mem(b'0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'),
    _s=[None]
) -> mem:
    l = 4 + _b(250)
    b = array(l)
    p = mem(b)


    if _s[0] is None:
        _s[0] = _c[10 :] # start with '_'


    while l:
        l -= 1
        p[l] = _g(_c)

    p[0] = _g(_s[0])


    return p




def gen_junk(
    cmd : bool=False,
    prc : bool=False,
    *,
    _em=mem(b''),
    _sp=b'\\n\\t'.join,
    _f0=b'"%b\\n"'.__mod__,
    _f1=b'__asm__ volatile ("%b");'.__mod__,
    _a=JUNK,
    _b=tuple(mem(j.tobytes().replace(b'%%', b'%'))
             for j in JUNK)
    ,
    _r=rand.randbelow,
    _c=rand.choice
) -> mem:
    if not FLAG_OBF:
        return mem((_f0 if cmd else _f1)(_em))


    n = 1 + _r(10)

    return mem(
        (_f0 if cmd else _f1)(_sp(
            map(_c, [_b if prc else _a] * n)
        ))
    )




def compress(
    dt  : mmap.mmap,
    dln : int,
    out : mem,
    *,
    _q=MSG[b'bar_compress'],
    _b=logbar
) -> mem:
    _g = dt.__getitem__
    _t = out.__setitem__


    i = j = 0

    while i < dln:
        if not (i & 0x3FFF):
            _b(_q, i, dln)


        r = 1
        c = _g(i)


        u = 127 if (dln - i) > 127 else dln - i
        while (r < u) and (_g(i + r) == c): r += 1


        if r >= 3:
            _t(j,     0x80 | r)
            _t(j + 1, c       )

            j += 2
            i += r
        else:
            s = i
            u = dln if dln < (s + 126) else s + 126

            while (i < u) and not (
                ((i + 2) < dln) and (_g(i) == _g(i + 1) == _g(i + 2))
            ): i += 1


            l = i - s

            if l:
                _t(j, l)
                j += 1

                out[j : j + l] = dt[s : i]
                j += l



    _b(_q, dln, dln)
    log(color('green', MSG[b'bar_done']))

    return out[0 : j]




def enc(
    dt   : mem,
    key  : mem,
    salt : int,
    *,
    _rep=False,
    _q=MSG[b'bar_enc'],
    _b=logbar
) -> mem:
    sz = len(dt)
    kl = len(key)
    mk = kl - 1


    if _rep:
        out = dt
    else:
        buf = array(sz)
        out = mem(buf)


    _g = dt.__getitem__
    _v = key.__getitem__
    _t = out.__setitem__


    i = salt & 0xFF

    for j in range(sz):
        if _rep and not (j & 0x3FFF):
            _b(_q, j, sz)


        k = _v( (j + i) & mk )

        y = ( k     ^ (j & 0xFF) ^ (j >> 8) ) & 0xFF
        x = ( _g(j) ^ y          ^ i        ) & 0xFF

        x = ( (x << 3) | (x >> 5) ) & 0xFF
        x = ( x + (y ^ 0xA5)      ) & 0xFF


        _t(j, x)
        i = ( x ^ ((y << 1) & 0xFF) ^ (i >> 1) ) & 0xFF


    if _rep:
        _b(_q, sz, sz)
        log(color('green', MSG[b'bar_done']))


    return out




def writef(fp: bytes, dt: mem, *, _ck=CHUNK) -> bool:
    sz = len(dt)
    fd = -1

    try:
        fd = os.open(fp, os.O_RDWR|os.O_CREAT|os.O_TRUNC, 0o644)
        os.ftruncate(fd, sz)


        with mmap.mmap(
            fd, sz,
            prot=mmap.PROT_WRITE, flags=mmap.MAP_SHARED
        ) as mp:
            mp.madvise(mmap.MADV_SEQUENTIAL)

            for i in range(0, sz, _ck):
                e = i + _ck if (i + _ck) < sz else sz
                mp[i : e] = dt[i : e]

            mp.flush()


        return True
    except OSError:
        return False

    finally:
        if fd != -1:
            os.fsync(fd)
            os.close(fd)




def make_link_ld(
            fp : bytes,
    entry : mem,    section : mem
) -> bool:
    if not FLAG_OBF:
        return writef(
            PATH_LINK_LD,
            mem(
b'''%b\n\n\n\n
ENTRY(%b)
PHDRS{
    sload PT_LOAD FILEHDR PHDRS FLAGS(%d); /* R+E */
    stack PT_GNU_STACK          FLAGS(%d); /* R+W */
}
SECTIONS{
    . = SIZEOF_HEADERS;

    ._ : {
        *(.rodata*)
        *(.text*  )
    }:sload

    /DISCARD/ : { *(*) }
}
''' % (PATH_LABEL % fp, entry, FL_RE, FL_RW))
        )



    script = array()
    addr   = FBADR + (rand.randbelow(256) * CHUNK)


    script.extend(mem(
b'''%b\n\n\n\n
ENTRY(%b)
PHDRS{
    sload PT_LOAD FILEHDR PHDRS FLAGS(%d); /* R+E */
    stack PT_GNU_STACK          FLAGS(%d); /* R+W */
}
SECTIONS{
    . = 0x%X + SIZEOF_HEADERS;

    .%b : {''' % (
            PATH_LABEL % fp,
            entry,
            FL_RE,
            FL_RW,
            addr,
            section
        )
    ))
    script.extend(rand.choice(SIGN))
    script.extend(mem(
b'''
        KEEP(*(.%b))
        *(.rodata* )
        *(.text*   )
    }:sload

    /DISCARD/ : { *(*) }
}
''' % section
    ))



    ok = writef(PATH_LINK_LD, script)

    del addr, script
    return ok




def make_loader_c(
                fp  : bytes,
    entry : mem, fmain : mem, section : mem,
                pst : mem,
        key   : mem,      salt    : int,
    *,
    _gn=lambda n, p=False: (
        tuple((
                gen_junk(False, True)
            if p else
                gen_junk(True, False)
        ) for _ in range(n))
    ),
    _fm=tuple( map(b'%d'.__mod__, range(256)) ).__getitem__,
    _sp=b','.join
) -> bool:
    code = array()



    xor       = rand.randbelow(256)
    shlmf     = rand.randbelow(32)
    shlex     = rand.randbelow(32)

    _bs       = gen_chars()
    _be       = gen_chars()
    kk        = gen_chars()
    sc        = gen_chars()
    lb_main   = gen_chars()

    debugexit = rand.choice(EXIT)

    uchar_key = mem(_sp( map(_fm, key) ))
    uchar_pst = mem(_sp( map(_fm, pst) ))



    code.extend(mem(
b'''%b\n\n\n\n
#define USING_OBF              %d
#define USING_ANTIDEBUG        %d
#define USING_ANTIVM           %d
\n\n\n
#define PST                    {%b}
#define KEY                    {%b}

#define SALT                   %d
#define XOR                    %d
''' % (
            PATH_LABEL % fp,
            FLAG_OBF, FLAG_DEBUG, FLAG_VM,
            uchar_pst, uchar_key,
            salt, xor
        )
    ))

    del uchar_pst, uchar_key


    code.extend(mem(
b'''\n\n\n
#define NULL                   0
#define EINTR                  4
#define NAME                   ""
#define SIZE                   512
#define CHUNK                  %d


#define SYS_READ               0
#define SYS_WRITE              %d
#define SYS_CLOSE              3
#define SYS_LSEEK              8
#define SYS_MPROTECT           10
#define SYS_FCNTL              %d
#define SYS_MLOCKALL           %d
#define SYS_PRCTL              %d
#define SYS_EXIT_GROUP         231
#define SYS_OPENAT             257
#define SYS_MEMFD_CREATE       %d
#define SYS_EXECVEAT           %d


#define O_RDONLY               0
#define SEEK_SET               0
#define MFD_ALLOW_SEALING      2
#define MCL_ALL                3
#define PR_SET_DUMPABLE        4
#define PR_SET_NO_NEW_PRIVS    38
#define AT_FDCWD               -100
#define F_ADD_SEALS            1033
#define F_SEALS_ALL            0x3F
#define AT_EMPTY_PATH          %d
#define PR_SET_PTRACER         %d




typedef unsigned char uchar;
typedef unsigned int  uint ;




#if (USING_OBF)
    __attribute__((used)) void _start(void)                 { %b return  ; };
    __attribute__((used)) int  main(int argc, char *argv[]) { %b return 0; };
#endif
''' % (
            CHUNK,

            1          ^ xor,      # SYS_WRITE
            72         ^ salt,     # SYS_FCNTL
            151        ^ xor,      # SYS_MLOCKALL
            157        ^ salt,     # SYS_PRCTL
            (319 ^ salt) << shlmf, # SYS_MEMFD_CREATE
            (322 ^ xor ) << shlex, # SYS_EXECVEAT
            0x1000     ^ salt,     # AT_EMPTY_PATH
            0x59616D61 ^ xor,      # PR_SET_PTRACER

            gen_junk(prc=True),
            gen_junk(prc=True)
        )
    ))


    code.extend(mem(
b'''\n\n\n
__asm__ (
    ".section .%b,\\"a\\",@progbits\\n"
    ".align 16\\n"

    ".hidden %b\\n"
    ".hidden %b\\n"

    "%b:\\n"
    ".incbin \\"%b\\"\\n"
    "%b:\\n"

    ".type %b, @object\\n"
    ".size %b, . - %b \\n"
);


__attribute__(
    (used, section(".%b"), aligned(16))
) static const uchar %b[] = KEY;


static void %b(void); __asm__ (
    ".section .text\\n"

    ".hidden %b\\n"

    "%b:\\n"
    "   %b
    "   syscall\\n"
    "   %b
    "   ret\\n"
);
\n\n
''' % (
            section,

                       _bs, _be,
                _bs, PATH_PAYLOAD, _be,
                    _bs, _bs, _bs,

            section, kk, sc, sc, sc,

            gen_junk(True, True)[1 :],
            gen_junk(True, True)[1 :]
        )
    ))


    code.extend(mem(
b'''
#define SYSCALL(n, a1, a2, a3, a4, a5, a6) ({         \\
    %b                                                \\
    long _r;                                          \\
    %b                                                \\
                                                      \\
    %b                                                \\
    register long rax __asm__("rax") = (long)(n );    \\
    %b                                                \\
    register long rdi __asm__("rdi") = (long)(a1);    \\
    %b                                                \\
    register long rsi __asm__("rsi") = (long)(a2);    \\
    %b                                                \\
    register long rdx __asm__("rdx") = (long)(a3);    \\
    %b                                                \\
    register long r10 __asm__("r10") = (long)(a4);    \\
    %b                                                \\
    register long r8  __asm__("r8" ) = (long)(a5);    \\
    %b                                                \\
    register long r9  __asm__("r9" ) = (long)(a6);    \\
    %b                                                \\
                                                      \\
    %b                                                \\
    __asm__ volatile (                                \\
        "%b\\n"                                       \\
        "call %b"                                     \\
        : "=a"(_r)                                    \\
                                                      \\
        :   "0"(rax),                                 \\
            "r"(rdi),    "r"(rsi),    "r"(rdx),       \\
            "r"(r10),    "r"(r8),     "r"(r9)         \\
                                                      \\
        : "memory", "rcx", "r11"                      \\
    );                                                \\
                                                      \\
    %b                                                \\
    _r;                                               \\
})
\n\n\n''' % (
            *_gn(11, True),
            rand.choice(JUNK) if FLAG_OBF else JUNK[0],
            sc,
            gen_junk(prc=True)
        )
    ))

    del sc


    code.extend(mem(
rb'''
#define EXIT() SYSCALL(SYS_EXIT_GROUP, 0, NULL, NULL, NULL, NULL, NULL)




#define SWRITE(d, b, l) do {           \
    volatile uint _f = XOR;            \
                                       \
                                       \
    uint _w = (uint)(l);               \
    uint _p = 0;                       \
                                       \
    while (_w) {                       \
        int _r = (int)SYSCALL(         \
            SYS_WRITE^_f,              \
            (d),                       \
            (const uchar*)(b) + _p,    \
            _w,                        \
            NULL, NULL, NULL           \
        );                             \
                                       \
        if (_r <= 0) {                 \
            if (_r == -EINTR)          \
                continue;              \
                                       \
            EXIT();                    \
        }                              \
                                       \
                                       \
        _p += (uint)_r;                \
        _w -= (uint)_r;                \
    }                                  \
} while (0)




#define ZEROS(dst, sz) do {     \
    void *_d = (void*)(dst);    \
    uint  _n = (uint)(sz);      \
                                \
    __asm__ volatile (          \
        "rep stosb\n\t"         \
        : "+D"(_d), "+c"(_n)    \
        : "a"(0)                \
        : "memory"              \
    );                          \
} while (0)




#define DEC(b, j, k, m, g) ({                     \
    uchar _b = (uchar)(b),                        \
          _i = (uchar)(g),                        \
          _k = *( (k) + (((j) + _i) & (m)) ),     \
          _y = _k ^ (j) ^ ((j) >> 8),             \
          _r = _b;                                \
                                                  \
    _r -= _y ^ 0xA5;                              \
    _r  = (_r >> 3) | (_r << 5);                  \
    _r ^= _y ^ _i;                                \
    (g) = (uchar)(_b ^ (_y << 1) ^ (_i >> 1));    \
                                                  \
    _r;                                           \
})




#define ANTIVM() ({                             \
    uchar _r;                                   \
                                                \
    __asm__ __volatile__ (                      \
        "movl $1, %%eax\n\t"                    \
        "cpuid\n\t"                             \
                                                \
        "btl $31, %%ecx\n\t"                    \
        "setc %0\n\t"                           \
                                                \
        : "=r"(_r)                              \
        : : "cc", "eax", "ebx", "ecx", "edx"    \
    );                                          \
                                                \
    _r;                                         \
})
'''
    ))


    code.extend(mem(
b'''\n\n\n
#define ANTIDEBUG() ({                                                \\
    %b                                                                \\
    uchar _r;                                                         \\
    %b                                                                \\
                                                                      \\
                                                                      \\
    uchar _e[] = PST;                                                 \\
    %b                                                                \\
    uint  _l   = (uint)sizeof(_e);                                    \\
    %b                                                                \\
    char *_b   = (char*)__builtin_alloca(SIZE);                       \\
    %b                                                                \\
                                                                      \\
    {char *_p = _b;                                                   \\
    %b                                                                \\
    uint   _y = (uint)sizeof(%b) - 1;                                 \\
    %b                                                                \\
    uint   _g = SALT;                                                 \\
    %b                                                                \\
                                                                      \\
                                                                      \\
    for (uint _j = 0;  _j < _l;  _j++)                                \\
        *_p++ = (char)DEC(_e[_j], _j, %b, _y, _g);                    \\
                                                                      \\
    *_p = '\\0';                                                      \\
    %b                                                                \\
    }                                                                 \\
                                                                      \\
                                                                      \\
    int _d = (int)SYSCALL(SYS_OPENAT, AT_FDCWD, _b,    O_RDONLY,      \\
                                      NULL,     NULL,  NULL     );    \\
    %b                                                                \\
                                                                      \\
    if (_d == -1) {                                                   \\
        %b                                                            \\
        _r = 0;                                                       \\
        %b                                                            \\
        goto _ret;                                                    \\
    }                                                                 \\
                                                                      \\
                                                                      \\
    int _n = (int)SYSCALL(SYS_READ, _d,   _b,   SIZE - 1,             \\
                                    NULL, NULL, NULL     );           \\
    %b                                                                \\
                                                                      \\
    SYSCALL(SYS_CLOSE, _d, NULL, NULL, NULL, NULL, NULL);             \\
    %b                                                                \\
                                                                      \\
                                                                      \\
    if (_n < 13) {                                                    \\
        %b                                                            \\
        _r = 1;                                                       \\
        %b                                                            \\
        goto _ret;                                                    \\
    }                                                                 \\
                                                                      \\
                                                                      \\
    _b[_n] = '\\0';                                                   \\
    _n -= 13;                                                         \\
    %b                                                                \\
                                                                      \\
                                                                      \\
    volatile uchar _x = SALT,  _z = XOR;                              \\
    %b                                                                \\
                                                                      \\
                                                                      \\
    for (uint _i = 0;  _i < _n;  _i++) {                              \\
        %b                                                            \\
        if (                                                          \\
( (uchar)_b[_i] == (uchar)(%d^_z) ) && ( (uchar)_b[_i + 6] == (uchar)(%d^_x) ) && \\
                    ( (uchar)_b[_i + 9] == (uchar)(%d^_z) )           \\
        ) {                                                           \\
            %b                                                        \\
            char *_s = &_b[_i + 10];                                  \\
                                                                      \\
                                                                      \\
            while (                                                   \\
( (uchar)*_s == (uchar)(%d^_z) ) || ( (uchar)*_s == (uchar)(%d^_x) )  \\
            ) _s++;                                                   \\
                                                                      \\
                                                                      \\
            %b                                                        \\
            _r = (uchar)( (uchar)*_s ^ (uchar)(%d^_z) );              \\
            %b                                                        \\
            goto _ret;                                                \\
        }                                                             \\
    }                                                                 \\
                                                                      \\
    _r = 1;                                                           \\
                                                                      \\
                                                                      \\
    _ret:                                                             \\
        ZEROS(_e, _l  );                                              \\
        ZEROS(_b, SIZE);                                              \\
                                                                      \\
        %b                                                            \\
        _r;                                                           \\
})




__attribute__((
    leaf,                    no_stack_protector,    noipa,
    visibility("hidden"),    cold,                  flatten,
                             nothrow
)) void %b(int argc, char *argv[], char *envp[]) {
#if (USING_ANTIDEBUG)
    %b
    if (ANTIDEBUG()) { %b %b }
    %b
#endif


#if (USING_ANTIVM)
    if (ANTIVM()) { %b %b }
    %b
#endif



    volatile uint q = SALT,  _q = %d,
                  f = XOR,   _f = %d;



#if (USING_ANTIDEBUG)
    %b
    SYSCALL(SYS_PRCTL^q,    PR_SET_PTRACER^f,    0,    NULL, NULL, NULL, NULL);
    %b
    SYSCALL(SYS_PRCTL^q,    PR_SET_NO_NEW_PRIVS, 1,    NULL, NULL, NULL, NULL);
    %b
    SYSCALL(SYS_PRCTL^q,    PR_SET_DUMPABLE,     0,    NULL, NULL, NULL, NULL);
    %b
    SYSCALL(SYS_MLOCKALL^f, MCL_ALL,             NULL, NULL, NULL, NULL, NULL);
    %b
#endif



    int d = (int)SYSCALL((SYS_MEMFD_CREATE>>_f)^q, NAME, MFD_ALLOW_SEALING, NULL, NULL, NULL, NULL);
    %b
    if (d == -1) EXIT();



    {//*
    extern const uchar
        %b[],
        %b[];
    %b
    const uchar
        *sky = %b,
        *src = %b;



    %b
    uchar *buf = (uchar*)__builtin_alloca(CHUNK);
    uchar *o   = buf;
    uchar *oen = buf + CHUNK;
    %b
    uint   x   = (uint)(%b - %b);
    %b
    uchar  y   = sizeof(%b) - 1;
    %b
    uint   i   = 0;
    %b
    uint   g   = SALT;
    %b



    while (i < x) {
        uchar c = DEC(*src, i, sky, y, g); src++; i++;

        if (c & 0x80) {
            uchar l = c & 0x7F;
            if (i >= x) break;

            uchar v = DEC(*src, i, sky, y, g); src++; i++;
            while (l--) {
                if (o >= oen) {SWRITE(d, buf, CHUNK); o = buf;}
                *o++ = v;
            }
        }
        else {
            uchar l = c;
            if ((i + l) > x) break;

            while (l--) {
                if (o >= oen) {SWRITE(d, buf, CHUNK); o = buf;}
                *o++ = DEC(*src, i, sky, y, g); src++; i++;
            }
        }
    }



    if (o > buf) SWRITE(d, buf, (uint)(o - buf));
    ZEROS(buf, CHUNK);
    }//*



    %b
    SYSCALL(SYS_FCNTL^q,          d, F_ADD_SEALS, F_SEALS_ALL, NULL, NULL,            NULL);
    %b
    SYSCALL(SYS_LSEEK,            d, 0,           SEEK_SET,    NULL, NULL,            NULL);
    %b
    SYSCALL((SYS_EXECVEAT>>_q)^f, d, NAME,        argv,        envp, AT_EMPTY_PATH^q, NULL);
    %b



    SYSCALL(SYS_CLOSE, d, NULL, NULL, NULL, NULL, NULL);
    EXIT();
}
''' % (
            *_gn(6, True),
                kk,
            gen_junk(prc=True),
            gen_junk(prc=True),
                kk,
            *_gn(11, True),

            b'T' [0] ^ xor,
            b'P' [0] ^ salt,
            b':' [0] ^ xor,
            gen_junk(prc=True),
            b' ' [0] ^ xor,
            b'\t'[0] ^ salt,
            gen_junk(prc=True),
            b'0' [0] ^ xor,
            gen_junk(prc=True),
            gen_junk(prc=True),

            fmain,

            gen_junk(prc=True),
            gen_junk(prc=True),
                debugexit,
            gen_junk(prc=True),

            gen_junk(prc=True),
                debugexit,
            gen_junk(prc=True),

            shlex, shlmf,

            *_gn(6, True),


                _bs, _be,
            gen_junk(prc=True),
                  kk, _bs,
            *_gn(2, True),
                _be, _bs,
            gen_junk(prc=True),
                    kk,

            *_gn(7, True)
        )
    ))

    del xor, shlmf, shlex
    del   _bs, _be, kk
    del    debugexit


    code.extend(mem(
b'''\n\n\n
__attribute__((
    naked,                 noreturn,    leaf,
    no_stack_protector,    noipa,       visibility("hidden"),
                        cold,    nothrow
)) void %b(void) {
#if (USING_OBF)
    __asm__ volatile (''' % entry
    ))


    code.extend(mem(
b'''
        %b
        "mov %%%%rsp, %%%%rsi\\n"
        %b
        "lodsq\\n"
        %b
        "mov %%%%rax, %%%%rdi\\n"
        %b

        "shl $3,      %%%%rax\\n"
        %b
        "add %%%%rsi, %%%%rax\\n"
        %b
        "add $8,      %%%%rax\\n"
        %b
        "mov %%%%rax, %%%%rdx\\n"
        %b

        "sub %%%%rbp, %%%%rbp\\n"
        %b
        "sub %%%%rbx, %%%%rbx\\n"
        %b
        "sub %%%%r12, %%%%r12\\n"
        %b
        "sub %%%%r13, %%%%r13\\n"
        %b
        "sub %%%%r14, %%%%r14\\n"
        %b
        "sub %%%%r15, %%%%r15\\n"
        %b

        %b
        %b
        %b
''' % (
            *_gn(14),
            (
                    JKFCAL[0]
                if rand.randbelow(3) else
                    b'"jmp %b\\n"' % fmain
            ),
            gen_junk(True),
            rand.choice(JKFCAL)
        )
    ))


    code.extend(mem(
b'''\n
        %b
        "call %b\\n"

        "%b:\\n"
            %b
            "pop              %%%%r8\\n"
            %b
            "addq $(%b - %b), %%%%r8\\n"
            %b

            %b
            "subq $8,         %%%%rsp\\n"
            %b
            "movq %%%%r8,    (%%%%rsp)\\n"
            %b

            %b
            "ret\\n"


        : : :           "memory", "cc",
              "rdi",    "rsi",    "rdx",    "rax",
              "rbp",    "rbx",    "r8",     "r12",
                    "r13",    "r14",    "r15"
    );
#else
    __asm__ volatile (
        "xor %%%%ebp, %%%%ebp\\n"
        "xor %%%%ebx, %%%%ebx\\n"

        "mov   (%%%%rsp), %%%%edi\\n"
        "lea  8(%%%%rsp), %%%%rsi\\n"
        "lea 16(%%%%rsp,  %%%%rdi, 8), %%%%rdx\\n"

        "sub $8, %%%%rsp\\n"
        "jmp %b"


        : : : "memory", "rbp", "rbx"
    );
#endif
    __builtin_unreachable();
}
''' % (
            gen_junk(True),
            lb_main, lb_main,
            gen_junk(True),
            gen_junk(True),
            fmain,
            lb_main,
            *_gn(5),
            fmain
        )
    ))



    ok = writef(PATH_LOADER_C, mem(code))

    del lb_main, code
    return ok




def make_elfstrip() -> bool:
    if os.access(PATH_ELFSTRIP, os.X_OK):
        return True


    dt = mem(b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00G\x0b@\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x10$\x00\x00\x00\x00\x00\x00\x10$\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x10$\x00\x00\x00\x00\x00\x00\x104@\x00\x00\x00\x00\x00\x104@\x00\x00\x00\x00\x00<\x00\x00\x00\x00\x00\x00\x00\xb0\x02\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00Q\xe5td\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00PX\xc3\x00\x00\x00\x00\x00\xf3\x0f\x1e\xfaS\x89\xfb\xe8\xe4\x0e\x00\x00\xe8\xef\x0e\x00\x001\xc0\xe8\xd8\x0e\x00\x00\x89\xdf\xe8a\x1d\x00\x00\x90\xf3\x0f\x1e\xfaAWAVAUATUSH\x81\xec8\x01\x00\x00\x83\xff\x02t\n\xbf\xbb!@\x00\xeb#\x0f\x1f\x00H\x8b~\x081\xc0\xbe\x02\x00\x00\x00g\xe8\xeb\x0e\x00\x00\x89D$X\xff\xc0u\x0f\xbfz"@\x00f\x90\xe8V\x0b\x00\x00\x0f\x1f\x00\x8b|$XH\x8d\xb4$\xa0\x00\x00\x00g\xe82\x11\x00\x00\xbf\x95"@\x00\xff\xc0t\xddH\x8b\x84$\xd0\x00\x00\x00\xbf\xb1"@\x00H\x89D$\x08H=\xff\x03\x00\x00~\xc3D\x8bD$XH\x8bt$\x08E1\xc91\xff\xb9\x01\x00\x00\x00\xba\x03\x00\x00\x00g\xe8\x90\x0f\x00\x00H\x89\xc3H\x83\xf8\xffu\x0b\x0f\x1f\x00\xbf\xde"@\x00\xeb\x91\x90H\x89\xc7\xba\x04\x00\x00\x00\xbe\xf9"@\x00g\xe8Y\x1e\x00\x00\xbf\xfe"@\x00\x85\xc0\x0f\x85p\xff\xff\xff\x80{\x05\x01t\x0ef\x90\xbf\x1f#@\x00\xe9^\xff\xff\xfff\x90\x8aC\x04\x88D$\\\xfe\xc8u-\x8bC\x1cf\x83{* A\xba \x00\x00\x00H\x89D$8\x0f\xb7C,H\x89D$\x18\x8bC\x10f\x89D$^f\x8bC\x12tC\xeb\xbd\x90H\x8bC \x80|$\\\x02\xbf>#@\x00f\x8bS6H\x89D$8\x0f\xb7C8H\x89D$\x18\x8bC\x10f\x89D$^f\x8bC\x12\x0f\x85\xf2\xfe\xff\xfff\x83\xfa8u\x84A\xba8\x00\x00\x00f\x90f\x83\xf8(\xbfc#@\x00\x0f\x94\xc2f=\xf3\x00\x0f\x94\xc0\t\xc2f\x8bD$^\x88\x94$\x92\x00\x00\x00\x83\xe8\x02f\x83\xf8\x01\x0f\x87\xb6\xfe\xff\xffH\x8bl$\x18H\x8bD$8L\x89T$\x10I\x0f\xaf\xeaH\x01\xc5\x0f\x92\xc0\x0f\xb6\xc0H9l$\x08\x0f\x82\'\xff\xff\xffH\x85\xc0\x0f\x85\x1e\xff\xff\xffH\x8bD$\x18E1\xc9A\x83\xc8\xff1\xff\xb9"\x00\x00\x00\xba\x03\x00\x00\x00H\xff\xc0H\xc1\xe0\x04H\x89\xc6H\x89D$`g\xe8E\x0e\x00\x00I\x89\xc6H\x83\xf8\xff\x0f\x84\xb4\xfe\xff\xffE1\xdbH\x89h\x08L\x8bT$\x10L\x89\x18H\x8bD$8\xc6D$]\x00H\x01\xd8H\x89D$@1\xc0\x80|$\\\x01\x0f\x95\xc01\xedE1\xe4H\x8d\x04\xc5\x08\x00\x00\x00H\x89l$0H\x89D$ H\x89l$P1\xed\x0f\x1f\x00H\x8bt$\x18A\x0f\xb7\xc4H9\xf0\x0f\x83\x96\x00\x00\x00I\x0f\xaf\xc2H\x8bt$@H\x01\xf0\x80|$\\\x01\x8b\x10u\t\x8bp\x10\x8bx\x04\xeb\t\x90H\x8bp H\x8bx\x08\x83\xfa\x03tO\x81\xfaS\xe5tdtO\xf6D$]\x01uT\xff\xcauPH\x8d\x047H9D$\x08rEH\x01\xdf\xba\x81#@\x00\xb9\x0e\x00\x00\x00L\x89T$\x10g\xe8)\x14\x00\x00\x8aT$]L\x8bT$\x10H\x85\xc0\xb0\x01\x0fE\xd0\x88T$]\xeb\x16f\x90@\xb5\x01\xeb\x0f\x0f\x1f\x00H\x89|$0H\x89t$Pf\x90A\xff\xc4\xe9X\xff\xff\xff\x83\xe5\x01f\xc7D$\x10\x00\x00f\xc7\x84$\x90\x00\x00\x00\x00\x00H\xc7D$(\x01\x00\x00\x00@\x88\xac$\x93\x00\x00\x00\x0f\x1f\x00D\x0f\xb7\xac$\x90\x00\x00\x00H\x8bD$\x18I9\xc5\x0f\x83\xd1\x03\x00\x00M\x0f\xaf\xeaH\x8bD$@I\x01\xc5\x80|$\\\x01E\x8bE\x00u\x16A\x8bE\x14E\x8be\x10E\x8bM\x04H\x89D$H\xeb\x17\x0f\x1f\x00I\x8bE(M\x8be M\x8bM\x08H\x89D$H\x0f\x1f\x00L9d$H\x0f\x82e\xfd\xff\xffL\x89\xca1\xc0L\x01\xe2\x0f\x92\xc0I\x89\xd7H9T$\x08\x0f\x82\\\x03\x00\x00$\x01\x0f\x85T\x03\x00\x00N\x8d\x1c\x0bA\x83\xf8\x04uBH\x8bL$0H\x8bt$PH\x01\xceH\x83|$P\x00@\x0f\x95\xc7L9\xc9\x0f\x93\xc1@\x84\xcft0H9\xf2r+H\x8bL$0H)\xf2L\x89\xdfH\x01\xdeL)\xc9\xf3\xaaH\x89\xd1H\x89\xf7\xeb\x18\x80|$]\x00u%A\x81\xf8P\xe5tdu\x101\xc0L\x89\xdfL\x89\xe1\xf3\xaa\xe9\xe9\x02\x00\x00\x90A\x81\xf8\x01\x00\x00pt\xe7\x0f\x1f\x00A\x83\xf8\x03uFL\x89\xdfL\x89\xe6L\x89T$xD\x89\x84$\x80\x00\x00\x00L\x89L$pL\x89\\$hg\xe8\xe7\x1b\x00\x00L\x8b\\$hL\x8bL$pH\x8dh\x01L\x8bT$xD\x8b\x84$\x80\x00\x00\x00L9\xe5\xe9\x1c\x01\x00\x00A\x83\xf8\x02t\nf\x90L\x89\xe5\xe9D\x01\x00\x00H\x8bD$ L\x89\xde1\xedL)\xd8H\x89D$hf\x90H\x8bD$hH\x01\xf0I9\xc4\x0f\x82\xe3\x00\x00\x00\x80|$\\\x01u\x08Hc\x0e\x8bF\x04\xeb\x08H\x8b\x0eH\x8bF\x08\x90H\x83\xf9\x15\x0f\x84\xb2\x00\x00\x00H\x83\xf9\x0eu\x1cf\x83|$^\x02\x0f\x84\xa0\x00\x00\x00\x80\xbc$\x93\x00\x00\x00\x00\x0f\x85\x92\x00\x00\x00f\x90H\x85\xc0u\x13H\x85\xc9t\x0eH\x8dA\xeaH\xa9\xfd\xff\xff\xffuzf\x90I\x8d<+H9\xfet_H\x8bT$ H\x89\x8c$\x98\x00\x00\x00D\x89\x84$\x94\x00\x00\x00L\x89\x94$\x88\x00\x00\x00L\x89\x9c$\x80\x00\x00\x00L\x89L$xH\x89t$pg\xe8\'\x1b\x00\x00H\x8b\x8c$\x98\x00\x00\x00D\x8b\x84$\x94\x00\x00\x00L\x8b\x94$\x88\x00\x00\x00L\x8b\x9c$\x80\x00\x00\x00L\x8bL$xH\x8bt$pH\x8bD$ H\x01\xc5H\x85\xc9t\x13\x0f\x1f\x00H\x8bD$ H\x01\xc6\xe9\x0f\xff\xff\xff\x0f\x1f\x00L9\xe5\x90\x0f\x83\xe6\xfe\xff\xffL\x89\xe1I\x8d\x14+1\xc0H)\xe9H\x89\xd7\xf3\xaa\x80|$\\\x01u\nA\x89m\x10A\x89m\x14\xeb\x08I\x89m I\x89m(N\x8d|\r\x00\x0f\x1f\x00A\x83\xf8\x01A\x0f\x94\xc4H\x85\xedt3J\x8dD\r\x00E\x84\xe4t)\x90A\x80|+\xff\x00u\x08H\xff\xcdu\xf3\x0f\x1f\x00M\x8d|)\x07I\x83\xe7\xf8I9\xc7L\x0fG\xf8L\x89\xfdL)\xcd\xebHA\x81\xf8S\xe5tdw+A\x81\xf8O\xe5tdw6A\x83\xf8\x03w\x0cE\x85\xc0\x0f\x84\xdb\x00\x00\x00\xeb%\x90A\x8d@\xfa\x83\xf8\x01\x0f\x87\xcb\x00\x00\x00\xeb\x15\x90D\x89\xc0\x83\xe0\xfd=\x01\x00\x00p\x0f\x85\xb7\x00\x00\x00\x0f\x1f\x00\x0f\xb7L$\x10H\x8bD$@I\x0f\xaf\xcaH\x01\xc1I9\xcdt2L\x89\xd2H\x89\xcfL\x89\xeeD\x89D$xL\x89L$pL\x89T$hg\xe8\xe5\x19\x00\x00D\x8bD$xL\x8bL$pL\x8bT$hH\x89\xc1f\x90\x80|$\\\x01u\x05\x89i\x10\xeb\x04H\x89i A\x83\xf8\x07t\x06E\x84\xe4t!\x90H\x8bD$HH9\xc5H\x0fC\xc5\x80|$\\\x01u\x05\x89A\x14\xeb\x18H\x89A(\xeb\x12f\x90\x80|$\\\x01u\x05\x89i\x14\xeb\x04H\x89i(H\x8bD$(f\xffD$\x10H\xffD$(H\xc1\xe0\x04L\x01\xf0L\x89\x08L\x89x\x08\x0f\x1f\x00f\xff\x84$\x90\x00\x00\x00\xe9\x1b\xfc\xff\xff\x0f\x1f\x00H\x8bD$@1\xd2\x90f9T$\x10t9\x838\x06\x0f\x94\xc1\x84\xc9t\'\x0f\xb7T$\x10I\x0f\xaf\xd2\x80|$\\\x01u\x0b\x89P\x10\x89P\x14\xeb\x17\x0f\x1f\x00H\x89P H\x89P(\xeb\nf\x90L\x01\xd0\xff\xc2\xeb\xc1\x90\x0f\xb7|$\x10H\x8bD$\x18H9\xc7s!H\x89\xc1H\x8bT$81\xc0H)\xf9I\x0f\xaf\xfaI\x0f\xaf\xcaH\x01\xfaH\x01\xdaH\x89\xd7\xf3\xaa\x90I\x8dV\x10\xbe\x01\x00\x00\x00H\x89\xd1H\x8bD$(H9\xc6sBH\x8b9L\x8bA\x08I\x89\xc9H\x89\xf0\x90I;y\xf0s\x16A\x0f\x10A\xf0I\x83\xe9\x10A\x0f\x11A\x10H\xff\xc8u\xe7\x0f\x1f\x00H\xc1\xe0\x04H\xff\xc6H\x83\xc1\x10L\x01\xf0H\x898L\x89@\x08\xeb\xb5\x90H\x89\xd0\xb9\x01\x00\x00\x001\xf6f\x90L\x8dF\x01H\x8b|$(M\x89\xc1I\xc1\xe1\x04H9\xf9s;K\x8d|\x0e\xf0L\x8bW\x08L;\x10s\r\x0f\x10\x08C\x0f\x11\x0c\x0e\xeb\x17\x0f\x1f\x00L\x8b@\x08M9\xc2s\x07L\x89G\x08\x0f\x1f\x00I\x89\xf0\x90H\xff\xc1H\x83\xc0\x10L\x89\xc6\xeb\xb0I\x8bv\x08A\xba\x01\x00\x00\x001\xc0M9\xc2s+H\x8b\nH9\xces\x0fL\x8d\x1c3H)\xf1L\x89\xdf\xf3\xaa\x0f\x1f\x00H\x8bJ\x08H9\xceH\x0fB\xf1I\xff\xc2H\x83\xc2\x10\xeb\xd0\x80|$\\\x01\x8bD$\x10u)E1\xc0E1\xd2f\x89C,\x80\xbc$\x92\x00\x00\x00\x00D\x89C f\xc7C.\x00\x00D\x89S0u+1\xc9\x89K$\xeb$1\xf61\xfff\x89C8\x80\xbc$\x92\x00\x00\x00\x00H\x89s(f\xc7C:\x00\x00\x89{<u\x051\xd2\x89S01\xc0\xc6C\x0f\x00H\x89C\x07K\x8b|\x0e\xf8H\x8bD$\x08H\x8do\x07H\x83\xe5\xf8H9\xc5H\x0fG\xe8H9\xefs\x14H\x89\xe9H\x8d\x14;1\xc0H)\xf9H\x89\xd7\xf3\xaa\x0f\x1f\x00H\x8bt$\x08H\x89\xdf\xba\x04\x00\x00\x00g\xe8\x15\x08\x00\x00\xbf\x90#@\x00\xff\xc0\x0f\x84,\xf7\xff\xffH\x8bt$\x08H\x89\xdfg\xe8*\x08\x00\x00H\x8bt$`L\x89\xf7g\xe8\x1c\x08\x00\x00\x8b|$XH\x89\xeeg\xe8_\x10\x00\x00\xbf\xac#@\x00\xff\xc0\x0f\x84\xf6\xf6\xff\xff\x8b|$Xg\xe8\x18\x10\x00\x00\xbf\xcc#@\x00\xff\xc0\x0f\x84\xdf\xf6\xff\xff\x8b|$Xg\xe8\xb1\x0f\x00\x00H\x8bD$\x081\xd2\xbe\xe8#@\x00\xbf\x01\x00\x00\x00H)\xe8Hi\xc0\xe8\x03\x00\x00H\xf7t$\x08\xba\x0e\x00\x00\x00H\x89\xc3g\xe8#\x10\x00\x00H\x8b|$\x08\xe8\x95\x01\x00\x00\xba\x04\x00\x00\x00\xbe\xf7#@\x00\xbf\x01\x00\x00\x00g\xe8\x04\x10\x00\x00H\x89\xef\xe8x\x01\x00\x00\xba\t\x00\x00\x00\xbe\xfc#@\x00\xbf\x01\x00\x00\x00g\xe8\xe7\x0f\x00\x00\xbe\n\x00\x00\x00H\x89\xd81\xd2H\xf7\xf6H\x89\xc7H\x89\xd3\xe8K\x01\x00\x00\xba\x01\x00\x00\x00\xbex"@\x00\xbf\x01\x00\x00\x00g\xe8\xba\x0f\x00\x00H\x89\xdf\xe8.\x01\x00\x00\xba\x03\x00\x00\x00\xbe\x06$@\x00\xbf\x01\x00\x00\x00g\xe8\x9d\x0f\x00\x00H\x81\xc48\x01\x00\x001\xc0[]A\\A]A^A_\xc3H1\xedH\x89\xe7H\x8d5\xac\xf4\xbf\xffH\x83\xe4\xf0\xe8\x03\x00\x00\x00\x0f\x1f\x00\xf3\x0f\x1e\xfa\x8b7H\x8dW\x08I\xc7\xc0\x9f!@\x00E1\xc9H\xc7\xc1\xe8\x00@\x00H\xc7\xc7\x10\x01@\x00\xe9\x19\x04\x00\x00f\x0f\x1f\x84\x00\x00\x00\x00\x00H\x8d=\xb9(\x00\x00H\x8d\x05\xb2(\x00\x00H9\xf8t\x15H\xc7\xc0\x00\x00\x00\x00H\x85\xc0t\t\xff\xe0\x0f\x1f\x80\x00\x00\x00\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00H\x8d=\x89(\x00\x00H\x8d5\x82(\x00\x00H)\xfeH\x89\xf0H\xc1\xee?H\xc1\xf8\x03H\x01\xc6H\xd1\xfet\x14H\xc7\xc0\x00\x00\x00\x00H\x85\xc0t\x08\xff\xe0f\x0f\x1fD\x00\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00\xf3\x0f\x1e\xfa\x80=U(\x00\x00\x00u+UH\x83=\n(\x00\x00\x00H\x89\xe5t\x0cH\x8b=\x1e(\x00\x00\xe8\xd9\xf3\xbf\xff\xe8d\xff\xff\xff\xc6\x05-(\x00\x00\x01]\xc3\x0f\x1f\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00\xf3\x0f\x1e\xfa\xe9w\xff\xff\xff\x0f\x1f\x00H\x83\xec(H\x85\xffu\x0b\xc6D$\x1e0\xb1\x15\xeb*f\x90\xb1\x16A\xb8\n\x00\x00\x00H\x89\xf81\xd2\x0f\xb6\xf1\xff\xc9I\xf7\xf0\x83\xc20\x88T4\x08H\x89\xfaH\x89\xc7H\x83\xfa\tw\xe0\x0f\xb6\xc9\xba\x16\x00\x00\x00\xbf\x01\x00\x00\x00)\xca\xff\xc1Hc\xc9Hc\xd2H\x8dt\x0c\x08g\xe8&\x0e\x00\x00H\x83\xc4(\xc3SH\x89\xfbg\xe8\xf7\x13\x00\x00H\x89\xde\xbf\x02\x00\x00\x00H\x89\xc2g\xe8\x06\x0e\x00\x00\xbf\x02\x00\x00\x00\xba\x01\x00\x00\x00\xbe\x08$@\x00g\xe8\xf1\r\x00\x00\xbf\x01\x00\x00\x00g\xe8\xa6\x14\x00\x00f\x0f\x1fD\x00\x00\xf3\x0f\x1e\xfaH\x81\xecX\x01\x00\x00H\x89\xfa1\xc0\xb9&\x00\x00\x00L\x8dD$ L\x89\xc7\xf3H\xabH\xc7\xc0\x085@\x00H\x89\x10H\x83:\x00\x0f\x84\xb4\x01\x00\x001\xc0f.\x0f\x1f\x84\x00\x00\x00\x00\x00H\x89\xc1H\x83\xc0\x01H\x83<\xc2\x00u\xf2H\x8d\x04\xcd\x10\x00\x00\x00H\x01\xd0H\x89\x05X\'\x00\x00H\x8b\x10H\x83\xc0\x08H\x85\xd2\x0f\x84\x88\x01\x00\x00H\x83\xfa%w\x08H\x8b\x08H\x89L\xd4 H\x8bP\x08H\x83\xc0\x10H\x85\xd2u\xe5H\x8b\x8c$\xa0\x00\x00\x00H\x8b\x84$ \x01\x00\x00H\x8bT$PH\x89\r\xe9&\x00\x00H\x85\xc0t\x07H\x89\x05\xc5&\x00\x00H\x89\x15&\'\x00\x00H\x85\xf6\x0f\x84\r\x01\x00\x00H\xc7\xc0p4@\x00H\xc7\xc1x4@\x00H\x890H\x8dF\x01H\x891\x0f\xb6\x16\x84\xd2t\x19f\x0f\x1fD\x00\x00\x80\xfa/u\x03H\x89\x01\x0f\xb6\x10H\x83\xc0\x01\x84\xd2u\xedL\x89\xc7\xe8\xad\r\x00\x00H\x8b\xbc$\xe8\x00\x00\x00\xe8\xe0\x0f\x00\x00H\x8b\x84$\x80\x00\x00\x00H9D$x\x0f\x84}\x00\x00\x00f\x0f\xef\xc0H\x89\xe7\xb8\x07\x00\x00\x001\xd2H\xc7D$\x10\x00\x00\x00\x00\xbe\x03\x00\x00\x00\x0f)\x04$\xc7D$\x10\x02\x00\x00\x00\xc7D$\x08\x01\x00\x00\x00\x0f\x05\x85\xc0y\x01\xf4H\x89\xfaL\x8dD$\x18A\xb9\x02\x00\x00\x00\xbe\x02\x80\x00\x00H\x8d=>\x13\x00\x00\xf6B\x06 t\x0bL\x89\xc8\x0f\x05H\x85\xc0y\x01\xf4H\x83\xc2\x08L9\xc2u\xe6\xc6\x05\x1d&\x00\x00\x01H\x81\xc4X\x01\x00\x00\xc3\x0f\x1f\x00H\x8b\x84$\x90\x00\x00\x00H9\x84$\x88\x00\x00\x00\x0f\x85m\xff\xff\xffH\x83\xbc$\xd8\x00\x00\x00\x00\x0f\x85^\xff\xff\xff\xeb\xcef\x0f\x1f\x84\x00\x00\x00\x00\x00H\x8b\x84$\x18\x01\x00\x00H\x85\xc0t+H\x89\xc6\xe9\xde\xfe\xff\xff\x0f\x1f\x00\xb8\x08\x00\x00\x00\xe9d\xfe\xff\xfff\x0f\x1fD\x00\x00H\xc7\x05\x8d%\x00\x00\x00\x00\x00\x00\xe9\xab\xfe\xff\xffH\xc7\xc2p4@\x00H\x8d\x05\x03\x15\x00\x00H\x89\x02H\xc7\xc2x4@\x00H\x89\x02\xe9\xd3\xfe\xff\xff\x0f\x1f\x84\x00\x00\x00\x00\x00\xf3\x0f\x1e\xfaUSH\x83\xec\x08\xe8\xb9\xf1\xff\xffH\xc7\xc3\x104@\x00H\xc7\xc5\x184@\x00H9\xebs\x11f\x0f\x1fD\x00\x00\xff\x13H\x83\xc3\x08H9\xebr\xf5H\x83\xc4\x08[]\xc3f\x0f\x1fD\x00\x00\xf3\x0f\x1e\xfaAUHc\xc6ATL\x8dl\xc2\x08I\x89\xfcUH\x89\xd5SH\x89\xc3H\x83\xec\x08\xe8\x9c\xff\xff\xff\x89\xdfL\x89\xeaH\x89\xeeA\xff\xd4\x89\xc7\xe8Z\xf1\xff\xfff.\x0f\x1f\x84\x00\x00\x00\x00\x00\xf3\x0f\x1e\xfaATHc\xc6I\x89\xfcUH\x8d|\xc2\x08H\x89\xc5SH\x8b2H\x89\xd3\xe8/\xfd\xff\xffH\x89\xda\x89\xeeL\x89\xe7H\x8d\x05\x90\xff\xff\xff[]A\\\xff\xe0f.\x0f\x1f\x84\x00\x00\x00\x00\x00\xf3\x0f\x1e\xfa\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x90\xf3\x0f\x1e\xfaUSH\x83\xec\x08H\xc7\xc3 4@\x00H\xc7\xc5\x184@\x00H9\xdds\x10\x0f\x1f\x00H\x83\xeb\x081\xc0\xff\x13H9\xddr\xf3H\x83\xc4\x081\xc0[]\xe9u\x11\x00\x00f\x0f\x1fD\x00\x00\xf3\x0f\x1e\xfaS\x89\xf3H\x83\xecPH\x89T$0dH\x8b\x04%(\x00\x00\x00H\x89D$\x181\xc0\x83\xe6@u[\x89\xd81\xc9\xf7\xd0\xa9\x00\x00A\x00tNH\x83\xec\x08\x89\xdaH\x89\xfeE1\xc9j\x00\x80\xce\x80\xbf\x02\x00\x00\x00E1\xc0Hc\xd2\xe8\x8d\t\x00\x00ZYHc\xf8\x85\xc0x\x08\x81\xe3\x00\x00\x08\x00uD\xe8W\x00\x00\x00H\x8bT$\x18dH+\x14%(\x00\x00\x00uBH\x83\xc4P[\xc3\x90H\x8dD$`\xc7\x04$\x10\x00\x00\x00\x8bL$0H\x89D$\x08H\x8dD$ H\x89D$\x10\xeb\x91\x0f\x1f\x80\x00\x00\x00\x00\xb8H\x00\x00\x00\xbe\x02\x00\x00\x00\xba\x01\x00\x00\x00\x0f\x05\xeb\xa9\xe8P\r\x00\x00\xf3\x0f\x1e\xfaH\x81\xff\x00\xf0\xff\xffw\x0bH\x89\xf8\xc3\x0f\x1f\x80\x00\x00\x00\x00H\x83\xec\x18H\x89|$\x08\xe8:\r\x00\x00H\x8b|$\x08\xf7\xdf\x898H\xc7\xc0\xff\xff\xff\xffH\x83\xc4\x18\xc3\x0f\x1fD\x00\x00\xf3\x0f\x1e\xfa\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x90\xf3\x0f\x1e\xfaATSH\x83\xec(A\xf7\xc1\xff\x0f\x00\x00\x0f\x85\x88\x00\x00\x00H\xb8\xfe\xff\xff\xff\xff\xff\xff\x7fH9\xf0rYI\x89\xfc\x89\xcb\xf6\xc1\x10\x0f\x85\x8b\x00\x00\x00Hc\xd2Lc\xd3Mc\xc0\xb8\t\x00\x00\x00L\x89\xe7\x0f\x05H\x89\xc7H\x83\xf8\xffu\x1dM\x85\xe4u\x18\x83\xe30H\xc7\xc7\xf4\xff\xff\xffH\xc7\xc0\xff\xff\xff\xff\x83\xfb H\x0fE\xf8H\x83\xc4([A\\\xe96\xff\xff\xfff\x0f\x1fD\x00\x00\xe8\x8b\x0c\x00\x00\xc7\x00\x0c\x00\x00\x00H\x83\xc4(H\xc7\xc0\xff\xff\xff\xff[A\\\xc3f\x0f\x1fD\x00\x00\xe8k\x0c\x00\x00\xc7\x00\x16\x00\x00\x00H\x83\xc4(H\xc7\xc0\xff\xff\xff\xff[A\\\xc3f\x0f\x1fD\x00\x00L\x89L$\x18D\x89D$\x14\x89T$\x10H\x89t$\x08\xe8\x18\xff\xff\xffL\x8bL$\x18D\x8bD$\x14\x8bT$\x10H\x8bt$\x08\xe9E\xff\xff\xff\xf3\x0f\x1e\xfaH\x83\xec\x10Hc\xcaE1\xc9H\x89\xf2j\x00H\x89\xfeE1\xc0\xbf\x1a\x00\x00\x00\xe8\xbd\x07\x00\x00H\x89\xc7\xe8\x95\xfe\xff\xffH\x83\xc4\x18\xc3\xf3\x0f\x1e\xfaUH\x89\xf5SH\x89\xfbH\x83\xec\x08\xe8\xbb\xfe\xff\xff\xb8\x0b\x00\x00\x00H\x89\xdfH\x89\xee\x0f\x05H\x89\xc7\xe8f\xfe\xff\xffH\x83\xc4\x08[]\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1fD\x00\x00\xf3\x0f\x1e\xfa\x85\xffx\x18H\x89\xf2\xb9\x00\x10\x00\x00H\x8d5R\x11\x00\x00\xe9$\x00\x00\x00\x0f\x1f@\x00H\x83\xec\x08H\xc7\xc7\xf7\xff\xff\xff\xe8 \xfe\xff\xffH\x83\xc4\x08\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x90\xf3\x0f\x1e\xfaUA\x89\xf8I\x89\xf1SH\x89\xd3H\x81\xec\xd8\x00\x00\x00dH\x8b\x04%(\x00\x00\x00H\x89\x84$\xc8\x00\x00\x001\xc0H\x8dT$\x10\x81\xf9\x00\x10\x00\x00\x0f\x85\xce\x00\x00\x00\x85\xff\x0f\x88\xc6\x00\x00\x00\x80>\x00\x0f\x85\x15\x01\x00\x00Hc\xff\xb8\x05\x00\x00\x00H\x89\xd6\x0f\x05A\x89\xc2\x83\xf8\xf7\x0f\x84\x1c\x01\x00\x00\x0f\x1f@\x00Ic\xfaE\x85\xd2un1\xc0\xb9\x12\x00\x00\x00H\x89\xdff\x0foD$\x10\xf3H\xabH\x8bD$ 1\xfff\x0foL$@f\x0foT$Pf\x0fo\\$`\x0f\x11\x03H\x89C\x10H\x8bD$(f\x0fod$p\x0f\x11K0H\x89C\x18\x8bD$0\x0f\x11S@\x89C H\x8bD$8\x0f\x11[PH\x89C(H\x8b\x84$\x80\x00\x00\x00\x0f\x11c`H\x89Cp\xe8-\xfd\xff\xffH\x8b\x94$\xc8\x00\x00\x00dH+\x14%(\x00\x00\x00\x0f\x85\xee\x00\x00\x00H\x81\xc4\xd8\x00\x00\x00[]\xc3\x0f\x1f@\x00A\x83\xf8\x9cu"\x81\xf9\x00\x01\x00\x00t*\x85\xc9uF\xb8\x04\x00\x00\x00L\x89\xcfH\x89\xd6\x0f\x05A\x89\xc2\xe99\xff\xff\xff\x90A\x0f\xb6\x01\x81\xf9\x00\x01\x00\x00u\x1c</u \xb8\x06\x00\x00\x00L\x89\xcfH\x89\xd6\x0f\x05A\x89\xc2\xe9\x13\xff\xff\xff\x0f\x1f\x00</t\xba\x0f\x1f@\x00Ic\xf8Lc\xd1\xb8\x06\x01\x00\x00L\x89\xce\x0f\x05A\x89\xc2\xe9\xf0\xfe\xff\xff\x0f\x1f\x84\x00\x00\x00\x00\x00\xb8H\x00\x00\x00\xbe\x01\x00\x00\x00\x0f\x05H\x85\xc0xKA\xba\x00\x10\x00\x00\xb8\x06\x01\x00\x00L\x89\xce\x0f\x05A\x89\xc2\x83\xf8\xea\x0f\x85\xbb\xfe\xff\xffH\x8d\xac$\xa0\x00\x00\x00D\x89\xc6H\x89T$\x08H\x89\xef\xe8\xeb\t\x00\x00H\x8bt$\x08\xb8\x04\x00\x00\x00H\x89\xef\x0f\x05A\x89\xc2\xe9\x8c\xfe\xff\xffH\xc7\xc7\xf7\xff\xff\xff\xe9\xf6\xfe\xff\xff\xe8s\t\x00\x00\x0f\x1f\x00AWf\x0f\xef\xc0I\x89\xf8AVAUI\x89\xf5ATUH\x89\xd5SH\x89\xcbH\x81\xecH\x08\x00\x00dH\x8b\x04%(\x00\x00\x00H\x89\x84$8\x08\x00\x001\xc0\x0f)D$\x10\x0f)D$ H\x85\xc9\x0f\x84\xb4\x02\x00\x00\xbf\x01\x00\x00\x00\x0f\x1f@\x00\x0f\xb6L\x05\x00H\x89\xfeH\x83\xc0\x01\x89\xcaH\xd3\xe6H\x89D\xcc0\xc0\xea\x06\x0f\xb6\xd2H\tt\xd4\x10H9\xd8u\xdaH\x83\xfb\x01\x0f\x84{\x02\x00\x00A\xb9\x01\x00\x00\x00\xb8\x01\x00\x00\x00E1\xd2H\xc7\xc7\xff\xff\xff\xff\xba\x01\x00\x00\x00\xeb$\x0f\x1f@\x00@8\xce\x0f\x83\x8f\x01\x00\x00I\x89\xd1I\x89\xd2\xb8\x01\x00\x00\x00I)\xf9I\x8d\x14\x02H9\xdas)H\x8dL=\x00\x0f\xb6t\x15\x00\x0f\xb6\x0c\x01@8\xf1u\xcdL9\xc8\x0f\x84t\x01\x00\x00H\x83\xc0\x01I\x8d\x14\x02H9\xdar\xd7A\xbe\x01\x00\x00\x00\xba\x01\x00\x00\x00E1\xd2I\xc7\xc4\xff\xff\xff\xff\xb8\x01\x00\x00\x00\xeb#\x0f\x1f\x00@8\xce\x0f\x83O\x01\x00\x00I\x89\xc6I\x89\xc2\xba\x01\x00\x00\x00M)\xe6J\x8d\x04\x12H9\xd8s*H\x8dL\x15\x00B\x0f\xb64!\x0f\xb6L\x05\x00@8\xf1u\xccI9\xd6\x0f\x84;\x01\x00\x00H\x83\xc2\x01J\x8d\x04\x12H9\xd8r\xd6M\x8d|$\x01H\x8dG\x01L9\xf8\x0f\x83\xa6\x01\x00\x00H\x89\xefJ\x8dt5\x00L\x89\xfaL\x89D$\x08\xe8\xe7\t\x00\x00H\x89\xdfL\x8bD$\x08L)\xf7\x85\xc0t\x14H\x8dC\xffL)\xe0L9\xe0I\x0fB\xc41\xffL\x8dp\x01L\x89\xe8L)\xc0H9\xd8r`L\x89\xc2H\x8ds\xffE1\xc0\xeb+\x0f\x1fD\x00\x00H\x89\xd8H+D\xcc0\x0f\x84\xca\x00\x00\x00L9\xc0I\x0fB\xc0E1\xc0H\x01\xc2L\x89\xe8H)\xd0H9\xd8r)\x0f\xb6\x0c2\x89\xc8\xc0\xe8\x06\x0f\xb6\xc0H\x8bD\xc4\x10H\xd3\xe8\xa8\x01u\xc2H\x01\xdaL\x89\xe8E1\xc0H)\xd0H9\xd8s\xd71\xd2H\x8b\x84$8\x08\x00\x00dH+\x04%(\x00\x00\x00\x0f\x85\xf8\x00\x00\x00H\x81\xc4H\x08\x00\x00H\x89\xd0[]A\\A]A^A_\xc3\x0f\x1f\x00L\x89\xd7A\xb9\x01\x00\x00\x00I\x83\xc2\x01\xb8\x01\x00\x00\x00\xe9h\xfe\xff\xff\x90I\x01\xc2\xb8\x01\x00\x00\x00\xe9Z\xfe\xff\xff\x0f\x1f\x00M\x89\xd4A\xbe\x01\x00\x00\x00I\x83\xc2\x01\xba\x01\x00\x00\x00\xe9\xa8\xfe\xff\xfff\x0f\x1f\x84\x00\x00\x00\x00\x00M\x01\xf2\xba\x01\x00\x00\x00\xe9\x92\xfe\xff\xff\x0f\x1f\x00M9\xf8L\x89\xf8I\x0fC\xc0H9\xd8r\x12\xeb/\x0f\x1f\x80\x00\x00\x00\x00H\x83\xc0\x01H9\xc3t\x1f\x0f\xb6\x0c\x028L\x05\x00t\xedH9\xd8s\x10L)\xe0E1\xc0H\x01\xc2\xe9\x05\xff\xff\xfff\x90L\x89\xf8\xeb\x11\x0f\x1f\x00H\x83\xe8\x01\x0f\xb6\x0c\x028L\x05\x00u\nI9\xc0r\xed\xe9\x19\xff\xff\xffL\x01\xf2I\x89\xf8\xe9\xd8\xfe\xff\xff1\xc0A\xb9\x01\x00\x00\x00H\xc7\xc7\xff\xff\xff\xffI\x89\xc7I\x89\xfcM\x89\xce\xe9L\xfe\xff\xff\xe8S\x06\x00\x00\x0f\x1f\x00\xf3\x0f\x1e\xfaAUATI\x89\xfcUSH\x83\xec\x08H\x85\xc9tzH\x89\xf5H\x89\xcbH9\xcer_\x0f\xb62I\x89\xd5H\x89\xea\xe81\x07\x00\x00H\x85\xc0tNH\x83\xfb\x01tHH\x89\xc2L)\xe2H)\xd5H9\xddr8H\x83\xfb\x02tRH\x83\xfb\x03\x0f\x84\x10\x01\x00\x00H\x83\xfb\x04\x0f\x84\x9e\x00\x00\x00H\x83\xc4\x08H\x8d4(H\x89\xd9L\x89\xea[H\x89\xc7]A\\A]\xe9b\xfc\xff\xfff\x901\xc0H\x83\xc4\x08[]A\\A]\xc3\x0f\x1f\x00H\x83\xc4\x08H\x89\xf8[]A\\A]\xc3f\x90A\x0f\xb7M\x00\x0f\xb70A\x89\xc8\x89\xf2fA\xc1\xc0\x08f\xc1\xc2\x08H\x83\xfd\x02\x0f\x84\x9c\x00\x00\x00f9\xcet\xbdH\x8dH\x03H\x01\xc5\xeb\x0cf\x90H\x83\xc1\x01fD9\xc2t\x17\x0f\xb6y\xff\xc1\xe2\x08H\x89\xc8\t\xfaH9\xe9u\xe5fD9\xc2u\x8fH\x83\xe8\x02\xeb\x8bf\x0f\x1f\x84\x00\x00\x00\x00\x00A\x8bM\x00\x8b0A\x89\xc8\x89\xf2A\x0f\xc8\x0f\xcaH\x83\xfd\x04\x0f\x84\xd2\x00\x00\x009\xce\x0f\x84`\xff\xff\xffH\x8dH\x05H\x01\xc5\xeb\x0e\x0f\x1fD\x00\x00H\x83\xc1\x01D9\xc2t\x1a\x0f\xb6y\xff\xc1\xe2\x08H\x89\xc8\t\xfaH9\xcdu\xe6A9\xd0\x0f\x85-\xff\xff\xffH\x83\xe8\x04\xe9&\xff\xff\xffH\x83\xc0\x02\xeb\x89f\x0f\x1fD\x00\x00E\x0f\xb6E\x00A\x0f\xb6U\x01\x0f\xb6H\x01\xc1\xe2\x10A\xc1\xe0\x18A\t\xd0A\x0f\xb6U\x02\xc1\xe1\x10\xc1\xe2\x08A\t\xd0\x0f\xb6\x10\xc1\xe2\x18\t\xca\x0f\xb6H\x02\xc1\xe1\x08\t\xcaH\x83\xfd\x03tPH\x8dH\x04H\x01\xc5A9\xd0u\x18\xe9\xcc\xfe\xff\xfff.\x0f\x1f\x84\x00\x00\x00\x00\x00H\x83\xc1\x01A9\xd0t\x1a\x0f\xb6y\xffH\x89\xc8\t\xfa\xc1\xe2\x08H9\xcdu\xe6D9\xc2\x0f\x85\x9d\xfe\xff\xffH\x83\xe8\x03\xe9\x96\xfe\xff\xffH\x83\xc0\x04\xe9U\xff\xff\xffH\x83\xc0\x03\xeb\xdf\x0f\x1fD\x00\x00\xf3\x0f\x1e\xfaH\x89\xf8M\x89\xc2H\x89\xf7M\x89\xc8H\x89\xd6L\x8bL$\x08H\x89\xca\x0f\x05\xc3f\x90\xf3\x0f\x1e\xfa\xe9\xd7\xff\xff\xff\x0f\x1f\x80\x00\x00\x00\x00\xf3\x0f\x1e\xfa\x89\xf8\xc3f\x0f\x1f\x84\x00\x00\x00\x00\x00\xf3\x0f\x1e\xfaH\x83\xec\x08\xe8\xe3\xff\xff\xffH\x83\xec\x08E1\xc9E1\xc0j\x001\xc91\xd2Hc\xf0\xbf\x03\x00\x00\x00\xe8\xb6\xff\xff\xffZ1\xd2Y\x83\xf8\xfc\x0fD\xc2Hc\xf8\xe8\x84\xf6\xff\xffH\x83\xc4\x08\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1fD\x00\x00\xf3\x0f\x1e\xfaH\x83\xec\x10Hc\xf7E1\xc9E1\xc0j\x001\xc91\xd2\xbfJ\x00\x00\x00\xe8o\xff\xff\xffH\x89\xc7\xe8G\xf6\xff\xffH\x83\xc4\x18\xc3f\x90\xf3\x0f\x1e\xfaH\x83\xec\x08Hc\xff\xb8M\x00\x00\x00\x0f\x05H\x89\xc7\xe8&\xf6\xff\xffH\x83\xc4\x08\xc3\x90\xf3\x0f\x1e\xfaH\x83\xec\x10H\x89\xf0H\x89\xd1Hc\xf7j\x00\xbf\x01\x00\x00\x00E1\xc9E1\xc0H\x89\xc2\xe8\x1a\xff\xff\xffH\x83\xc4\x18H\x89\xc7\xe9\xee\xf5\xff\xfff.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f@\x00\xf3\x0f\x1e\xfaAUI\x89\xfdATUSH\x83\xec\x08H\x8b\x05\x90\x19\x00\x00L\x8b%\x91\x19\x00\x00H\x8b\x1dz\x19\x00\x00H\x8d\x84\x078\xff\xff\xffI\xf7\xdcI!\xc4H\x85\xdbt2H\x8do\x08\x0f\x1f\x00L\x89\xe0H+C(L\x89\xe7H\x83\xc5\x08H\x89E\xf8H\x8bS\x10H\x8bs\x08H+{(\xe8\xf0\x04\x00\x00H\x8b\x1bH\x85\xdbu\xd5H\x8b\x05F\x19\x00\x00I\x89E\x00L\x89\xe0M\x89l$\x08H\x83\xc4\x08[]A\\A]\xc3\x0f\x1f\x80\x00\x00\x00\x00\xf3\x0f\x1e\xfaSH\x83\xec\x10H\x8bO(L\x8bW\x18H\x85\xc9\x0f\x84\xfe\x01\x00\x00H\x8b\x7f L\x89\xd01\xf6E1\xc0\xeb-\x0f\x1f\x84\x00\x00\x00\x00\x00\x83\xfa\x02\x0f\x85\x7f\x01\x00\x00H\xc7\xc2\x00\x00\x00\x00H\x85\xd2t\x07H\x89\xd6H+p\x10H\x01\xf8H\x83\xe9\x01t\x17\x8b\x10\x83\xfa\x06u\xd4L\x89\xd6H+p\x10H\x01\xf8H\x83\xe9\x01u\xe9M\x85\xc0\x0f\x84\xa3\x01\x00\x00I\x8b@ I\x03p\x10H\x8d\x1d\xfc\x18\x00\x00I\x8bP(H\x895\xf9\x18\x00\x00H\x89\x05\xfa\x18\x00\x00I\x8b@0H\xc7\x05\x83\x18\x00\x00\x01\x00\x00\x00H\x89\x05\xf4\x18\x00\x00H\x89\x1d]\x18\x00\x00H\x01\xd6H\x8dH\xffH\xf7\xdeH!\xceH\x01\xd6H\x8d\x90\xdf\x00\x00\x00H\x895\xc7\x18\x00\x00H\x895\xd0\x18\x00\x00H\x83\xf8\x07w\x15H\xc7\x05\xb7\x18\x00\x00\x08\x00\x00\x00\xba\xe7\x00\x00\x00\xb8\x08\x00\x00\x00H\x01\xd6H\x89\x05#\x18\x00\x00H\x8d=\xbc\x18\x00\x00H\x83\xe6\xf8H\x895\t\x18\x00\x00H\x81\xfeP\x01\x00\x00v!A\xba"\x00\x00\x00E1\xc9\xb8\t\x00\x00\x001\xffI\xc7\xc0\xff\xff\xff\xff\xba\x03\x00\x00\x00\x0f\x05H\x89\xc7\xe82\xfe\xff\xffH\x89\x00fH\x0fn\xc0H\x89\xc7H\x89\xc3f\x0fl\xc0\x0f)\x04$\xe8\x9c\x03\x00\x00\x85\xc0\x0f\x88\xab\x00\x00\x00\x0f\x84\x99\x00\x00\x00\xc7C8\x02\x00\x00\x00\xb8\xda\x00\x00\x00H\x8d=\x96\x19\x00\x00\x0f\x05\x89C0H\x8d\x05\xb2\x17\x00\x00f\x0fo\x0c$H\x89\x83\xa8\x00\x00\x00H\x8d\x83\x88\x00\x00\x00H\x89\x83\x88\x00\x00\x00H\x8b\x05!\x17\x00\x00\x0f\x11K\x10H\x89C H\x83\xc4\x10[\xc3\x0f\x1f\x00\x83\xfa\x07u\x0bI\x89\xc0\xe9\x87\xfe\xff\xff\x0f\x1f\x00\x81\xfaQ\xe5td\x0f\x85x\xfe\xff\xffH\x8bP(D\x8b\r\xc9\x16\x00\x00I9\xd1\x0f\x83d\xfe\xff\xffA\xb9\x00\x00\x80\x00L9\xcaI\x0fG\xd1\x89\x15\xad\x16\x00\x00\xe9L\xfe\xff\xff\xc6\x05\xf9\x16\x00\x00\x01\xe9[\xff\xff\xff\xf4H\x83\xc4\x10[\xc3\x0f\x1fD\x00\x00H\x8b\x15y\x17\x00\x00H\x8b5b\x17\x00\x00H\x8b\x05s\x17\x00\x00\xe9\x81\xfe\xff\xfff.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f@\x00\xf3\x0f\x1e\xfaSH\x85\xfft6H\xc7\xc3\xb86@\x00H\x89\xfe\xba\x08\x00\x00\x00H\x89\xdf\xe8b\x02\x00\x00\xc6C\x01\x00H\x8b\x13dH\x8b\x04%\x00\x00\x00\x00H\x89P([\xc3f\x0f\x1f\x84\x00\x00\x00\x00\x00H\xc7\xc3\xb86@\x00Hi\xc3mN\xc6AH\x89\x03\xeb\xcef.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x00\xf3\x0f\x1e\xfa\xf4\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\xf3\x0f\x1e\xfadH\x8b\x04%\x00\x00\x00\x00H\x83\xc04\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f@\x00\xf3\x0f\x1e\xfaHc\xff\xb8\xe7\x00\x00\x00\x0f\x05\xba<\x00\x00\x00\x0f\x1fD\x00\x00H\x89\xd0\x0f\x05\xeb\xf9\x90\xf3\x0f\x1e\xfa\xb8/p\x00\x00\x89\xf1H\x8dW\x02I\x89\xf8f\x89\x07H\x8d5\x02\x03\x00\x00\xb8\x01\x00\x00\x00\x0f\x1f\x80\x00\x00\x00\x00\x0f\xb6>A\x89\xc1I\x89\xd2\x83\xc0\x01H\x83\xc2\x01H\x83\xc6\x01@\x88z\xff@\x84\xffu\xe3\x89\xca\xbf\xcd\xcc\xcc\xcc\x85\xc9tX\x89\xd2\x83\xc0\x01H\x89\xd6H\x0f\xaf\xd7H\xc1\xea#\x83\xfe\tw\xeb\x89\xc2A\xba\xcd\xcc\xcc\xccA\xc6\x04\x10\x00f\x0f\x1fD\x00\x00\x89\xca\x89\xceD\x8dH\xffI\x0f\xaf\xd2L\x89\xc8H\xc1\xea#\x8d<\x92\x01\xff)\xfe\x83\xc60C\x884\x08\x89\xce\x89\xd1\x83\xfe\tw\xd6\xc3\x0f\x1fD\x00\x00A\x8dA\x02A\xc6\x020A\xc6\x04\x00\x00\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\xf3\x0f\x1e\xfaH\x89\xf9H\x89\xd0@\x0f\xb6\xf6@\xf6\xc7\x07u \xeb*f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\xb6\x119\xf2t H\x83\xc1\x01H\x83\xe8\x01\xf6\xc1\x07t\x0cH\x85\xc0u\xe71\xd2H\x89\xd0\xc3\x901\xd2H\x85\xc0t\xf4\x0f\xb6\x119\xf2tUH\xba\x01\x01\x01\x01\x01\x01\x01\x01Lc\xc6I\xba\xff\xfe\xfe\xfe\xfe\xfe\xfe\xfeI\xb9\x80\x80\x80\x80\x80\x80\x80\x80L\x0f\xaf\xc2H\x83\xf8\x07w\x15\xeb(\x0f\x1fD\x00\x00H\x83\xe8\x08H\x83\xc1\x08H\x83\xf8\x07vBH\x8b\x11L1\xc2J\x8d<\x12H\xf7\xd2H!\xfaL\x85\xcat\xddH\x89\xcaf.\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\xb6\n9\xf1t\x84H\x83\xc2\x01H\x83\xe8\x01u\xef\xe9s\xff\xff\xfff.\x0f\x1f\x84\x00\x00\x00\x00\x00H\x85\xc0u\xce\xe9_\xff\xff\xfff\x0f\x1fD\x00\x00\xf3\x0f\x1e\xfaH\x85\xd2u\x15\xeb%\x0f\x1fD\x00\x00H\x83\xc7\x01H\x83\xc6\x01H\x83\xea\x01t\x12\x0f\xb6\x068\x07t\xeb\x0f\xb6\x07\x0f\xb6\x16)\xd0\xc3f\x901\xc0\xc3H\x89\xf8H\x83\xfa\x08r\x14\xf7\xc7\x07\x00\x00\x00t\x0c\xa4H\xff\xca\xf7\xc7\x07\x00\x00\x00u\xf4H\x89\xd1H\xc1\xe9\x03\xf3H\xa5\x83\xe2\x07t\x05\xa4\xff\xcau\xfb\xc3H\x89\xfe\xbf\x02\x10\x00\x00\xb8\x9e\x00\x00\x00\x0f\x05\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\x90\xf3\x0f\x1e\xfaH\x89\xf8@\xf6\xc7\x07u\x0b\xeb\x19\x90H\x83\xc0\x01\xa8\x07t\x10\x808\x00u\xf3H)\xf8\xc3\x0f\x1f\x80\x00\x00\x00\x00I\xb8\xff\xfe\xfe\xfe\xfe\xfe\xfe\xfeH\x8b\x10H\xbe\x80\x80\x80\x80\x80\x80\x80\x80J\x8d\x0c\x02H\xf7\xd2H!\xcaH\x85\xf2u&f\x90H\x8bP\x08H\x83\xc0\x08J\x8d\x0c\x02H\xf7\xd2H!\xcaH\x85\xf2t\xe9\xeb\x0b\x0f\x1f\x80\x00\x00\x00\x00H\x83\xc0\x01\x808\x00u\xf7H)\xf8\xc3\x0f\x1f\x00\xf3\x0f\x1e\xfaUH\x89\xf2H\x89\xfdSH\x89\xf31\xf6H\x83\xec\x08\xe8\x06\xfe\xff\xffH\x89\xc2H)\xeaH\x85\xc0H\x89\xd8H\x0fE\xc2H\x83\xc4\x08[]\xc3H\x89\xf8H)\xf0H9\xd0\x0f\x83\xf3\xfe\xff\xffH\x89\xd1H\x8d|\x17\xffH\x8dt\x16\xff\xfd\xf3\xa4\xfcH\x8dG\x01\xc3f.\x0f\x1f\x84\x00\x00\x00\x00\x00\xf3\x0f\x1e\xfaPXH\x83\xec\x08\xe8\xd1\xfc\xff\xffPX\xc3/dev/null\x00/proc/self/fd/\x00(U) elfstrip <ELF-file>\n(C) Vladislav Khudash, 2026.\n(I) Extreme ELF-file metadata stripper.\n(P) GitHub: https://github.com/vk-candpython/elfstrip\n(!) Warning: Modifies target file in-place.\x00[-] OSError: open() failed\x00[-] OSError: fstat() failed\x00[!] file size is below minimum ELF threshold\x00[-] OSError: mmap() failed\x00\x7fELF\x00[-] file is not valid ELF binary\x00[-] invalid ELF-file structure\x00[-] ELF-file architecture is not x64\x00[-] unsupported ELF-file type\x00_Unwind_Resume\x00[-] OSError: msync() failed\x00[-] OSError: ftruncate() failed\x00[-] OSError: fsync() failed\x00[+] Stripped: \x00 -> \x00 bytes (-\x00%)\n\x00\x00\x00\x00\x00\x00\x00@\x0c@\x00\x00\x00\x00\x00\x00\x0c@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@4@\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00')


    ok = writef(PATH_ELFSTRIP, dt   )
    os.chmod(   PATH_ELFSTRIP, 0o755)


    del    dt
    return ok




def strip_payload(_fp: bytes) -> None:
    if not make_elfstrip():
        return


    log(color('white', MSG[b'ok_file'] % PATH_ELFSTRIP))
    sp_run((PATH_ELFSTRIP, _fp), capture_output=True)




def c_compile(nm: bytes) -> int:
    sz  = 0
    cmd = (
        CC,
        b'-o', nm,
        PATH_LOADER_C,
        b'-T', PATH_LINK_LD,
        *PARAM
    )


    c = sp_run(cmd, capture_output=True).returncode

    if c == 0:
        log(color('yellow', MSG[b'compile' ])[0 : -1])
        log(color('green',  MSG[b'bar_done']))


        sp_run((PATH_ELFSTRIP, nm), capture_output=True)
        log(color('yellow', MSG[b'elfstrip'])[0 : -1])
        log(color('green',  MSG[b'bar_done']))


        sz = os.stat(nm).st_size
    else:
        log(color('red', MSG[b'fail_compile'] % c))


    del cmd, c
    return sz




def setup(p: bytes, _fp: bytes, psz: int) -> bool:
    _s = time()



    p  = os.path.realpath(p)
    nm = PATH_OUTPUT % os.path.basename(p)

    log(color('yellow', MSG[b'start'] % nm))



    try:
        strip_payload(_fp)

        fd  = os.open(_fp, os.O_RDONLY)
        fsz = os.fstat(fd).st_size

        log(color('yellow', MSG[b'strip_payload'] % (
            psz,  fsz,
            psz - fsz,
            ( 1 - (fsz / psz) ) * 100
        )))


        if fsz > FZLIM:
            log(color('red', MSG[b'fail_sz'] % (p, FZLIM >> 30)), err=True)
            return False
    except OSError:
        log(color('red', MSG[b'fail_open'  ] % p), err=True)
        return False


    try:
        with mmap.mmap(
            fd, fsz,
            prot=mmap.PROT_READ, flags=mmap.MAP_PRIVATE
        ) as mp:
            mp.madvise(mmap.MADV_SEQUENTIAL)



            if mp[0 : 5] != MELF:
                log(color('red', MSG[b'is_not_elf'] % p), err=True)
                return False



            kln  = rand.choice(KSZ)
            key  = mem(rand.token_bytes(kln))
            salt = rand.randbelow(256)


            org_sz = len(mp)

            exz = ( ((org_sz + 125) // 126) * 127 ) + 3
            exe = mem(array(exz))
            exe = compress(mp, org_sz, exe)

            cmp_sz = len(exe)


            log(color('yellow', MSG[b'compress'] % (
                    org_sz,  cmp_sz,
                    org_sz - cmp_sz,
                    ( 1 - (cmp_sz / org_sz) ) * 100
                )
            ))



            exe = enc(exe, key, salt, _rep=True)
            pst = enc(PST, key, salt)
    except OSError:
        log(color('red', MSG[b'fail_mmap'] % p), err=True)
        return False

    finally:
        os.close(fd)



    entry, fmain, section = (
            (gen_chars(),    gen_chars(),  gen_chars()   )
        if FLAG_OBF else
            (mem(b'_start'), mem(b'main'), mem(b'rodata'))
    )



    for (func, path, args) in (
( make_link_ld,  PATH_LINK_LD,  (p, entry, section                       ) ),
( writef,        PATH_PAYLOAD,  (PATH_PAYLOAD, exe                       ) ),
( make_loader_c, PATH_LOADER_C, (p, entry, fmain, section, pst, key, salt) )
    ):
        if func(*args):
            log(color('white', MSG[b'ok_file'  ] % path))
        else:
            log(color('red',   MSG[b'fail_file'] % path), err=True)
            return False



    del kln, key, salt
    del exz, exe, pst
    del entry, fmain, section



    sz = c_compile(nm)
    if sz: log(color('yellow', MSG[b'out'] % (nm, sz)))



    _e = time()
    log(color('green',  MSG[b'end' ] % nm       ))
    log(color('yellow', MSG[b'time'] % (_e - _s)))



    del _s, _e, nm, sz
    gc.collect()
    return True




def make_dir() -> bool:
    try:
        os.makedirs(PATH_DIR, exist_ok=True)
    except OSError:
        log(color('red',    MSG[b'fail_dir'] % PATH_DIR), err=True)
        return False
    else:
        log(color('yellow', MSG[b'ok_dir'  ] % PATH_DIR))
        return True




def cleanup() -> None:
    if not os.path.isdir(PATH_DIR):
        return


    try:
        shutil.rmtree(PATH_DIR)
    except OSError:
        log(color('red',    MSG[b'fail_cleanup'] % PATH_DIR))
    else:
        log(color('yellow', MSG[b'ok_cleanup'  ] % PATH_DIR))




def main() -> int:
    sys.settrace(None)
    sys.setprofile(None)
    gc.set_debug(0)

    gc.disable()
    gc.collect()



    if FLAG_HELP:
        log(color('yellow', MSG[b'info'] % (
                sys.version_info.major,
                os.path.basename(sys.argv[0]).encode()
            )
        ))
        sys.exit(0)

    elif not _argv:
        log(color('red', MSG[b'prev']))
        sys.exit(1)

    else:
        MSG.pop(b'info')
        log(mem(b'\n'))



    arch = mem(machine().encode().lower())

    if arch in X64:
        log(color('green', MSG[b'valid_arch'] % arch))
    else:
        log(color('red',   MSG[b'fail_arch']  % arch), err=True)
        sys.exit(1)

    del arch



    if CC:
        log(color('green', MSG[b'use_compiler' ] % CC))
    else:
        log(color('red',   MSG[b'fail_compiler'] % mem(b'musl-gcc, gcc')))
        sys.exit(1)



    if FLAG_OBF:   log(color('green', MSG[b'use_flag'] % b'OBFUSCATION'))
    if FLAG_DEBUG: log(color('green', MSG[b'use_flag'] % b'ANTI-DEBUG' ))
    if FLAG_VM:    log(color('green', MSG[b'use_flag'] % b'ANTI-VM'    ))



    sep = mem(b'\n\n\n')
    log(sep)

    if not make_dir():
        sys.exit(1)

    log(sep)



    _fp = PATH_PAYLOAD
    ok  = 0

    try:
        for p in _argv:
            p = p.encode()


            try:
                psz = os.stat(p).st_size
                shutil.copy2(p, _fp)
            except OSError:
                log(color('red', MSG[b'fail_open'] % p), err=True)
                log(sep)
                continue


            log(color('yellow', MSG[b'sproc'] % p))

            try:
                if not setup(p, _fp, psz): ok = 1
            except KeyboardInterrupt:
                log(sep)
                break

            except Exception as er:
                log(color('red', MSG[b'error'] % (
                        type(er).__name__.encode(),
                        str(er).encode()
                    )
                ))

            log(color('yellow', MSG[b'eproc'] % p))
            log(sep)
    finally:
        cleanup()
        log(mem(b'\n'))
        gc.collect()
        sys.exit(ok)




if __name__ == '__main__': main()
