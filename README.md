# 👾 pyelfpacker


<div align="center">

[![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-Python%203-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*Military‑grade ELF obfuscation — Compress, Encrypt, Polymorph, Fileless Execute*

</div>

---

> [!WARNING]
> This tool is intended for educational purposes and authorized security auditing only.  
> The author is not responsible for any misuse or damage caused by this software.

---

## 📖 Table of Contents | Оглавление

- [English](#english)
  - [📋 Overview](#-overview)
  - [✨ Features](#-features)
  - [🔒 Complete Protection Pipeline](#-complete-protection-pipeline)
  - [🚀 Quick Start](#-quick-start)
  - [⚙️ Deep Technical Analysis](#️-deep-technical-analysis)
  - [📁 Output](#-output)
  - [⚠️ Requirements](#️-requirements)
  - [🔧 Troubleshooting](#-troubleshooting)

- [Русский](#русский)
  - [📋 Обзор](#-обзор)
  - [✨ Возможности](#-возможности)
  - [🔒 Полный конвейер защиты](#-полный-конвейер-защиты)
  - [🚀 Быстрый старт](#-быстрый-старт)
  - [⚙️ Глубокий технический анализ](#️-глубокий-технический-анализ)
  - [📁 Результат](#-результат)
  - [⚠️ Требования](#️-требования)
  - [🔧 Устранение неполадок](#-устранение-неполадок)

---

# English

## 📋 Overview

**PyELFPacker** — is a powerful ELF binary obfuscation and packing tool that transforms standard Linux executables into heavily protected, self-decrypting binaries with fileless execution capabilities. Written in Python, it leverages a custom C stub, RLE compression, XOR stream cipher, and a built‑in `elfstrip` to produce extremely stripped “ghost” binaries.

### What makes it unique?

| Component | Implementation |
|-----------|----------------|
| **Single‑pass RLE Compression** | Byte‑level run‑length encoding with 0x80 flag – typical 30–60% size reduction |
| **XOR Stream Cipher** | 16–128 byte key + salt + feedback mechanism – each byte depends on previous state |
| **Polymorphic C Stub** | Random identifier names from 129‑char alphabet (Latin + Cyrillic + Ukrainian) per build |
| **Dead Code Injection** | 150+ combinatorial ASM patterns + random C junk statements (enabled via `--obf`) |
| **Embedded elfstrip** | Pre‑compiled `elfstrip` binary embedded in the Python script – removes section headers |
| **Polyglot Signatures** | 27 different file format headers injected into the linker script |
| **Fileless Execution** | `memfd_create` + `execveat` with `AT_EMPTY_PATH` – zero disk trace |
| **Anti‑Debug & Anti‑VM** | TracerPid check, `PR_SET_PTRACER`, `PR_SET_DUMPABLE`, mlockall, **CPUID hypervisor detection** |
| **Memory Protection** | mlockall + F_SEAL_ALL – prevents swapping and memory modification |
| **Highly Optimised Builder** | Memoryviews, pre‑allocated buffers, single‑pass compression, GC control |

## ✨ Features

### Core Protection

| Feature | Description |
|---------|-------------|
| 🗜️ **RLE Compression** | Byte‑level RLE with 0x80 repeat flag, typical 30‑60% reduction |
| 🔐 **XOR Stream Cipher** | Salt + key mutation with feedback – non‑linear encryption |
| 🎲 **Polymorphic Stub** | Random function/variable names from 129‑char alphabet (Latin + Cyrillic + Ukrainian) |
| 📝 **Dead ASM Injection** | 25+ patterns (nop, pause, clc, xor, lea, push/pop, etc.) + register combinations |
| 🔧 **Dead C Injection** | Random junk statements in SYSCALL macro, ANTIDEBUG, and loader body |

### Compilation & Linking

| Feature | Description |
|---------|-------------|
| 🏗️ **MUSL/GCC Auto‑detect** | Prefers MUSL (smaller output), falls back to GCC |
| 📦 **Custom Linker Script** | Random base address (0x400000 + random*0x1000), discards unused sections |
| 🚫 **Compiler Flags** | `-O3 -static-pie -fomit-frame-pointer -fno-stack-protector -Wl,--strip-all` |
| 🧹 **ELFSTRIP** | Embedded `elfstrip` – removes section headers completely, breaks `objdump`, `readelf`, `gdb` |

### Runtime Protection

| Feature | Description |
|---------|-------------|
| 💾 **Fileless Execution** | `memfd_create` → write → seal → `execveat` with `AT_EMPTY_PATH` |
| 🛡️ **Anti‑Debug** | Parses `/proc/self/status` for `TracerPid` (obfuscated string in binary) |
| 🔒 **PTRACE Block** | `prctl(PR_SET_PTRACER, 0)` – only children can ptrace |
| 🚫 **No New Privs** | `prctl(PR_SET_NO_NEW_PRIVS, 1)` – prevents setuid escalation |
| 📵 **No Core Dumps** | `prctl(PR_SET_DUMPABLE, 0)` – blocks gcore and coredumps |
| 🔐 **Memory Lock** | `mlockall(MCL_ALL)` – prevents swapping to disk |
| 🔏 **Sealed Memory FD** | `fcntl(F_ADD_SEALS, F_SEALS_ALL)` – prevents modification before exec |
| 🛡️ **Anti‑VM** | **CPUID hypervisor bit check** (ECX bit 31) – detects virtualization, triggers exit when set |

### Polyglot Signatures (27 formats)

| Signature | Format |
|-----------|--------|
| `\x7FELF` | ELF (native) |
| `MZ` + `PE` | Windows PE |
| `\x89PNG` | PNG Image |
| `%PDF` | PDF Document |
| `PK\x03\x04` | ZIP Archive |
| `\x1F\x8B` | GZIP |
| `\xFD\x37\x7A\x58\x5A` | XZ/LZMA |
| `\x21\x3C\x61\x72\x63\x68\x3E` | AR Archive |
| `\xCA\xFE\xBA\xBE` | Mach‑O (32‑bit) |
| `\xCF\xFA\xED\xFE` | Mach‑O (64‑bit) |
| `#!/bin/bash` | Shell Script |
| `UPX!` | UPX Packer |
| `\xFF\xD8\xFF\xE0` | JPEG |
| `BM` | BMP |
| `ID3` | MP3 |
| `ftypisom` | MP4 |
| `SQLite format 3` | SQLite |
| `\xD0\xCF\x11\xE0` | MS Office |
| `\x00\x61\x73\x6D` | WebAssembly |
| `\xFE\xED\xFA\xCE` | Mach‑O (32‑bit, alternative) |
| `\xBE\xBA\xFE\xCA` | Java Class |
| `\x99\x01` | DOS COM |
| `\x00\x01\x00\x00` | TrueType Font |
| `<?xml` | XML |
| `<!DOCTYPE` | HTML |
| `\x25\x21` | PostScript |
| `\x3C\x3F\x78\x6D\x6C` | XML Declaration |

## 🔒 Complete Protection Pipeline

```
PHASE 1: ELF VALIDATION
├── Checks ELF magic (\x7FELF\x02)
├── Validates x86_64 architecture
└── Memory‑maps file with MADV_SEQUENTIAL

PHASE 2: RLE COMPRESSION
├── Flag byte: 0x00-0x7F = literal run, 0x80-0xFF = repeat run
├── Minimum repeat threshold: 3 identical bytes
├── Maximum literal run: 126 bytes
└── Output buffer: exact pre‑allocation

PHASE 3: XOR STREAM ENCRYPTION
├── Key: 16-128 random bytes + random salt (0-255)
├── State: i = (x ^ ((y << 1) ^ (i >> 1))) & 0xFF
├── Operations: XOR → rotate left 3 → add (y ^ 0xA5)
└── /proc/self/status string also encrypted

PHASE 4: POLYMORPHIC LOADER GENERATION
├── Random identifiers: 4-254 chars, 129‑char alphabet
├── Obfuscated constants: XORed and shifted syscall numbers
├── Random dead code: 150+ ASM patterns, 11 junk per SYSCALL macro
└── Unique linker script: random base address + random polyglot signature

PHASE 5: C COMPILATION
├── Compiler: MUSL (preferred) or GCC
├── 20+ aggressive compiler flags for size and stealth
└── Custom linker script with discarded sections

PHASE 6: ELFSTRIP
├── Embedded pre‑compiled elfstrip binary (~13 KB)
├── Truncates section header table
└── Result: "ghost" ELF — runs but has no visible sections
```

## 🚀 Quick Start

### 📥 Download

```bash
git clone https://github.com/vk-candpython/pyelfpacker.git
cd pyelfpacker
```

### 📦 Requirements

```bash
# Install MUSL (recommended for smaller output)
sudo apt install musl-tools    # Debian/Ubuntu
sudo pacman -S musl            # Arch

# Or use GCC (auto‑detected)
sudo apt install gcc
```

### 🏃 Usage

```bash
python3 pyelfpacker.py [--obf] [--debug] [--vm] <elf1> [elf2 ...]
```

**Example:**
```bash
python3 pyelfpacker.py --obf --debug /bin/ls
```

**Output:**
```
(C) Vladislav Khudash, 2026
(P) GitHub: https://github.com/vk-candpython/pyelfpacker
(!) Only for x64 Linux

(Usage): python3 pyelfpacker.py <elf1> [elf2 ...]

[  OK  ]: architecture is valid (x86_64)
[  OK  ]: using compiler(/usr/bin/gcc)
[  OK  ]: using flag(OBFUSCATION)
[  OK  ]: using flag(ANTI-DEBUG)

[  OK  ]: make build dir(./_mk_pyelfpacker-...)

[ INFO ]: Start processing -> /bin/ls
[ INFO ]: building ELF(./pyelfpacker-ls)
[ INFO ]: compressing: {--------------------} 100%  (DONE)
[  OK  ]: compressed:  (142144 -> 87514) bytes  |  saved: 54630 bytes (38.4%)
[ INFO ]: encrypting:  {--------------------} 100%  (DONE)
[ BUILD ]: file(./_mk_pyelfpacker-.../link.ld)
[ BUILD ]: file(./_mk_pyelfpacker-.../payload.bin)
[ BUILD ]: file(./_mk_pyelfpacker-.../loader.c)
[ BUILD ]: file(./_mk_pyelfpacker-.../elfstrip)
[  OK  ]: compiled  .................  (DONE)
[  OK  ]: stripped  .................  (DONE)
[ INFO ]: time      .................  (2.15s)
[  OK  ]: outfile(./pyelfpacker-ls, 88234 bytes)
[  OK  ]: building completed ELF(./pyelfpacker-ls)
[ INFO ]: End processing -> /bin/ls

[  OK  ]: cleanup build dir(./_mk_pyelfpacker-...)
```

## ⚙️ Deep Technical Analysis

### The SYSCALL Macro (One for ALL)

A single unified macro handles every system call in the loader. Each expansion injects 11 random junk statements (when `--obf` is enabled). The syscall is made via `call` to a trampoline function that contains random dead code before and after the `syscall` instruction. Clobbers `rcx` and `r11` per x86_64 ABI.

### The Syscall Trampoline

A dedicated static function with `.hidden` visibility contains the actual `syscall` instruction, surrounded by random junk ASM. This centralises all syscalls through one obfuscated gate.

### RLE Decompression (Runtime)

The decompressor processes the encrypted payload byte‑by‑byte. Each byte is first decrypted via the `DEC` macro, then interpreted as either a repeat run (0x80 flag set) or literal run. Output is written in 4 KB chunks to the sealed memory file descriptor.

### DEC Macro (Decrypt Single Byte)

The inverse of the encryption function: subtract `(y ^ 0xA5)`, rotate right 3, XOR with derived key and state. The state `g` is updated with a non‑linear feedback function: `g = (b ^ ((y << 1) ^ (i >> 1))) & 0xFF`.

### ANTIDEBUG Macro

The string `/proc/self/status` is encrypted in the binary. The macro decrypts it at runtime, opens the file, and searches for an obfuscated `TracerPid:` pattern (each character XORed with different keys). Returns the TracerPid value: 0 = clean, >0 = debugger detected. All buffers are securely zeroed before return.

### ANTIVM Macro

When the `--vm` flag is enabled, the generated loader includes an anti‑VM check. It executes `CPUID` with EAX=1 and tests bit 31 of ECX (the hypervisor present bit). If this bit is set, the binary immediately exits (or executes a dead‑code exit path). This detection method is fast, lightweight, and does not rely on parsing `/proc` or other easily spoofed indicators.

### Fileless Execution

The payload is decrypted and decompressed directly into a memory file descriptor created via `memfd_create`. The fd is then sealed with `F_SEAL_ALL` to prevent any modification before execution via `execveat` with `AT_EMPTY_PATH`.

### ZEROS Macro (Secure Memory Wipe)

Uses `rep stosq` in reverse direction (DF=1) to zero sensitive buffers. Reverse direction makes memory forensics recovery harder.

### Dead Code Injection Patterns

25+ base ASM patterns combined with 10 registers generate 150+ unique dead code combinations at build time. Additionally, the C code is peppered with random statements between every meaningful line.

### Builder Optimisations

| Optimisation | Implementation |
|--------------|----------------|
| **Memoryviews** | Zero‑copy slicing, no intermediate allocations |
| **Pre‑allocated Buffers** | Exact size calculation for RLE output |
| **MADV_SEQUENTIAL** | Hint kernel for sequential access |
| **Chunked I/O** | 4 KB chunks for large files |
| **Pre‑compiled elfstrip** | Embedded as bytes, written once per session |
| **Single‑pass Compression** | RLE compresses in one pass |
| **In‑place Encryption** | XOR modifies buffer directly |
| **GC Control** | `gc.disable()` + manual `gc.collect()` |
| **Colour Output Caching** | Memoised ANSI colour codes |

## 📁 Output

```
original_elf  →  pyelfpacker-original_elf
```

**Output binary properties:**
- Stripped of all symbols and section headers
- Contains encrypted payload in a `.rodata`‑like section
- Executes entirely from memory
- Leaves no traces on disk (except the binary itself)
- Typically **30–60% smaller** than original

## ⚠️ Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.6+ | Required for builder |
| **MUSL-GCC** | Any | Recommended (smaller output) |
| **GCC** | Any | Fallback |
| **Linux Kernel** | 3.17+ | For `memfd_create` |
| **Linux Kernel** | 3.19+ | For `execveat` |
| **Architecture** | x86_64 | Only 64‑bit |

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `Cannot determine architecture` | Only x86_64 supported |
| `No suitable compiler found` | Install `musl-tools` or `gcc` |
| `compilation failed` | Check compiler; try GCC if MUSL fails |
| `execveat: Function not implemented` | Kernel < 3.19 |
| `memfd_create: Function not implemented` | Kernel < 3.17 |
| Obfuscated binary segfaults | Original may need dynamic libraries |
| `gdb` still attaches | Use `PR_SET_PTRACER` + TracerPid |
| Binary size increased | Normal for very small binaries |
| `--vm` flag causes exit in VM | Anti‑VM detection triggers; run on physical hardware |

---

# Русский

## 📋 Обзор

**PyELFPacker** — мощный инструмент для обфускации и упаковки ELF‑бинарников, превращающий стандартные исполняемые файлы Linux в сильно защищённые, саморасшифровывающиеся программы с бесфайловым выполнением. Написан на Python, использует кастомный C‑стаб, RLE‑сжатие, потоковый XOR‑шифр и встроенный `elfstrip` для создания «призрачных» бинарников без заголовков секций.

### Что делает его уникальным?

| Компонент | Реализация |
|-----------|------------|
| **Однопроходное RLE‑сжатие** | Побайтовое кодирование с флагом 0x80 – типичное сжатие 30–60% |
| **Потоковый XOR‑шифр** | Ключ 16–128 байт + соль + обратная связь – каждый байт зависит от предыдущих |
| **Полиморфный C‑стаб** | Случайные имена из 129‑символьного алфавита (латиница + кириллица + украинский) |
| **Впрыск мёртвого кода** | 150+ комбинаторных ASM‑паттернов + случайный мусор в C (включается через `--obf`) |
| **Встроенный elfstrip** | Предскомпилированный бинарник `elfstrip` встроен в Python‑скрипт – удаляет заголовки секций |
| **Полиглот‑сигнатуры** | 27 различных заголовков форматов файлов |
| **Бесфайловое выполнение** | `memfd_create` + `execveat` с `AT_EMPTY_PATH` – нулевой след на диске |
| **Анти‑отладка & Анти‑VM** | Проверка TracerPid, `PR_SET_PTRACER`, `PR_SET_DUMPABLE`, mlockall, **обнаружение гипервизора через CPUID** |
| **Защита памяти** | mlockall + F_SEAL_ALL – предотвращает свопинг и модификацию памяти |
| **Оптимизированный билдер** | Memoryviews, предварительно выделенные буферы, однопроходное сжатие, контроль GC |

## ✨ Возможности

### Основная защита

| Возможность | Описание |
|-------------|----------|
| 🗜️ **RLE‑сжатие** | Побайтовое RLE с флагом 0x80, типичное сжатие 30–60% |
| 🔐 **Потоковый XOR‑шифр** | Соль + мутация ключа с обратной связью – нелинейное шифрование |
| 🎲 **Полиморфная заглушка** | Случайные имена из 129‑символьного алфавита (латиница + кириллица + украинский) |
| 📝 **Впрыск мёртвого ASM** | 25+ паттернов + комбинации с 10 регистрами = 150+ вариантов |
| 🔧 **Впрыск мёртвого C** | Случайный мусор в макросе SYSCALL, ANTIDEBUG и теле загрузчика |

### Компиляция и линковка

| Возможность | Описание |
|-------------|----------|
| 🏗️ **Автовыбор MUSL/GCC** | Предпочитает MUSL (меньший размер), откат к GCC |
| 📦 **Кастомный линкер‑скрипт** | Случайный базовый адрес, сбрасывает все неиспользуемые секции |
| 🚫 **Флаги компилятора** | `-O3 -static-pie -fomit-frame-pointer -fno-stack-protector -Wl,--strip-all` |
| 🧹 **ELFSTRIP** | Встроенный `elfstrip` – полное удаление заголовков секций, ломает `objdump`, `readelf`, `gdb` |

### Защита времени выполнения

| Возможность | Описание |
|-------------|----------|
| 💾 **Бесфайловое выполнение** | `memfd_create` → запись → seal → `execveat` с `AT_EMPTY_PATH` |
| 🛡️ **Анти‑отладка** | Парсинг `/proc/self/status` для `TracerPid` (строка зашифрована в бинарнике) |
| 🔒 **Блокировка PTRACE** | `prctl(PR_SET_PTRACER, 0)` – только потомки могут трассировать |
| 🚫 **Запрет новых привилегий** | `prctl(PR_SET_NO_NEW_PRIVS, 1)` |
| 📵 **Запрет core‑дампов** | `prctl(PR_SET_DUMPABLE, 0)` |
| 🔐 **Блокировка памяти** | `mlockall(MCL_ALL)` |
| 🔏 **Запечатанный memory FD** | `fcntl(F_ADD_SEALS, F_SEALS_ALL)` |
| 🛡️ **Анти‑VM** | **Проверка бита гипервизора CPUID** (ECX бит 31) – обнаружение виртуализации, выход при обнаружении |

## 🔒 Полный конвейер защиты

*(См. английскую версию для подробной диаграммы)*

## 🚀 Быстрый старт

```bash
git clone https://github.com/vk-candpython/pyelfpacker.git
cd pyelfpacker
python3 pyelfpacker.py --obf --debug /bin/ls
./pyelfpacker-ls
```

## ⚙️ Глубокий технический анализ

### Макрос SYSCALL (Один на ВСЕ)

Единый унифицированный макрос обрабатывает каждый системный вызов в загрузчике. Каждое раскрытие впрыскивает 11 случайных мусорных инструкций (при включённом `--obf`). Системный вызов делается через `call` к функции‑трамплину, которая содержит случайный мёртвый код до и после инструкции `syscall`.

### RLE‑распаковка (во время выполнения)

Распаковщик обрабатывает зашифрованные данные побайтово. Каждый байт сначала расшифровывается через макрос `DEC`, затем интерпретируется как повторяющаяся серия (флаг 0x80) или литеральная серия. Вывод пишется чанками по 4 КБ в запечатанный файловый дескриптор в памяти.

### Макрос DEC (Расшифровка одного байта)

Обратная функция шифрования: вычитание `(y ^ 0xA5)`, поворот вправо на 3, XOR с производным ключом и состоянием. Состояние `g` обновляется нелинейной функцией с обратной связью: `g = (b ^ ((y << 1) ^ (i >> 1))) & 0xFF`.

### Макрос ANTIDEBUG

Строка `/proc/self/status` зашифрована в бинарнике. Макрос расшифровывает её во время выполнения, открывает файл и ищет обфусцированный паттерн `TracerPid:` (каждый символ XOR с разными ключами). Возвращает значение TracerPid: 0 = чисто, >0 = обнаружен отладчик. Все буферы безопасно затираются перед возвратом.

### Макрос ANTIVM

При включении флага `--vm` в генерируемый загрузчик добавляется проверка на виртуальную машину. Она выполняет инструкцию `CPUID` с EAX=1 и проверяет бит 31 регистра ECX (бит присутствия гипервизора). Если этот бит установлен, бинарник немедленно завершается (или выполняет путь выхода с мёртвым кодом). Этот метод быстр, лёгок и не полагается на парсинг `/proc` или другие легко подделываемые индикаторы.

### Бесфайловое выполнение

Полезная нагрузка расшифровывается и распаковывается напрямую в файловый дескриптор в памяти, созданный через `memfd_create`. Затем fd запечатывается с `F_SEAL_ALL` для предотвращения любых модификаций перед выполнением через `execveat` с `AT_EMPTY_PATH`.

### Макрос ZEROS (Безопасное затирание памяти)

Использует `rep stosq` в обратном направлении (DF=1) для затирания чувствительных буферов. Обратное направление усложняет восстановление memory forensics.

### Оптимизации билдера

| Оптимизация | Реализация |
|-------------|------------|
| **Memoryviews** | Zero‑copy слайсинг |
| **Предвыделенные буферы** | Точный расчёт размера для RLE |
| **MADV_SEQUENTIAL** | Подсказка ядру о последовательном доступе |
| **Чанковый I/O** | Блоки по 4 КБ для больших файлов |
| **Предскомпилированный elfstrip** | Встроен как байты, записывается один раз |
| **Однопроходное сжатие** | RLE сжимает за один проход |
| **Шифрование на месте** | XOR модифицирует буфер напрямую |
| **Контроль GC** | `gc.disable()` + ручной `gc.collect()` |
| **Кеширование цветов** | Мемоизация ANSI‑кодов |

## 📁 Результат

```
оригинальный_elf  →  pyelfpacker-оригинальный_elf
```

## ⚠️ Требования

| Требование | Версия | Примечания |
|------------|--------|------------|
| **Python** | 3.6+ | Для билдера |
| **MUSL-GCC** | Любая | Рекомендуется |
| **GCC** | Любая | Запасной |
| **Ядро Linux** | 3.17+ | Для `memfd_create` |
| **Ядро Linux** | 3.19+ | Для `execveat` |
| **Архитектура** | x86_64 | Только 64‑бит |

## 🔧 Устранение неполадок

| Проблема | Решение |
|----------|---------|
| `Cannot determine architecture` | Только x86_64 |
| `No suitable compiler found` | Установи `musl-tools` или `gcc` |
| `compilation failed` | Проверь компилятор |
| `execveat: Function not implemented` | Ядро < 3.19 |
| `memfd_create: Function not implemented` | Ядро < 3.17 |
| Обфусцированный бинарник падает | Оригинал может требовать динамические библиотеки |
| `gdb` всё ещё цепляется | Используй `PR_SET_PTRACER` + TracerPid |
| Размер бинарника увеличился | Нормально для очень маленьких бинарников |
| Флаг `--vm` вызывает выход в VM | Срабатывает анти‑VM детекция; запускай на физическом железе |

---

<div align="center">

**[⬆ Back to Top](#-pyelfpacker)**

*ELF Obfuscation for Linux*

</div>
