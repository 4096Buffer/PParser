# PE Parser

A Windows PE (Portable Executable) file parser written in C++ as a cybersecurity learning project.

## Features

- DOS Header and NT Headers validation
- Section enumeration (name, virtual size, virtual address, raw offset)
- x86 disassembly of the `.text` section using Capstone
- Import table parsing (imported DLLs)

## Requirements

- MinGW-w64 (`x86_64-w64-mingw32-g++`)
- [Capstone](https://github.com/capstone-engine/capstone) compiled for MinGW (x86_64)

## Building

Place `libcapstone.a` and `include/` next to `main.cpp`, then run:

```bash
bash compile.bash
```

## Usage

Run `parser.exe` and enter the path to a PE file when prompted:

```
Pass a filename of the PE: sample.exe
```