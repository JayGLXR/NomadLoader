# NomadLoader

NomadLoader is an advanced utility for converting Windows Portable Executable (PE) files to position-independent code (PIC) shellcode. It enables executable content to be executed from any memory location without requiring traditional loading or relocation.

## Features

- **PE to Shellcode Conversion**: Transform standard EXE and DLL files into position-independent code
- **Multi-Stage Loading**: Tiered loading with increasingly sophisticated techniques for improved stealth
- **Just-In-Time IAT Patching**: Resolve imports only when needed to reduce initial detection surface
- **Command-Line Encryption**: Securely pass parameters to the loaded PE file
- **PE Header Obfuscation**: Minimize PE signatures in memory
- **NOP-Like Instruction Substitution**: Replace standard NOPs with equivalent, less detectable instructions

## Project Status

This project is in active development. The current implementation includes:

- ✅ PE file parsing and analysis
- ✅ PE dumping from memory (EXE) and disk (DLL)
- ✅ Basic shellcode generation
- ✅ Command-line interface

Coming soon:
- ⏳ Advanced multi-stage loading
- ⏳ Just-in-time IAT patching
- ⏳ Command-line encryption

## Usage

NomadLoader provides a command-line interface with several subcommands:

### Dumping PE Files

```bash
NomadLoader dump -i /path/to/input.exe -o /path/to/output.bin
```

This extracts the PE file from memory or disk in a format suitable for shellcode conversion.

### Generating Shellcode

```bash
NomadLoader generate -i /path/to/input.bin -o /path/to/output.bin --obfuscate --multi-stage
```

Available options:

- `--obfuscate`: Enable PE header obfuscation
- `--multi-stage`: Enable multi-stage loading
- `--jit-imports`: Enable just-in-time IAT patching
- `--encrypt-cmdline`: Enable command line encryption
- `--encryption-level N`: Set encryption strength (1-3)
- `-c, --cmdline "string"`: Specify command line arguments to pass to the PE

### Executing Shellcode

```bash
NomadLoader execute -i /path/to/input.bin -c "command line arguments" --wait
```

This generates shellcode and executes it immediately.

## Building from Source

### Prerequisites

- Rust 1.65 or newer
- Cargo package manager
- Windows-based development environment (for testing)

### Build Steps

1. Clone the repository
   ```
   git clone https://github.com/jayglxr/NomadLoader.git
   cd NomadLoader
   ```

2. Build the project
   ```
   cargo build --release
   ```

3. Run tests
   ```
   cargo test
   ```

## Architecture

NomadLoader consists of several modules:

- **PE Module**: Parse and manipulate PE files
- **Dumper Module**: Extract PE files from memory/disk
- **Generator Module**: Generate shellcode from PE files
- **Stages Module**: Implement multi-stage loading
- **IAT Module**: Provide just-in-time IAT patching
- **Cmdline Module**: Handle command-line encryption
- **Executor Module**: Execute generated shellcode

## Security Considerations

NomadLoader is a security research tool designed for legitimate security testing and research purposes only. Ensure you have proper authorization before using this tool on any system.

## License

This project is licensed under the MIT License - see the LICENSE file for details.