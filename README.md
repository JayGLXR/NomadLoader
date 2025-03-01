# NomadLoader

NomadLoader is an advanced, Rust-based utility for converting Windows Portable Executable (PE) files to position-independent code (PIC) shellcode. It enables executable content to be executed from any memory location without requiring traditional loading or relocation.

![NomadLoader](https://github.com/user-attachments/assets/3e4fffc7-54d8-482e-ac73-b15504e03a06)


## Features

- **PE to Shellcode Conversion**: Transform standard EXE and DLL files into position-independent code that can run from any memory location
- **Multi-Stage Loading**: Tiered loading with increasingly sophisticated techniques for improved stealth and evasion
- **Just-In-Time IAT Patching**: Resolve imports only when needed to reduce initial detection surface and improve runtime behavior
- **Command-Line Encryption**: Securely pass parameters to the loaded PE file with configurable encryption strength
- **PE Header Obfuscation**: Minimize PE signatures in memory to evade detection
- **NOP-Like Instruction Substitution**: Replace standard NOPs with equivalent, less detectable instructions for improved stealth

## Project Status

This project is in active development. The current implementation includes:

- ✅ PE file parsing and analysis (supports both 32-bit and 64-bit PE formats)
- ✅ PE dumping from memory (EXE) and disk (DLL)
- ✅ Basic shellcode generation with assembly templating
- ✅ Command-line interface with multiple operation modes

Coming soon:
- ⏳ Advanced multi-stage loading with encryption
- ⏳ Just-in-time IAT patching for dynamic import resolution
- ⏳ Command-line encryption with multiple security levels
- ⏳ Full shellcode execution functionality

## How It Works

NomadLoader operates in three main stages:

1. **PE Dumping**: Extracts PE files from either memory (for EXEs) or disk (for DLLs), preserving critical structures and sections.

2. **Shellcode Generation**: Transforms the dumped PE data into executable shellcode with these components:
   - Assembly stub that handles dynamic loading, relocation, and IAT resolution
   - Optional obfuscation for PE headers and sensitive data
   - Support for multi-stage loading with encryption
   - Command-line argument handling

3. **Execution**: Loads and executes the generated shellcode in memory, optionally with encrypted command-line parameters.

## Usage

NomadLoader provides a command-line interface with several subcommands:

### Dumping PE Files

```bash
NomadLoader dump -i /path/to/input.exe -o /path/to/output.bin
```

This extracts the PE file from memory (EXE) or disk (DLL) in a format suitable for shellcode conversion.

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

This generates shellcode and executes it immediately. The `--wait` flag pauses execution until user confirmation.

## Building from Source

### Prerequisites

- Rust 1.65 or newer
- Cargo package manager
- Windows-based development environment (for full functionality testing)

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

The release binary will be available at `target/release/NomadLoader`.

## Technical Architecture

NomadLoader consists of several specialized modules:

### PE Module
- Parses PE file headers, sections, imports, and relocations
- Supports both 32-bit and 64-bit PE formats
- Provides utilities for RVA-to-offset conversion and memory mapping

### Dumper Module
- **ExeDumper**: Creates a suspended process to extract PE data from memory
- **DllDumper**: Memory-maps DLL files to extract PE data directly
- Handles section alignment and memory requirements calculations

### Generator Module
- Creates assembly stubs with Keystone Engine for loading PE in memory
- Implements templating for dynamic code generation
- Supports various obfuscation techniques for generated shellcode

### IAT Module
- Provides just-in-time import resolution via function trampolines
- Maintains a shadow IAT for tracking resolved imports
- Prioritizes critical imports for PE loading

### Stages Module
- Implements multi-stage loading with encryption
- Supports multiple encryption algorithms (XOR, AES-256, ChaCha20-Poly1305)
- Configurable anti-analysis features

### Cmdline Module
- Encrypts command-line arguments for secure parameter passing
- Hooks PEB to hide command-line from memory inspection tools
- Supports multiple encryption levels

### Executor Module
- Loads and executes shellcode in memory
- Provides memory allocation and permission setting
- Manages thread creation and cleanup

## Security Considerations

NomadLoader is a security research tool designed for legitimate security testing and research purposes only. Ensure you have proper authorization before using this tool on any system.

The techniques implemented in this tool, such as PE loading and shellcode generation, have legitimate uses in security research, red team operations, and software prototyping. However, they can also be misused. Use responsibly and ethically.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The Rust community for excellent libraries and tools
- Security researchers who have documented PE file format and shellcode techniques
