//! Just-in-time IAT patching implementation
//!
//! This module provides the implementation for just-in-time IAT patching.

use crate::iat::{IatError, Result, IatConfig, ImportFunction};
use crate::pe::PeFile;
use log::{debug, info, warn};
use std::collections::HashMap;

/// JIT IAT patcher
pub struct JitPatcher {
    config: IatConfig,
    shadow_iat: HashMap<u32, ImportFunction>,
}

impl JitPatcher {
    /// Create a new JIT patcher with default configuration
    pub fn new() -> Self {
        Self {
            config: IatConfig::default(),
            shadow_iat: HashMap::new(),
        }
    }
    
    /// Create a new JIT patcher with custom configuration
    pub fn with_config(config: IatConfig) -> Self {
        Self {
            config,
            shadow_iat: HashMap::new(),
        }
    }
    
    /// Initialize the shadow IAT from a PE file
    pub fn init_from_pe(&mut self, pe: &PeFile) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        info!("Initializing JIT IAT patcher");
        
        // Clear any existing shadow IAT
        self.shadow_iat.clear();
        
        // Process each import descriptor
        for import in &pe.imports {
            let dll_name = import.dll_name.clone();
            
            // Process import entries
            for (i, entry) in import.entries.iter().enumerate() {
                let iat_rva = import.first_thunk + (i as u32 * 8); // 8 bytes per entry for 64-bit
                
                // Create import function info
                let import_func = match entry {
                    crate::pe::ImportEntry::ByName { hint, name } => {
                        ImportFunction {
                            dll_name: dll_name.clone(),
                            function_name: Some(name.clone()),
                            ordinal: None,
                            iat_rva,
                            original_value: 0, // Will be set at runtime
                            resolved: false,
                            resolved_address: None,
                        }
                    },
                    crate::pe::ImportEntry::ByOrdinal { ordinal } => {
                        ImportFunction {
                            dll_name: dll_name.clone(),
                            function_name: None,
                            ordinal: Some(*ordinal),
                            iat_rva,
                            original_value: 0, // Will be set at runtime
                            resolved: false,
                            resolved_address: None,
                        }
                    },
                };
                
                // Add to shadow IAT
                self.shadow_iat.insert(iat_rva, import_func);
                
                debug!("Added import: {} @ RVA 0x{:X}", 
                       import_func.function_name.as_ref().unwrap_or(&format!("Ordinal#{}", 
                       import_func.ordinal.unwrap_or(0))), 
                       iat_rva);
            }
        }
        
        info!("JIT IAT patcher initialized with {} imports", self.shadow_iat.len());
        
        Ok(())
    }
    
    /// Generate assembly code for the JIT IAT patcher trampoline
    pub fn generate_trampolines(&self) -> Result<String> {
        if !self.config.enabled || self.shadow_iat.is_empty() {
            return Ok(String::new());
        }
        
        info!("Generating JIT IAT patcher trampolines");
        
        let mut asm = String::new();
        
        // Add data section for the shadow IAT
        asm.push_str("# Shadow IAT data section\n");
        asm.push_str("shadow_iat_data:\n");
        
        // For each import, create a shadow IAT entry
        for (rva, import) in &self.shadow_iat {
            asm.push_str(&format!("    # Import: {}\n", 
                import.function_name.as_ref().unwrap_or(&format!("Ordinal#{}", 
                import.ordinal.unwrap_or(0)))));
            asm.push_str(&format!("    .quad 0x{:X}  # RVA\n", rva));
            asm.push_str("    .quad 0x0  # Resolved address (to be filled at runtime)\n");
            asm.push_str("    .quad 0x0  # Flags\n");
            
            // DLL name
            asm.push_str(&format!("    .asciz \"{}\"  # DLL name\n", import.dll_name));
            
            // Function name or ordinal
            if let Some(name) = &import.function_name {
                asm.push_str(&format!("    .asciz \"{}\"  # Function name\n", name));
            } else if let Some(ordinal) = import.ordinal {
                asm.push_str(&format!("    .word 0x{:X}  # Ordinal\n", ordinal));
                asm.push_str("    .word 0x0  # Padding\n");
            }
        }
        
        // Add the JIT trampoline code
        asm.push_str("\n# JIT IAT resolver trampoline\n");
        asm.push_str("jit_trampoline:\n");
        asm.push_str("    # Save registers\n");
        asm.push_str("    push rax\n");
        asm.push_str("    push rcx\n");
        asm.push_str("    push rdx\n");
        asm.push_str("    push r8\n");
        asm.push_str("    push r9\n");
        asm.push_str("    push r10\n");
        asm.push_str("    push r11\n");
        
        asm.push_str("    # Get the import RVA from the caller\n");
        asm.push_str("    mov rax, [rsp + 56]  # Return address on stack\n");
        asm.push_str("    sub rax, rbx         # Subtract base address to get RVA\n");
        
        asm.push_str("    # Find the import in the shadow IAT\n");
        asm.push_str("    lea rcx, [rip + shadow_iat_data]  # RCX = Shadow IAT base\n");
        asm.push_str("find_import_loop:\n");
        asm.push_str("    cmp dword ptr [rcx], 0  # Check if end of shadow IAT\n");
        asm.push_str("    je import_not_found\n");
        asm.push_str("    cmp dword ptr [rcx], eax  # Compare RVA\n");
        asm.push_str("    je import_found\n");
        asm.push_str("    add rcx, 32  # Move to next entry\n");
        asm.push_str("    jmp find_import_loop\n");
        
        asm.push_str("import_found:\n");
        asm.push_str("    # Check if already resolved\n");
        asm.push_str("    cmp qword ptr [rcx + 8], 0  # Check resolved address\n");
        asm.push_str("    jne use_resolved_address\n");
        
        asm.push_str("    # Load the DLL\n");
        asm.push_str("    lea r8, [rcx + 24]  # R8 = DLL name\n");
        asm.push_str("    sub rsp, 40  # Shadow space + extra for 16-byte alignment\n");
        asm.push_str("    mov rcx, r8  # RCX = DLL name\n");
        asm.push_str("    call LoadLibraryA\n");
        asm.push_str("    add rsp, 40\n");
        asm.push_str("    test rax, rax  # Check if DLL loaded\n");
        asm.push_str("    jz import_error\n");
        
        asm.push_str("    # Save DLL handle\n");
        asm.push_str("    mov rdx, rax  # RDX = DLL handle\n");
        
        asm.push_str("    # Check if import by name or ordinal\n");
        asm.push_str("    test byte ptr [rcx + 16], 1  # Check flag for ordinal\n");
        asm.push_str("    jnz resolve_by_ordinal\n");
        
        asm.push_str("    # Resolve by name\n");
        asm.push_str("    lea r8, [rcx + 40]  # R8 = Function name\n");
        asm.push_str("    sub rsp, 40  # Shadow space for Win64 calling convention\n");
        asm.push_str("    mov rcx, rdx  # RCX = DLL handle\n");
        asm.push_str("    mov rdx, r8   # RDX = Function name\n");
        asm.push_str("    call GetProcAddress\n");
        asm.push_str("    add rsp, 40\n");
        asm.push_str("    jmp save_resolved_address\n");
        
        asm.push_str("resolve_by_ordinal:\n");
        asm.push_str("    # Resolve by ordinal\n");
        asm.push_str("    movzx r8d, word ptr [rcx + 40]  # R8D = Ordinal\n");
        asm.push_str("    sub rsp, 40  # Shadow space for Win64 calling convention\n");
        asm.push_str("    mov rcx, rdx  # RCX = DLL handle\n");
        asm.push_str("    mov rdx, r8   # RDX = Ordinal\n");
        asm.push_str("    call GetProcAddress\n");
        asm.push_str("    add rsp, 40\n");
        
        asm.push_str("save_resolved_address:\n");
        asm.push_str("    # Save resolved address\n");
        asm.push_str("    mov [rcx + 8], rax  # Store in shadow IAT\n");
        asm.push_str("    or dword ptr [rcx + 16], 2  # Set resolved flag\n");
        
        asm.push_str("use_resolved_address:\n");
        asm.push_str("    # Get resolved address\n");
        asm.push_str("    mov rax, [rcx + 8]  # RAX = Resolved address\n");
        
        asm.push_str("    # Restore registers and jump to resolved address\n");
        asm.push_str("    pop r11\n");
        asm.push_str("    pop r10\n");
        asm.push_str("    pop r9\n");
        asm.push_str("    pop r8\n");
        asm.push_str("    pop rdx\n");
        asm.push_str("    pop rcx\n");
        asm.push_str("    pop rax\n");
        asm.push_str("    add rsp, 8  # Remove return address\n");
        asm.push_str("    jmp rax  # Jump to resolved function\n");
        
        asm.push_str("import_not_found:\n");
        asm.push_str("import_error:\n");
        asm.push_str("    # Handle error case - just return\n");
        asm.push_str("    xor rax, rax  # Return NULL\n");
        asm.push_str("    pop r11\n");
        asm.push_str("    pop r10\n");
        asm.push_str("    pop r9\n");
        asm.push_str("    pop r8\n");
        asm.push_str("    pop rdx\n");
        asm.push_str("    pop rcx\n");
        asm.push_str("    pop rax\n");
        asm.push_str("    ret\n");
        
        Ok(asm)
    }
    
    /// Generate code to patch the IAT with trampolines
    pub fn generate_iat_patcher(&self) -> Result<String> {
        if !self.config.enabled || self.shadow_iat.is_empty() {
            return Ok(String::new());
        }
        
        info!("Generating IAT patcher code");
        
        let mut asm = String::new();
        
        asm.push_str("# IAT patcher for JIT resolution\n");
        
        // Add code to patch each IAT entry
        for (rva, import) in &self.shadow_iat {
            // For critical imports, don't use JIT if configured
            let is_critical = if let Some(name) = &import.function_name {
                self.config.critical_functions.contains(name)
            } else {
                false
            };
            
            if is_critical {
                asm.push_str(&format!("    # Critical import: {}\n", 
                    import.function_name.as_ref().unwrap_or(&format!("Ordinal#{}", 
                    import.ordinal.unwrap_or(0)))));
                    
                // Resolve critical imports immediately
                // This would call the standard import resolution logic
                asm.push_str(&format!("    mov rcx, rbx\n"));
                asm.push_str(&format!("    add rcx, 0x{:X}\n", rva));
                asm.push_str(&format!("    call resolve_import\n"));
            } else {
                asm.push_str(&format!("    # JIT import: {}\n", 
                    import.function_name.as_ref().unwrap_or(&format!("Ordinal#{}", 
                    import.ordinal.unwrap_or(0)))));
                    
                // For non-critical imports, patch with trampoline
                asm.push_str(&format!("    mov qword ptr [rbx + 0x{:X}], jit_trampoline\n", rva));
            }
        }
        
        // Add timeout logic if enabled
        if self.config.use_timeout {
            let timeout_ms = self.config.timeout_ms;
            
            asm.push_str(&format!("\n# Timeout thread for resolving remaining imports after {} ms\n", timeout_ms));
            asm.push_str("    # Create a thread to resolve remaining imports after timeout\n");
            asm.push_str("    sub rsp, 64  # Shadow space + parameters\n");
            asm.push_str("    lea rcx, [rip + timeout_thread]  # Thread function\n");
            asm.push_str("    xor rdx, rdx  # Parameter\n");
            asm.push_str("    xor r8, r8    # Creation flags\n");
            asm.push_str("    lea r9, [rsp + 32]  # Thread ID\n");
            asm.push_str("    call CreateThread\n");
            asm.push_str("    add rsp, 64\n");
            
            asm.push_str("\ntimeout_thread:\n");
            asm.push_str("    # Wait for timeout\n");
            asm.push_str(&format!("    mov ecx, {}\n", timeout_ms));
            asm.push_str("    call Sleep\n");
            
            asm.push_str("    # Resolve all remaining imports\n");
            asm.push_str("    lea rcx, [rip + shadow_iat_data]  # RCX = Shadow IAT base\n");
            
            asm.push_str("timeout_resolve_loop:\n");
            asm.push_str("    cmp dword ptr [rcx], 0  # Check if end of shadow IAT\n");
            asm.push_str("    je timeout_done\n");
            asm.push_str("    test byte ptr [rcx + 16], 2  # Check if already resolved\n");
            asm.push_str("    jnz timeout_next_import\n");
            
            asm.push_str("    # Resolve this import\n");
            asm.push_str("    push rcx\n");
            asm.push_str("    mov edx, [rcx]  # EDX = RVA\n");
            asm.push_str("    add rdx, rbx    # RDX = VA\n");
            asm.push_str("    call resolve_import\n");
            asm.push_str("    pop rcx\n");
            
            asm.push_str("timeout_next_import:\n");
            asm.push_str("    add rcx, 32  # Move to next entry\n");
            asm.push_str("    jmp timeout_resolve_loop\n");
            
            asm.push_str("timeout_done:\n");
            asm.push_str("    ret  # Exit thread\n");
        }
        
        Ok(asm)
    }
}