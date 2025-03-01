//! Shellcode generation functionality
//!
//! This module provides functionality for generating shellcode from PE files.

mod assembly;

use assembly::{AssemblyTemplate, generate_cmdline_asm, get_shellcode_stub_template, get_obfuscation_code};
use thiserror::Error;
use std::path::Path;
use std::io;
use std::fs::File;
use std::io::{Read, Write};
use log::{debug, info, warn};
use rand::Rng;
use std::collections::HashMap;
use crate::pe::{PeFile, PeError};
use crate::iat::{IatConfig, JitPatcher};

/// Errors that can occur during shellcode generation
#[derive(Error, Debug)]
pub enum GeneratorError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    #[error("PE error: {0}")]
    Pe(String),
    
    #[error("PE parsing error: {0}")]
    PeParsing(#[from] PeError),
    
    #[error("Assembly error: {0}")]
    Assembly(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Unsupported operation: {0}")]
    Unsupported(String),
}

/// Result type for generator operations
pub type Result<T> = std::result::Result<T, GeneratorError>;

/// Configuration for shellcode generation
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// Command line arguments to pass to the PE
    pub cmdline: Option<String>,
    
    /// Whether to obfuscate the PE header
    pub obfuscate: bool,
    
    /// Whether to use multi-stage loading
    pub multi_stage: bool,
    
    /// Whether to use just-in-time IAT patching
    pub jit_imports: bool,
    
    /// Whether to encrypt the command line
    pub encrypt_cmdline: bool,
    
    /// Encryption strength (1-3)
    pub encryption_level: u8,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            cmdline: None,
            obfuscate: false,
            multi_stage: false,
            jit_imports: false,
            encrypt_cmdline: false,
            encryption_level: 1,
        }
    }
}

/// Shellcode generator
pub struct ShellcodeGenerator {
    config: GeneratorConfig,
}

impl ShellcodeGenerator {
    /// Create a new shellcode generator with default configuration
    pub fn new() -> Self {
        Self {
            config: GeneratorConfig::default(),
        }
    }
    
    /// Create a new shellcode generator with custom configuration
    pub fn with_config(config: GeneratorConfig) -> Self {
        Self { config }
    }
    
    /// Generate shellcode from a PE file
    pub fn generate(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        info!("Generating shellcode from PE file: {}", input_path.display());
        
        // Read the PE file
        let mut pe_data = Vec::new();
        let mut file = File::open(input_path)?;
        file.read_to_end(&mut pe_data)?;
        
        info!("Read {} bytes from PE file", pe_data.len());
        
        // Generate shellcode stub
        info!("Generating shellcode stub...");
        let stub = self.generate_shellcode_stub(&pe_data)?;
        
        info!("Shellcode stub size: {} bytes", stub.len());
        
        // Apply obfuscation if requested
        let pe_data = if self.config.obfuscate {
            info!("Applying PE header obfuscation...");
            self.obfuscate_pe_header(&pe_data)?
        } else {
            pe_data
        };
        
        // Generate padding
        let padding = self.generate_nop_padding(0x1000 - stub.len());
        info!("Generated {} bytes of padding", padding.len());
        
        // Combine all parts
        let mut shellcode = Vec::new();
        shellcode.extend_from_slice(&stub);
        shellcode.extend_from_slice(&padding);
        shellcode.extend_from_slice(&pe_data);
        
        info!("Total shellcode size: {} bytes", shellcode.len());
        
        // Write the shellcode to the output file
        let mut output_file = File::create(output_path)?;
        output_file.write_all(&shellcode)?;
        
        info!("Shellcode written to: {}", output_path.display());
        
        Ok(())
    }
    
    /// Generate the shellcode stub that will load the PE file
    fn generate_shellcode_stub(&self, pe_data: &[u8]) -> Result<Vec<u8>> {
        info!("Generating full-featured shellcode stub");
        
        // Parse the PE file to get information about it
        let pe_file = PeFile::parse(pe_data)?;
        
        // Get information from the PE file
        let e_lfanew = pe_file.get_e_lfanew();
        let entry_point = pe_file.get_entry_point();
        let image_size = pe_file.get_image_size();
        let image_base = pe_file.get_image_base();
        
        info!("PE info - e_lfanew: 0x{:X}, entry point: 0x{:X}, image size: 0x{:X}, image base: 0x{:X}", 
              e_lfanew, entry_point, image_size, image_base);
              
        // Create variables for the assembly template
        let mut vars = HashMap::new();
        
        // Add command line code if specified
        let cmdline_code = if let Some(cmd) = &self.config.cmdline {
            info!("Adding command line: {}", cmd);
            generate_cmdline_asm(cmd)
        } else {
            String::new()
        };
        vars.insert("CMDLINE_ASM".to_string(), cmdline_code);
        
        // Add JIT IAT patching if requested
        if self.config.jit_imports {
            info!("Adding just-in-time IAT patching code");
            
            // Create JIT patcher
            let mut jit_config = IatConfig {
                enabled: true,
                ..IatConfig::default()
            };
            
            // Create JIT patcher
            let mut patcher = JitPatcher::with_config(jit_config);
            
            // Initialize it with the PE file
            match patcher.init_from_pe(&pe_file) {
                Ok(_) => {
                    // Generate trampoline code
                    match patcher.generate_trampolines() {
                        Ok(code) => {
                            vars.insert("JIT_TRAMPOLINES".to_string(), code);
                        },
                        Err(e) => {
                            warn!("Failed to generate JIT trampolines: {}", e);
                            vars.insert("JIT_TRAMPOLINES".to_string(), String::new());
                        }
                    }
                    
                    // Generate IAT patcher code
                    match patcher.generate_iat_patcher() {
                        Ok(code) => {
                            vars.insert("JIT_PATCHER".to_string(), code);
                        },
                        Err(e) => {
                            warn!("Failed to generate JIT IAT patcher: {}", e);
                            vars.insert("JIT_PATCHER".to_string(), String::new());
                        }
                    }
                },
                Err(e) => {
                    warn!("Failed to initialize JIT patcher: {}", e);
                    vars.insert("JIT_TRAMPOLINES".to_string(), String::new());
                    vars.insert("JIT_PATCHER".to_string(), String::new());
                }
            }
        } else {
            vars.insert("JIT_TRAMPOLINES".to_string(), String::new());
            vars.insert("JIT_PATCHER".to_string(), String::new());
        }
        
        // Set the shellcode size (for finding the PE data)
        vars.insert("SHELLCODE_SIZE".to_string(), "0x1000".to_string());
        
        // Add obfuscation code if requested
        let obfuscate_code = if self.config.obfuscate {
            info!("Adding PE header obfuscation code");
            
            // Critical fields that need to be preserved for loading
            let segments = vec![
                (0x3c, 4),               // e_lfanew
                (e_lfanew as u32, 4),    // PE signature
                (e_lfanew as u32 + 0x28, 4),  // EntryPoint RVA
                (e_lfanew as u32 + 0x30, 8),  // ImageBase
                (e_lfanew as u32 + 0x50, 4),  // SizeOfImage
                (e_lfanew as u32 + 0x88, 8),  // Import Directory (RVA + Size)
                (e_lfanew as u32 + 0xa8, 8),  // Relocation Directory (RVA + Size)
                (e_lfanew as u32 + 0xf0, 8),  // Delay Import Directory (RVA + Size)
            ];
            
            get_obfuscation_code(&segments)
        } else {
            String::new()
        };
        vars.insert("OBFUSCATE_ASM".to_string(), obfuscate_code);
        
        // Create the assembly template
        let mut template = AssemblyTemplate::new(&get_shellcode_stub_template());
        template.set_many(&vars);
        
        // Compile the assembly to machine code
        let result = template.compile();
        match result {
            Ok(code) => {
                info!("Successfully compiled shellcode stub - {} bytes", code.len());
                Ok(code)
            },
            Err(e) => {
                warn!("Failed to compile shellcode stub, falling back to placeholder");
                
                // Fallback stub - just for development purposes
                // In production, we would want to ensure the compilation always succeeds
                let fallback_stub = vec![
                    // Start with some x64 code that does nothing useful
                    0x48, 0x83, 0xEC, 0x28,          // sub rsp, 28h
                    0x48, 0x31, 0xC0,                // xor rax, rax
                    0x48, 0x31, 0xDB,                // xor rbx, rbx
                    0x48, 0x31, 0xC9,                // xor rcx, rcx
                    0x48, 0x31, 0xD2,                // xor rdx, rdx
                    0x48, 0x31, 0xF6,                // xor rsi, rsi
                    0x48, 0x31, 0xFF,                // xor rdi, rdi
                    0x4D, 0x31, 0xC0,                // xor r8, r8
                    0x4D, 0x31, 0xC9,                // xor r9, r9
                    0x4D, 0x31, 0xD2,                // xor r10, r10
                    0x4D, 0x31, 0xDB,                // xor r11, r11
                    0x4D, 0x31, 0xE4,                // xor r12, r12 
                    0x4D, 0x31, 0xED,                // xor r13, r13
                    0x4D, 0x31, 0xF6,                // xor r14, r14
                    0x4D, 0x31, 0xFF,                // xor r15, r15
                    0x48, 0x83, 0xC4, 0x28,          // add rsp, 28h
                    0xC3,                            // ret
                ];
                
                Err(e)
            }
        }
    }
    
    /// Obfuscate the PE header
    fn obfuscate_pe_header(&self, pe_data: &[u8]) -> Result<Vec<u8>> {
        info!("Obfuscating PE header");
        
        // Parse the PE file to get information about it
        let pe_file = PeFile::parse(pe_data)?;
        
        // Get information from the PE file
        let e_lfanew = pe_file.get_e_lfanew() as usize;
        let entry_point_offset = e_lfanew + 0x28;
        let image_base_offset = e_lfanew + 0x30;
        let image_size_offset = e_lfanew + 0x50;
        
        // Get data directory offsets
        let mut data_dir_offsets = Vec::new();
        let data_dir_start = e_lfanew + 0x88; // First data directory
        
        // Get the number of data directories
        let num_dirs = pe_file.nt_headers.optional_header.number_of_rva_and_sizes as usize;
        
        // Each data directory is 8 bytes (RVA + size)
        for i in 0..num_dirs {
            if i == 1 || i == 5 || i == 13 { // Import, Relocation, and Delay Import Directories
                let offset = data_dir_start + (i * 8);
                data_dir_offsets.push(offset..offset + 8);
            }
        }
        
        // Preserve critical fields
        let mut critical_ranges = vec![
            0..2,              // MZ signature
            0x3c..0x40,        // e_lfanew
            e_lfanew..e_lfanew + 4,  // PE signature
            entry_point_offset..entry_point_offset + 4,  // EntryPoint RVA
            image_base_offset..image_base_offset + 8,    // ImageBase
            image_size_offset..image_size_offset + 4,    // SizeOfImage
        ];
        
        // Add data directory ranges
        critical_ranges.extend(data_dir_offsets);
        
        // Create a new byte array with randomized content
        let mut rng = rand::thread_rng();
        let mut obfuscated = pe_data.to_vec();
        
        // Only randomize the PE header, not the entire file
        let header_size = 0x1000.min(pe_data.len());
        
        // Randomize all bytes in the header except critical ranges
        for i in 0..header_size {
            let is_critical = critical_ranges.iter().any(|range| range.contains(&i));
            if !is_critical {
                obfuscated[i] = rng.gen();
            }
        }
        
        info!("PE header obfuscation complete - preserved {} critical ranges", critical_ranges.len());
        
        Ok(obfuscated)
    }
    
    /// Generate NOP-like padding instructions
    fn generate_nop_padding(&self, size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut padding = Vec::with_capacity(size);
        
        // Define NOP-like instructions
        let nop_like = vec![
            vec![0x90],                      // NOP
            vec![0x86, 0xDB],                // XCHG BL, BL
            vec![0x66, 0x87, 0xF6],          // XCHG SI, SI
            vec![0x48, 0x90],                // XCHG RAX, RAX
            vec![0x0F, 0x1F, 0x00],          // NOP DWORD PTR [RAX]
            vec![0x0F, 0x1F, 0x40, 0x00],    // NOP DWORD PTR [RAX + 00H]
            vec![0x0F, 0x1F, 0x44, 0x00, 0x00], // NOP DWORD PTR [RAX + RAX*1 + 00H]
            vec![0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00], // NOP WORD PTR [RAX + RAX*1 + 00H]
            vec![0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00], // NOP DWORD PTR [RAX + 00000000H]
            vec![0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // NOP DWORD PTR [RAX + RAX*1 + 00000000H]
        ];
        
        // Fill with random NOP-like instructions
        let mut remaining = size;
        while remaining > 0 {
            // Select NOP-like instructions that fit in the remaining space
            let valid_nops: Vec<_> = nop_like.iter()
                .filter(|nop| nop.len() <= remaining)
                .collect();
            
            if valid_nops.is_empty() {
                // If no valid NOP-like instructions, use simple NOP
                padding.push(0x90);
                remaining -= 1;
            } else {
                // Select a random NOP-like instruction
                let nop = valid_nops[rng.gen_range(0..valid_nops.len())];
                padding.extend_from_slice(nop);
                remaining -= nop.len();
            }
        }
        
        padding
    }
}