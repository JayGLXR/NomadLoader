//! PE (Portable Executable) file parsing and manipulation
//! 
//! This module provides functionality for working with Windows PE files,
//! including parsing headers, sections, imports, and other PE components.

mod header;
mod section;
mod import;

pub use header::*;
pub use section::*;
pub use import::*;

use thiserror::Error;
use std::path::Path;
use std::fs::File;
use std::io::{self, Read};

/// Extract a null-terminated C string from a byte slice
fn extract_c_string(data: &[u8]) -> Result<String> {
    // Find the position of the null terminator
    let null_pos = data.iter()
        .position(|&c| c == 0)
        .unwrap_or(data.len());
    
    // Extract the string up to the null terminator
    let str_bytes = &data[0..null_pos];
    
    // Convert to a String
    String::from_utf8(str_bytes.to_vec())
        .map_err(|_| PeError::InvalidFormat("Invalid UTF-8 string".to_string()))
}

/// Errors that can occur when working with PE files
#[derive(Error, Debug)]
pub enum PeError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Invalid PE signature")]
    InvalidSignature,
    
    #[error("Invalid PE format: {0}")]
    InvalidFormat(String),
    
    #[error("Unsupported PE feature: {0}")]
    Unsupported(String),
    
    #[error("Required data directory not found: {0}")]
    MissingDataDirectory(String),
    
    #[error("Windows API error: {0}")]
    WindowsApi(u32),
}

/// Result type for PE operations
pub type Result<T> = std::result::Result<T, PeError>;

/// The main PE file structure
#[derive(Debug)]
pub struct PeFile {
    /// Raw PE file data
    pub data: Vec<u8>,
    
    /// DOS header
    pub dos_header: DosHeader,
    
    /// NT headers
    pub nt_headers: NtHeaders,
    
    /// Section headers
    pub sections: Vec<SectionHeader>,
    
    /// Import descriptors
    pub imports: Vec<ImportDescriptor>,
    
    /// Delay import descriptors (if present)
    pub delay_imports: Option<Vec<DelayImportDescriptor>>,
    
    /// Base relocations (if present)
    pub relocations: Option<Vec<BaseRelocation>>,
}

impl PeFile {
    /// Parse a PE file from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DosHeader::SIZE {
            return Err(PeError::InvalidFormat("Data too small for DOS header".to_string()));
        }
        
        // Parse the DOS header
        let dos_header = DosHeader::parse(data)?;
        
        // Calculate offset to NT headers
        let nt_offset = dos_header.e_lfanew as usize;
        if nt_offset >= data.len() {
            return Err(PeError::InvalidFormat("Invalid e_lfanew offset".to_string()));
        }
        
        // Parse the NT headers
        let nt_headers = NtHeaders::parse(&data[nt_offset..])?;
        
        // Calculate offset to section headers
        let sections_offset = nt_offset + 4 + FileHeader::SIZE + nt_headers.file_header.size_of_optional_header as usize;
        if sections_offset >= data.len() {
            return Err(PeError::InvalidFormat("Invalid section headers offset".to_string()));
        }
        
        // Parse the section headers
        let num_sections = nt_headers.file_header.number_of_sections as usize;
        let mut sections = Vec::with_capacity(num_sections);
        
        for i in 0..num_sections {
            let section_offset = sections_offset + (i * SectionHeader::SIZE);
            if section_offset + SectionHeader::SIZE > data.len() {
                return Err(PeError::InvalidFormat("Invalid section header offset".to_string()));
            }
            
            let section = SectionHeader::parse(&data[section_offset..section_offset + SectionHeader::SIZE])?;
            sections.push(section);
        }
        
        // Create a RVA to offset converter for this PE file
        let rva_to_offset = |rva: u32| -> Option<u32> {
            for section in &sections {
                if rva >= section.virtual_address && 
                   rva < section.virtual_address + section.virtual_size {
                    return Some(rva - section.virtual_address + section.pointer_to_raw_data);
                }
            }
            None
        };
        
        // Parse the import directory
        let mut imports = Vec::new();
        if let Some(import_dir) = nt_headers.optional_header.get_import_directory() {
            if import_dir.is_present() {
                let import_rva = import_dir.virtual_address;
                let import_size = import_dir.size;
                
                if let Some(import_offset) = rva_to_offset(import_rva) {
                    let mut offset = import_offset as usize;
                    loop {
                        // Check if we're past the end of the import directory
                        if offset + ImportDescriptor::SIZE > data.len() {
                            break;
                        }
                        
                        // Parse the import descriptor
                        let import_desc = ImportDescriptor::parse(&data[offset..offset + ImportDescriptor::SIZE])?;
                        
                        // Check if this is the terminating descriptor
                        if import_desc.is_terminator() {
                            break;
                        }
                        
                        if !import_desc.is_valid() {
                            break;
                        }
                        
                        // Parse the DLL name
                        let mut import_desc = import_desc;
                        if let Some(name_offset) = rva_to_offset(import_desc.name) {
                            import_desc.dll_name = extract_c_string(&data[name_offset as usize..])?;
                        } else {
                            return Err(PeError::InvalidFormat(format!(
                                "Invalid RVA for import DLL name: 0x{:08x}", import_desc.name
                            )));
                        }
                        
                        // Parse the import entries
                        let mut entries = Vec::new();
                        
                        // Use the ILT if available, otherwise use the IAT
                        let thunk_rva = if import_desc.original_first_thunk != 0 {
                            import_desc.original_first_thunk
                        } else {
                            import_desc.first_thunk
                        };
                        
                        if let Some(thunk_offset) = rva_to_offset(thunk_rva) {
                            let is_pe32_plus = nt_headers.optional_header.magic == 0x20b;
                            let thunk_size = if is_pe32_plus { 8 } else { 4 };
                            
                            let mut thunk_idx = 0;
                            loop {
                                let entry_offset = thunk_offset as usize + (thunk_idx * thunk_size);
                                if entry_offset + thunk_size > data.len() {
                                    break;
                                }
                                
                                // Parse the import entry
                                let entry_result = if is_pe32_plus {
                                    ImportEntry::parse_64(&data[entry_offset..entry_offset + thunk_size], data, &rva_to_offset)
                                } else {
                                    ImportEntry::parse_32(&data[entry_offset..entry_offset + thunk_size], data, &rva_to_offset)
                                };
                                
                                // If the entry is all zeros, it's the end of the list
                                match entry_result {
                                    Ok(entry) => entries.push(entry),
                                    Err(_) => break,
                                }
                                
                                thunk_idx += 1;
                            }
                        }
                        
                        import_desc.entries = entries;
                        imports.push(import_desc);
                        
                        // Move to the next import descriptor
                        offset += ImportDescriptor::SIZE;
                    }
                }
            }
        }
        
        // Parse the delay import directory
        let mut delay_imports = None;
        if let Some(delay_dir) = nt_headers.optional_header.get_delay_import_directory() {
            if delay_dir.is_present() {
                let delay_rva = delay_dir.virtual_address;
                let delay_size = delay_dir.size;
                
                if let Some(delay_offset) = rva_to_offset(delay_rva) {
                    let mut offset = delay_offset as usize;
                    let mut descriptors = Vec::new();
                    
                    loop {
                        // Check if we're past the end of the delay import directory
                        if offset + DelayImportDescriptor::SIZE > data.len() {
                            break;
                        }
                        
                        // Parse the delay import descriptor
                        let delay_desc = DelayImportDescriptor::parse(&data[offset..offset + DelayImportDescriptor::SIZE])?;
                        
                        // Check if this is the terminating descriptor
                        if delay_desc.is_terminator() {
                            break;
                        }
                        
                        if !delay_desc.is_valid() {
                            break;
                        }
                        
                        // Parse the DLL name
                        let mut delay_desc = delay_desc;
                        if let Some(name_offset) = rva_to_offset(delay_desc.name) {
                            delay_desc.dll_name = extract_c_string(&data[name_offset as usize..])?;
                        } else {
                            return Err(PeError::InvalidFormat(format!(
                                "Invalid RVA for delay import DLL name: 0x{:08x}", delay_desc.name
                            )));
                        }
                        
                        // Parse the delay import entries
                        let mut entries = Vec::new();
                        
                        if let Some(thunk_offset) = rva_to_offset(delay_desc.delay_import_name_table) {
                            let is_pe32_plus = nt_headers.optional_header.magic == 0x20b;
                            let thunk_size = if is_pe32_plus { 8 } else { 4 };
                            
                            let mut thunk_idx = 0;
                            loop {
                                let entry_offset = thunk_offset as usize + (thunk_idx * thunk_size);
                                if entry_offset + thunk_size > data.len() {
                                    break;
                                }
                                
                                // Parse the import entry
                                let entry_result = if is_pe32_plus {
                                    ImportEntry::parse_64(&data[entry_offset..entry_offset + thunk_size], data, &rva_to_offset)
                                } else {
                                    ImportEntry::parse_32(&data[entry_offset..entry_offset + thunk_size], data, &rva_to_offset)
                                };
                                
                                // If the entry is all zeros, it's the end of the list
                                match entry_result {
                                    Ok(entry) => entries.push(entry),
                                    Err(_) => break,
                                }
                                
                                thunk_idx += 1;
                            }
                        }
                        
                        delay_desc.entries = entries;
                        descriptors.push(delay_desc);
                        
                        // Move to the next delay import descriptor
                        offset += DelayImportDescriptor::SIZE;
                    }
                    
                    if !descriptors.is_empty() {
                        delay_imports = Some(descriptors);
                    }
                }
            }
        }
        
        // Parse base relocations
        let mut relocations = None;
        if let Some(reloc_dir) = nt_headers.optional_header.get_base_relocation_directory() {
            if reloc_dir.is_present() {
                let reloc_rva = reloc_dir.virtual_address;
                let reloc_size = reloc_dir.size;
                
                if let Some(reloc_offset) = rva_to_offset(reloc_rva) {
                    let reloc_data = &data[reloc_offset as usize..(reloc_offset + reloc_size) as usize];
                    let reloc = BaseRelocation::parse(reloc_data, reloc_size)?;
                    
                    if !reloc.blocks.is_empty() {
                        relocations = Some(reloc);
                    }
                }
            }
        }
        
        Ok(Self {
            data: data.to_vec(),
            dos_header,
            nt_headers,
            sections,
            imports,
            delay_imports,
            relocations,
        })
    }
    
    /// Read a PE file from disk
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        
        Self::parse(&data)
    }
    
    /// Get the offset to the NT headers (e_lfanew)
    pub fn get_e_lfanew(&self) -> u32 {
        self.dos_header.e_lfanew
    }
    
    /// Get the address of the entry point (RVA)
    pub fn get_entry_point(&self) -> u32 {
        self.nt_headers.optional_header.address_of_entry_point
    }
    
    /// Get the preferred image base address
    pub fn get_image_base(&self) -> u64 {
        self.nt_headers.optional_header.image_base
    }
    
    /// Get the size of the image in memory
    pub fn get_image_size(&self) -> u32 {
        self.nt_headers.optional_header.size_of_image
    }
    
    /// Get the size of the text section
    pub fn get_text_section_size(&self) -> Option<u32> {
        self.sections.iter()
            .find(|s| s.name.starts_with(b".text"))
            .map(|s| s.virtual_size)
    }
    
    /// Convert a Relative Virtual Address (RVA) to a file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        for section in &self.sections {
            if rva >= section.virtual_address && 
               rva < section.virtual_address + section.virtual_size {
                return Some(rva - section.virtual_address + section.pointer_to_raw_data);
            }
        }
        None
    }
    
    /// Convert a file offset to a Relative Virtual Address (RVA)
    pub fn offset_to_rva(&self, offset: u32) -> Option<u32> {
        for section in &self.sections {
            if offset >= section.pointer_to_raw_data && 
               offset < section.pointer_to_raw_data + section.size_of_raw_data {
                return Some(offset - section.pointer_to_raw_data + section.virtual_address);
            }
        }
        None
    }
}