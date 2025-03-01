//! PE header structures and parsing
//!
//! This module provides structures and functions for working with the PE file headers.

use std::fmt;
use byteorder::{ByteOrder, LittleEndian};
use crate::pe::{PeError, Result};

/// DOS header structure
#[derive(Debug, Clone)]
pub struct DosHeader {
    /// Magic number ('MZ')
    pub e_magic: u16,
    /// Bytes on last page of file
    pub e_cblp: u16,
    /// Pages in file
    pub e_cp: u16,
    /// Relocations
    pub e_crlc: u16,
    /// Size of header in paragraphs
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed
    pub e_maxalloc: u16,
    /// Initial (relative) SS value
    pub e_ss: u16,
    /// Initial SP value
    pub e_sp: u16,
    /// Checksum
    pub e_csum: u16,
    /// Initial IP value
    pub e_ip: u16,
    /// Initial (relative) CS value
    pub e_cs: u16,
    /// File address of relocation table
    pub e_lfarlc: u16,
    /// Overlay number
    pub e_ovno: u16,
    /// Reserved words
    pub e_res: [u16; 4],
    /// OEM identifier
    pub e_oemid: u16,
    /// OEM information
    pub e_oeminfo: u16,
    /// Reserved words
    pub e_res2: [u16; 10],
    /// File address of new exe header
    pub e_lfanew: u32,
}

impl DosHeader {
    /// Size of the DOS header in bytes
    pub const SIZE: usize = 64;
    
    /// Parse a DOS header from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(PeError::InvalidFormat("Data too small for DOS header".to_string()));
        }
        
        let e_magic = LittleEndian::read_u16(&data[0..2]);
        if e_magic != 0x5A4D { // 'MZ'
            return Err(PeError::InvalidSignature);
        }
        
        Ok(Self {
            e_magic,
            e_cblp: LittleEndian::read_u16(&data[2..4]),
            e_cp: LittleEndian::read_u16(&data[4..6]),
            e_crlc: LittleEndian::read_u16(&data[6..8]),
            e_cparhdr: LittleEndian::read_u16(&data[8..10]),
            e_minalloc: LittleEndian::read_u16(&data[10..12]),
            e_maxalloc: LittleEndian::read_u16(&data[12..14]),
            e_ss: LittleEndian::read_u16(&data[14..16]),
            e_sp: LittleEndian::read_u16(&data[16..18]),
            e_csum: LittleEndian::read_u16(&data[18..20]),
            e_ip: LittleEndian::read_u16(&data[20..22]),
            e_cs: LittleEndian::read_u16(&data[22..24]),
            e_lfarlc: LittleEndian::read_u16(&data[24..26]),
            e_ovno: LittleEndian::read_u16(&data[26..28]),
            e_res: [
                LittleEndian::read_u16(&data[28..30]),
                LittleEndian::read_u16(&data[30..32]),
                LittleEndian::read_u16(&data[32..34]),
                LittleEndian::read_u16(&data[34..36]),
            ],
            e_oemid: LittleEndian::read_u16(&data[36..38]),
            e_oeminfo: LittleEndian::read_u16(&data[38..40]),
            e_res2: [
                LittleEndian::read_u16(&data[40..42]),
                LittleEndian::read_u16(&data[42..44]),
                LittleEndian::read_u16(&data[44..46]),
                LittleEndian::read_u16(&data[46..48]),
                LittleEndian::read_u16(&data[48..50]),
                LittleEndian::read_u16(&data[50..52]),
                LittleEndian::read_u16(&data[52..54]),
                LittleEndian::read_u16(&data[54..56]),
                LittleEndian::read_u16(&data[56..58]),
                LittleEndian::read_u16(&data[58..60]),
            ],
            e_lfanew: LittleEndian::read_u32(&data[60..64]),
        })
    }
}

/// File header characteristic flags
#[derive(Debug, Clone, Copy)]
pub struct FileCharacteristics(pub u16);

impl FileCharacteristics {
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    pub const AGGRESSIVE_WS_TRIM: u16 = 0x0010;
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    pub const BYTES_REVERSED_LO: u16 = 0x0080;
    pub const MACHINE_32BIT: u16 = 0x0100;
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    pub const SYSTEM: u16 = 0x1000;
    pub const DLL: u16 = 0x2000;
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
    pub const BYTES_REVERSED_HI: u16 = 0x8000;
    
    pub fn has_flag(&self, flag: u16) -> bool {
        (self.0 & flag) != 0
    }
    
    pub fn is_dll(&self) -> bool {
        self.has_flag(Self::DLL)
    }
    
    pub fn is_exe(&self) -> bool {
        self.has_flag(Self::EXECUTABLE_IMAGE) && !self.is_dll()
    }
}

impl fmt::Display for FileCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        
        if self.has_flag(Self::RELOCS_STRIPPED) { flags.push("RELOCS_STRIPPED"); }
        if self.has_flag(Self::EXECUTABLE_IMAGE) { flags.push("EXECUTABLE_IMAGE"); }
        if self.has_flag(Self::LINE_NUMS_STRIPPED) { flags.push("LINE_NUMS_STRIPPED"); }
        if self.has_flag(Self::LOCAL_SYMS_STRIPPED) { flags.push("LOCAL_SYMS_STRIPPED"); }
        if self.has_flag(Self::AGGRESSIVE_WS_TRIM) { flags.push("AGGRESSIVE_WS_TRIM"); }
        if self.has_flag(Self::LARGE_ADDRESS_AWARE) { flags.push("LARGE_ADDRESS_AWARE"); }
        if self.has_flag(Self::BYTES_REVERSED_LO) { flags.push("BYTES_REVERSED_LO"); }
        if self.has_flag(Self::MACHINE_32BIT) { flags.push("MACHINE_32BIT"); }
        if self.has_flag(Self::DEBUG_STRIPPED) { flags.push("DEBUG_STRIPPED"); }
        if self.has_flag(Self::REMOVABLE_RUN_FROM_SWAP) { flags.push("REMOVABLE_RUN_FROM_SWAP"); }
        if self.has_flag(Self::NET_RUN_FROM_SWAP) { flags.push("NET_RUN_FROM_SWAP"); }
        if self.has_flag(Self::SYSTEM) { flags.push("SYSTEM"); }
        if self.has_flag(Self::DLL) { flags.push("DLL"); }
        if self.has_flag(Self::UP_SYSTEM_ONLY) { flags.push("UP_SYSTEM_ONLY"); }
        if self.has_flag(Self::BYTES_REVERSED_HI) { flags.push("BYTES_REVERSED_HI"); }
        
        write!(f, "{}", flags.join(" | "))
    }
}

/// Machine types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    Unknown,
    X86,
    X64,
    IA64,
    ARM,
    ARM64,
    Other(u16),
}

impl From<u16> for Machine {
    fn from(value: u16) -> Self {
        match value {
            0x0 => Machine::Unknown,
            0x14c => Machine::X86,
            0x8664 => Machine::X64,
            0x200 => Machine::IA64,
            0x1c0 => Machine::ARM,
            0xaa64 => Machine::ARM64,
            other => Machine::Other(other),
        }
    }
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Machine::Unknown => write!(f, "Unknown"),
            Machine::X86 => write!(f, "x86"),
            Machine::X64 => write!(f, "x64"),
            Machine::IA64 => write!(f, "IA64"),
            Machine::ARM => write!(f, "ARM"),
            Machine::ARM64 => write!(f, "ARM64"),
            Machine::Other(code) => write!(f, "Other(0x{:04x})", code),
        }
    }
}

/// COFF File Header
#[derive(Debug, Clone)]
pub struct FileHeader {
    /// The architecture type of the computer
    pub machine: Machine,
    /// The number of sections
    pub number_of_sections: u16,
    /// The low 32 bits of the time stamp of the image
    pub time_date_stamp: u32,
    /// The file offset of the COFF symbol table
    pub pointer_to_symbol_table: u32,
    /// The number of symbols in the symbol table
    pub number_of_symbols: u32,
    /// The size of the optional header
    pub size_of_optional_header: u16,
    /// The characteristics of the image
    pub characteristics: FileCharacteristics,
}

impl FileHeader {
    /// Size of the file header in bytes
    pub const SIZE: usize = 20;
    
    /// Parse a file header from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(PeError::InvalidFormat("Data too small for file header".to_string()));
        }
        
        Ok(Self {
            machine: Machine::from(LittleEndian::read_u16(&data[0..2])),
            number_of_sections: LittleEndian::read_u16(&data[2..4]),
            time_date_stamp: LittleEndian::read_u32(&data[4..8]),
            pointer_to_symbol_table: LittleEndian::read_u32(&data[8..12]),
            number_of_symbols: LittleEndian::read_u32(&data[12..16]),
            size_of_optional_header: LittleEndian::read_u16(&data[16..18]),
            characteristics: FileCharacteristics(LittleEndian::read_u16(&data[18..20])),
        })
    }
}

/// DLL characteristics
#[derive(Debug, Clone, Copy)]
pub struct DllCharacteristics(pub u16);

impl DllCharacteristics {
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const NO_ISOLATION: u16 = 0x0200;
    pub const NO_SEH: u16 = 0x0400;
    pub const NO_BIND: u16 = 0x0800;
    pub const APPCONTAINER: u16 = 0x1000;
    pub const WDM_DRIVER: u16 = 0x2000;
    pub const GUARD_CF: u16 = 0x4000;
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;
    
    pub fn has_flag(&self, flag: u16) -> bool {
        (self.0 & flag) != 0
    }
}

impl fmt::Display for DllCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        
        if self.has_flag(Self::HIGH_ENTROPY_VA) { flags.push("HIGH_ENTROPY_VA"); }
        if self.has_flag(Self::DYNAMIC_BASE) { flags.push("DYNAMIC_BASE"); }
        if self.has_flag(Self::FORCE_INTEGRITY) { flags.push("FORCE_INTEGRITY"); }
        if self.has_flag(Self::NX_COMPAT) { flags.push("NX_COMPAT"); }
        if self.has_flag(Self::NO_ISOLATION) { flags.push("NO_ISOLATION"); }
        if self.has_flag(Self::NO_SEH) { flags.push("NO_SEH"); }
        if self.has_flag(Self::NO_BIND) { flags.push("NO_BIND"); }
        if self.has_flag(Self::APPCONTAINER) { flags.push("APPCONTAINER"); }
        if self.has_flag(Self::WDM_DRIVER) { flags.push("WDM_DRIVER"); }
        if self.has_flag(Self::GUARD_CF) { flags.push("GUARD_CF"); }
        if self.has_flag(Self::TERMINAL_SERVER_AWARE) { flags.push("TERMINAL_SERVER_AWARE"); }
        
        write!(f, "{}", flags.join(" | "))
    }
}

/// Data directory entry
#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    /// Virtual address of the table
    pub virtual_address: u32,
    /// Size of the table
    pub size: u32,
}

impl DataDirectory {
    /// Size of a data directory entry in bytes
    pub const SIZE: usize = 8;
    
    /// Parse a data directory from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(PeError::InvalidFormat("Data too small for data directory".to_string()));
        }
        
        Ok(Self {
            virtual_address: LittleEndian::read_u32(&data[0..4]),
            size: LittleEndian::read_u32(&data[4..8]),
        })
    }
    
    /// Check if this data directory is present (has a non-zero address and size)
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// Optional header for a PE32 or PE32+ file
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    /// Standard fields
    /// The state of the image file
    pub magic: u16,
    /// The major version number of the linker
    pub major_linker_version: u8,
    /// The minor version number of the linker
    pub minor_linker_version: u8,
    /// The size of the code section
    pub size_of_code: u32,
    /// The size of the initialized data section
    pub size_of_initialized_data: u32,
    /// The size of the uninitialized data section
    pub size_of_uninitialized_data: u32,
    /// The address of the entry point
    pub address_of_entry_point: u32,
    /// The address of the beginning of the code section
    pub base_of_code: u32,
    /// The address of the beginning of the data section (PE32 only)
    pub base_of_data: Option<u32>,
    
    /// Windows-specific fields
    /// The preferred address of the first byte of the image when loaded in memory
    pub image_base: u64,
    /// The alignment of sections loaded in memory
    pub section_alignment: u32,
    /// The alignment of the raw data of sections in the image file
    pub file_alignment: u32,
    /// The major version number of the required OS
    pub major_operating_system_version: u16,
    /// The minor version number of the required OS
    pub minor_operating_system_version: u16,
    /// The major version number of the image
    pub major_image_version: u16,
    /// The minor version number of the image
    pub minor_image_version: u16,
    /// The major version number of the subsystem
    pub major_subsystem_version: u16,
    /// The minor version number of the subsystem
    pub minor_subsystem_version: u16,
    /// Reserved, must be zero
    pub win32_version_value: u32,
    /// The size of the image in bytes
    pub size_of_image: u32,
    /// The combined size of the MS-DOS stub, PE header, and section headers
    pub size_of_headers: u32,
    /// The image file checksum
    pub checksum: u32,
    /// The subsystem required to run this image
    pub subsystem: u16,
    /// DLL characteristics of the image
    pub dll_characteristics: DllCharacteristics,
    /// The size of the stack to reserve
    pub size_of_stack_reserve: u64,
    /// The size of the stack to commit
    pub size_of_stack_commit: u64,
    /// The size of the local heap to reserve
    pub size_of_heap_reserve: u64,
    /// The size of the local heap to commit
    pub size_of_heap_commit: u64,
    /// Reserved, must be zero
    pub loader_flags: u32,
    /// The number of data-directory entries
    pub number_of_rva_and_sizes: u32,
    
    /// Data directories
    pub data_directories: Vec<DataDirectory>,
}

impl OptionalHeader {
    /// Parse an optional header from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 24 {
            return Err(PeError::InvalidFormat("Data too small for optional header".to_string()));
        }
        
        let magic = LittleEndian::read_u16(&data[0..2]);
        let is_pe32_plus = match magic {
            0x10b => false, // PE32
            0x20b => true,  // PE32+
            _ => return Err(PeError::InvalidFormat(format!("Unknown optional header magic: 0x{:x}", magic))),
        };
        
        // Calculate the header size based on the magic value
        let (base_size, data_dir_offset) = if is_pe32_plus {
            (108, 108) // PE32+
        } else {
            (96, 96)   // PE32
        };
        
        if data.len() < base_size {
            return Err(PeError::InvalidFormat("Data too small for optional header".to_string()));
        }
        
        let mut header = Self {
            magic,
            major_linker_version: data[2],
            minor_linker_version: data[3],
            size_of_code: LittleEndian::read_u32(&data[4..8]),
            size_of_initialized_data: LittleEndian::read_u32(&data[8..12]),
            size_of_uninitialized_data: LittleEndian::read_u32(&data[12..16]),
            address_of_entry_point: LittleEndian::read_u32(&data[16..20]),
            base_of_code: LittleEndian::read_u32(&data[20..24]),
            base_of_data: if is_pe32_plus {
                None
            } else {
                Some(LittleEndian::read_u32(&data[24..28]))
            },
            
            // Windows-specific fields - different offset based on format
            image_base: if is_pe32_plus {
                LittleEndian::read_u64(&data[24..32])
            } else {
                LittleEndian::read_u32(&data[28..32]) as u64
            },
            
            section_alignment: LittleEndian::read_u32(&data[if is_pe32_plus { 32 } else { 32 }..if is_pe32_plus { 36 } else { 36 }]),
            file_alignment: LittleEndian::read_u32(&data[if is_pe32_plus { 36 } else { 36 }..if is_pe32_plus { 40 } else { 40 }]),
            major_operating_system_version: LittleEndian::read_u16(&data[if is_pe32_plus { 40 } else { 40 }..if is_pe32_plus { 42 } else { 42 }]),
            minor_operating_system_version: LittleEndian::read_u16(&data[if is_pe32_plus { 42 } else { 42 }..if is_pe32_plus { 44 } else { 44 }]),
            major_image_version: LittleEndian::read_u16(&data[if is_pe32_plus { 44 } else { 44 }..if is_pe32_plus { 46 } else { 46 }]),
            minor_image_version: LittleEndian::read_u16(&data[if is_pe32_plus { 46 } else { 46 }..if is_pe32_plus { 48 } else { 48 }]),
            major_subsystem_version: LittleEndian::read_u16(&data[if is_pe32_plus { 48 } else { 48 }..if is_pe32_plus { 50 } else { 50 }]),
            minor_subsystem_version: LittleEndian::read_u16(&data[if is_pe32_plus { 50 } else { 50 }..if is_pe32_plus { 52 } else { 52 }]),
            win32_version_value: LittleEndian::read_u32(&data[if is_pe32_plus { 52 } else { 52 }..if is_pe32_plus { 56 } else { 56 }]),
            size_of_image: LittleEndian::read_u32(&data[if is_pe32_plus { 56 } else { 56 }..if is_pe32_plus { 60 } else { 60 }]),
            size_of_headers: LittleEndian::read_u32(&data[if is_pe32_plus { 60 } else { 60 }..if is_pe32_plus { 64 } else { 64 }]),
            checksum: LittleEndian::read_u32(&data[if is_pe32_plus { 64 } else { 64 }..if is_pe32_plus { 68 } else { 68 }]),
            subsystem: LittleEndian::read_u16(&data[if is_pe32_plus { 68 } else { 68 }..if is_pe32_plus { 70 } else { 70 }]),
            dll_characteristics: DllCharacteristics(LittleEndian::read_u16(&data[if is_pe32_plus { 70 } else { 70 }..if is_pe32_plus { 72 } else { 72 }])),
            
            size_of_stack_reserve: if is_pe32_plus {
                LittleEndian::read_u64(&data[72..80])
            } else {
                LittleEndian::read_u32(&data[72..76]) as u64
            },
            size_of_stack_commit: if is_pe32_plus {
                LittleEndian::read_u64(&data[80..88])
            } else {
                LittleEndian::read_u32(&data[76..80]) as u64
            },
            size_of_heap_reserve: if is_pe32_plus {
                LittleEndian::read_u64(&data[88..96])
            } else {
                LittleEndian::read_u32(&data[80..84]) as u64
            },
            size_of_heap_commit: if is_pe32_plus {
                LittleEndian::read_u64(&data[96..104])
            } else {
                LittleEndian::read_u32(&data[84..88]) as u64
            },
            
            loader_flags: LittleEndian::read_u32(&data[if is_pe32_plus { 104 } else { 88 }..if is_pe32_plus { 108 } else { 92 }]),
            number_of_rva_and_sizes: LittleEndian::read_u32(&data[if is_pe32_plus { 108 } else { 92 }..if is_pe32_plus { 112 } else { 96 }]),
            
            data_directories: Vec::new(),
        };
        
        // Parse data directories
        let num_dirs = header.number_of_rva_and_sizes as usize;
        let data_dir_size = DataDirectory::SIZE;
        
        if data.len() < data_dir_offset + (num_dirs * data_dir_size) {
            return Err(PeError::InvalidFormat(format!(
                "Data too small for {} data directories", num_dirs
            )));
        }
        
        // Parse each data directory
        for i in 0..num_dirs {
            let offset = data_dir_offset + (i * data_dir_size);
            let dir = DataDirectory::parse(&data[offset..offset + data_dir_size])?;
            header.data_directories.push(dir);
        }
        
        Ok(header)
    }
    
    /// Get a specific data directory
    pub fn get_data_directory(&self, index: usize) -> Option<&DataDirectory> {
        self.data_directories.get(index)
    }
    
    /// Get the export directory
    pub fn get_export_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(0)
    }
    
    /// Get the import directory
    pub fn get_import_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(1)
    }
    
    /// Get the resource directory
    pub fn get_resource_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(2)
    }
    
    /// Get the exception directory
    pub fn get_exception_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(3)
    }
    
    /// Get the security directory
    pub fn get_security_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(4)
    }
    
    /// Get the base relocation directory
    pub fn get_base_relocation_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(5)
    }
    
    /// Get the debug directory
    pub fn get_debug_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(6)
    }
    
    /// Get the architecture directory
    pub fn get_architecture_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(7)
    }
    
    /// Get the global ptr directory
    pub fn get_global_ptr_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(8)
    }
    
    /// Get the TLS directory
    pub fn get_tls_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(9)
    }
    
    /// Get the load config directory
    pub fn get_load_config_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(10)
    }
    
    /// Get the bound import directory
    pub fn get_bound_import_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(11)
    }
    
    /// Get the IAT directory
    pub fn get_iat_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(12)
    }
    
    /// Get the delay import directory
    pub fn get_delay_import_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(13)
    }
    
    /// Get the COM descriptor directory
    pub fn get_com_descriptor_directory(&self) -> Option<&DataDirectory> {
        self.get_data_directory(14)
    }
}

/// NT Headers structure
#[derive(Debug, Clone)]
pub struct NtHeaders {
    /// NT signature ('PE\0\0')
    pub signature: u32,
    /// File header
    pub file_header: FileHeader,
    /// Optional header
    pub optional_header: OptionalHeader,
}

impl NtHeaders {
    /// NT signature value ('PE\0\0')
    pub const SIGNATURE: u32 = 0x00004550;
    
    /// Parse NT headers from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(PeError::InvalidFormat("Data too small for NT headers".to_string()));
        }
        
        let signature = LittleEndian::read_u32(&data[0..4]);
        if signature != Self::SIGNATURE {
            return Err(PeError::InvalidSignature);
        }
        
        let file_header = FileHeader::parse(&data[4..24])?;
        
        // The size of the optional header is stored in the file header
        let opt_header_size = file_header.size_of_optional_header as usize;
        if data.len() < 4 + FileHeader::SIZE + opt_header_size {
            return Err(PeError::InvalidFormat("Data too small for optional header".to_string()));
        }
        
        let optional_header = OptionalHeader::parse(&data[24..24 + opt_header_size])?;
        
        Ok(Self {
            signature,
            file_header,
            optional_header,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dos_header_parse() {
        // Create a simple valid DOS header
        let mut data = vec![0; 64];
        data[0] = b'M';
        data[1] = b'Z';
        // Set e_lfanew to 0x80
        data[60] = 0x80;
        
        let header = DosHeader::parse(&data).unwrap();
        assert_eq!(header.e_magic, 0x5A4D);
        assert_eq!(header.e_lfanew, 0x80);
    }
    
    #[test]
    fn test_invalid_dos_signature() {
        // Create an invalid DOS header
        let data = vec![0; 64];
        let result = DosHeader::parse(&data);
        assert!(result.is_err());
        
        match result.unwrap_err() {
            PeError::InvalidSignature => {},
            e => panic!("Expected InvalidSignature error, got {:?}", e),
        }
    }
    
    #[test]
    fn test_machine_from_u16() {
        assert_eq!(Machine::from(0x14c), Machine::X86);
        assert_eq!(Machine::from(0x8664), Machine::X64);
        assert_eq!(Machine::from(0x1234), Machine::Other(0x1234));
    }
    
    #[test]
    fn test_file_characteristics() {
        let chars = FileCharacteristics(FileCharacteristics::EXECUTABLE_IMAGE | FileCharacteristics::DLL);
        assert!(chars.has_flag(FileCharacteristics::EXECUTABLE_IMAGE));
        assert!(chars.has_flag(FileCharacteristics::DLL));
        assert!(!chars.has_flag(FileCharacteristics::SYSTEM));
        assert!(chars.is_dll());
        assert!(!chars.is_exe());
    }
}