//! PE section handling
//!
//! This module provides structures and functions for working with PE file sections.

use std::fmt;
use byteorder::{ByteOrder, LittleEndian};
use crate::pe::{PeError, Result};

/// Section characteristics flags
#[derive(Debug, Clone, Copy)]
pub struct SectionCharacteristics(pub u32);

impl SectionCharacteristics {
    // Section characteristics
    pub const TYPE_NO_PAD: u32 = 0x00000008;
    pub const CNT_CODE: u32 = 0x00000020;
    pub const CNT_INITIALIZED_DATA: u32 = 0x00000040;
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    pub const LNK_OTHER: u32 = 0x00000100;
    pub const LNK_INFO: u32 = 0x00000200;
    pub const LNK_REMOVE: u32 = 0x00000800;
    pub const LNK_COMDAT: u32 = 0x00001000;
    pub const GPREL: u32 = 0x00008000;
    pub const MEM_PURGEABLE: u32 = 0x00020000;
    pub const MEM_16BIT: u32 = 0x00020000;
    pub const MEM_LOCKED: u32 = 0x00040000;
    pub const MEM_PRELOAD: u32 = 0x00080000;
    pub const ALIGN_1BYTES: u32 = 0x00100000;
    pub const ALIGN_2BYTES: u32 = 0x00200000;
    pub const ALIGN_4BYTES: u32 = 0x00300000;
    pub const ALIGN_8BYTES: u32 = 0x00400000;
    pub const ALIGN_16BYTES: u32 = 0x00500000;
    pub const ALIGN_32BYTES: u32 = 0x00600000;
    pub const ALIGN_64BYTES: u32 = 0x00700000;
    pub const ALIGN_128BYTES: u32 = 0x00800000;
    pub const ALIGN_256BYTES: u32 = 0x00900000;
    pub const ALIGN_512BYTES: u32 = 0x00A00000;
    pub const ALIGN_1024BYTES: u32 = 0x00B00000;
    pub const ALIGN_2048BYTES: u32 = 0x00C00000;
    pub const ALIGN_4096BYTES: u32 = 0x00D00000;
    pub const ALIGN_8192BYTES: u32 = 0x00E00000;
    pub const LNK_NRELOC_OVFL: u32 = 0x01000000;
    pub const MEM_DISCARDABLE: u32 = 0x02000000;
    pub const MEM_NOT_CACHED: u32 = 0x04000000;
    pub const MEM_NOT_PAGED: u32 = 0x08000000;
    pub const MEM_SHARED: u32 = 0x10000000;
    pub const MEM_EXECUTE: u32 = 0x20000000;
    pub const MEM_READ: u32 = 0x40000000;
    pub const MEM_WRITE: u32 = 0x80000000;
    
    pub fn has_flag(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
    
    pub fn is_code(&self) -> bool {
        self.has_flag(Self::CNT_CODE)
    }
    
    pub fn is_initialized_data(&self) -> bool {
        self.has_flag(Self::CNT_INITIALIZED_DATA)
    }
    
    pub fn is_uninitialized_data(&self) -> bool {
        self.has_flag(Self::CNT_UNINITIALIZED_DATA)
    }
    
    pub fn is_executable(&self) -> bool {
        self.has_flag(Self::MEM_EXECUTE)
    }
    
    pub fn is_readable(&self) -> bool {
        self.has_flag(Self::MEM_READ)
    }
    
    pub fn is_writable(&self) -> bool {
        self.has_flag(Self::MEM_WRITE)
    }
    
    pub fn get_permissions_string(&self) -> String {
        let mut perms = String::new();
        
        if self.is_readable() {
            perms.push('R');
        } else {
            perms.push('-');
        }
        
        if self.is_writable() {
            perms.push('W');
        } else {
            perms.push('-');
        }
        
        if self.is_executable() {
            perms.push('X');
        } else {
            perms.push('-');
        }
        
        perms
    }
}

impl fmt::Display for SectionCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        
        if self.has_flag(Self::TYPE_NO_PAD) { flags.push("TYPE_NO_PAD"); }
        if self.has_flag(Self::CNT_CODE) { flags.push("CNT_CODE"); }
        if self.has_flag(Self::CNT_INITIALIZED_DATA) { flags.push("CNT_INITIALIZED_DATA"); }
        if self.has_flag(Self::CNT_UNINITIALIZED_DATA) { flags.push("CNT_UNINITIALIZED_DATA"); }
        if self.has_flag(Self::LNK_OTHER) { flags.push("LNK_OTHER"); }
        if self.has_flag(Self::LNK_INFO) { flags.push("LNK_INFO"); }
        if self.has_flag(Self::LNK_REMOVE) { flags.push("LNK_REMOVE"); }
        if self.has_flag(Self::LNK_COMDAT) { flags.push("LNK_COMDAT"); }
        if self.has_flag(Self::GPREL) { flags.push("GPREL"); }
        if self.has_flag(Self::MEM_PURGEABLE) { flags.push("MEM_PURGEABLE"); }
        if self.has_flag(Self::MEM_LOCKED) { flags.push("MEM_LOCKED"); }
        if self.has_flag(Self::MEM_PRELOAD) { flags.push("MEM_PRELOAD"); }
        if self.has_flag(Self::LNK_NRELOC_OVFL) { flags.push("LNK_NRELOC_OVFL"); }
        if self.has_flag(Self::MEM_DISCARDABLE) { flags.push("MEM_DISCARDABLE"); }
        if self.has_flag(Self::MEM_NOT_CACHED) { flags.push("MEM_NOT_CACHED"); }
        if self.has_flag(Self::MEM_NOT_PAGED) { flags.push("MEM_NOT_PAGED"); }
        if self.has_flag(Self::MEM_SHARED) { flags.push("MEM_SHARED"); }
        if self.has_flag(Self::MEM_EXECUTE) { flags.push("MEM_EXECUTE"); }
        if self.has_flag(Self::MEM_READ) { flags.push("MEM_READ"); }
        if self.has_flag(Self::MEM_WRITE) { flags.push("MEM_WRITE"); }
        
        // Check alignment flags
        let align_mask = 0x00F00000;
        let align_value = self.0 & align_mask;
        match align_value {
            0x00100000 => flags.push("ALIGN_1BYTES"),
            0x00200000 => flags.push("ALIGN_2BYTES"),
            0x00300000 => flags.push("ALIGN_4BYTES"),
            0x00400000 => flags.push("ALIGN_8BYTES"),
            0x00500000 => flags.push("ALIGN_16BYTES"),
            0x00600000 => flags.push("ALIGN_32BYTES"),
            0x00700000 => flags.push("ALIGN_64BYTES"),
            0x00800000 => flags.push("ALIGN_128BYTES"),
            0x00900000 => flags.push("ALIGN_256BYTES"),
            0x00A00000 => flags.push("ALIGN_512BYTES"),
            0x00B00000 => flags.push("ALIGN_1024BYTES"),
            0x00C00000 => flags.push("ALIGN_2048BYTES"),
            0x00D00000 => flags.push("ALIGN_4096BYTES"),
            0x00E00000 => flags.push("ALIGN_8192BYTES"),
            _ => {}
        }
        
        write!(f, "{}", flags.join(" | "))
    }
}

/// Section header structure
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Section name (8 bytes, null-padded)
    pub name: [u8; 8],
    /// Section virtual size
    pub virtual_size: u32,
    /// Section virtual address
    pub virtual_address: u32,
    /// Section raw data size
    pub size_of_raw_data: u32,
    /// Section raw data pointer
    pub pointer_to_raw_data: u32,
    /// Section relocation pointer
    pub pointer_to_relocations: u32,
    /// Section line number pointer
    pub pointer_to_linenumbers: u32,
    /// Section relocation count
    pub number_of_relocations: u16,
    /// Section line number count
    pub number_of_linenumbers: u16,
    /// Section characteristics
    pub characteristics: SectionCharacteristics,
}

impl SectionHeader {
    /// Size of a section header in bytes
    pub const SIZE: usize = 40;
    
    /// Parse a section header from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(PeError::InvalidFormat("Data too small for section header".to_string()));
        }
        
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[0..8]);
        
        Ok(Self {
            name,
            virtual_size: LittleEndian::read_u32(&data[8..12]),
            virtual_address: LittleEndian::read_u32(&data[12..16]),
            size_of_raw_data: LittleEndian::read_u32(&data[16..20]),
            pointer_to_raw_data: LittleEndian::read_u32(&data[20..24]),
            pointer_to_relocations: LittleEndian::read_u32(&data[24..28]),
            pointer_to_linenumbers: LittleEndian::read_u32(&data[28..32]),
            number_of_relocations: LittleEndian::read_u16(&data[32..34]),
            number_of_linenumbers: LittleEndian::read_u16(&data[34..36]),
            characteristics: SectionCharacteristics(LittleEndian::read_u32(&data[36..40])),
        })
    }
    
    /// Get section name as a string
    pub fn get_name(&self) -> String {
        self.name.iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as char)
            .collect()
    }
    
    /// Check if this is a text section
    pub fn is_text_section(&self) -> bool {
        self.get_name().starts_with(".text") && 
        self.characteristics.is_code() && 
        self.characteristics.is_executable()
    }
    
    /// Check if this is a data section
    pub fn is_data_section(&self) -> bool {
        self.get_name().starts_with(".data") && 
        self.characteristics.is_initialized_data() &&
        !self.characteristics.is_executable()
    }
    
    /// Check if this is a read-only data section
    pub fn is_rdata_section(&self) -> bool {
        self.get_name().starts_with(".rdata") && 
        self.characteristics.is_initialized_data() &&
        !self.characteristics.is_executable() &&
        !self.characteristics.is_writable()
    }
    
    /// Check if this is a BSS section
    pub fn is_bss_section(&self) -> bool {
        self.get_name().starts_with(".bss") && 
        self.characteristics.is_uninitialized_data()
    }
}

/// Base relocation block
#[derive(Debug, Clone)]
pub struct BaseRelocationBlock {
    /// Page RVA
    pub page_rva: u32,
    /// Block size
    pub block_size: u32,
    /// Relocation entries
    pub entries: Vec<BaseRelocationEntry>,
}

impl BaseRelocationBlock {
    /// Size of the base relocation block header in bytes
    pub const HEADER_SIZE: usize = 8;
    
    /// Parse a base relocation block from a byte slice
    pub fn parse(data: &[u8], block_size: u32) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE as usize {
            return Err(PeError::InvalidFormat("Data too small for base relocation block".to_string()));
        }
        
        let page_rva = LittleEndian::read_u32(&data[0..4]);
        let block_size = LittleEndian::read_u32(&data[4..8]);
        
        // Calculate the number of entries
        let num_entries = (block_size as usize - Self::HEADER_SIZE) / 2;
        let mut entries = Vec::with_capacity(num_entries);
        
        for i in 0..num_entries {
            let offset = Self::HEADER_SIZE + (i * 2);
            if offset + 2 > data.len() {
                break;
            }
            
            let entry_data = LittleEndian::read_u16(&data[offset..offset + 2]);
            entries.push(BaseRelocationEntry::from(entry_data));
        }
        
        Ok(Self {
            page_rva,
            block_size,
            entries,
        })
    }
}

/// Base relocation entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseRelocationType {
    /// The base relocation is skipped
    Absolute,
    /// The base relocation applies the difference to the high 16 bits of a 32-bit offset
    High,
    /// The base relocation applies the difference to the low 16 bits of a 32-bit offset
    Low,
    /// The base relocation applies the difference to the high 16 bits of a 32-bit offset
    /// and adjusts for sign extension of the low 16 bits
    HighLow,
    /// The relocation applies to a 64-bit address
    Dir64,
    /// Unknown type
    Unknown(u8),
}

impl From<u8> for BaseRelocationType {
    fn from(value: u8) -> Self {
        match value {
            0 => BaseRelocationType::Absolute,
            1 => BaseRelocationType::High,
            2 => BaseRelocationType::Low,
            3 => BaseRelocationType::HighLow,
            10 => BaseRelocationType::Dir64,
            other => BaseRelocationType::Unknown(other),
        }
    }
}

/// Base relocation entry
#[derive(Debug, Clone, Copy)]
pub struct BaseRelocationEntry {
    /// Type of relocation
    pub reloc_type: BaseRelocationType,
    /// Offset from the page RVA
    pub offset: u16,
}

impl From<u16> for BaseRelocationEntry {
    fn from(value: u16) -> Self {
        let offset = value & 0x0FFF;
        let reloc_type = BaseRelocationType::from(((value >> 12) & 0xF) as u8);
        
        Self {
            reloc_type,
            offset,
        }
    }
}

/// Base relocation directory
#[derive(Debug, Clone)]
pub struct BaseRelocation {
    /// Relocation blocks
    pub blocks: Vec<BaseRelocationBlock>,
}

impl BaseRelocation {
    /// Parse a base relocation directory from a byte slice
    pub fn parse(data: &[u8], size: u32) -> Result<Self> {
        if data.is_empty() {
            return Err(PeError::InvalidFormat("Empty base relocation directory".to_string()));
        }
        
        let mut blocks = Vec::new();
        let mut offset = 0;
        
        while offset < size as usize {
            if offset + BaseRelocationBlock::HEADER_SIZE > data.len() {
                break;
            }
            
            let block_size = LittleEndian::read_u32(&data[offset + 4..offset + 8]) as usize;
            if block_size < BaseRelocationBlock::HEADER_SIZE || offset + block_size > data.len() {
                break;
            }
            
            let block = BaseRelocationBlock::parse(&data[offset..offset + block_size], block_size as u32)?;
            blocks.push(block);
            
            offset += block_size;
        }
        
        Ok(Self { blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_section_characteristics() {
        let chars = SectionCharacteristics(
            SectionCharacteristics::CNT_CODE | 
            SectionCharacteristics::MEM_EXECUTE | 
            SectionCharacteristics::MEM_READ
        );
        
        assert!(chars.has_flag(SectionCharacteristics::CNT_CODE));
        assert!(chars.has_flag(SectionCharacteristics::MEM_EXECUTE));
        assert!(chars.has_flag(SectionCharacteristics::MEM_READ));
        assert!(!chars.has_flag(SectionCharacteristics::MEM_WRITE));
        
        assert!(chars.is_code());
        assert!(chars.is_executable());
        assert!(chars.is_readable());
        assert!(!chars.is_writable());
        
        assert_eq!(chars.get_permissions_string(), "RX-");
    }
    
    #[test]
    fn test_section_header_parse() {
        let mut data = vec![0; SectionHeader::SIZE];
        
        // Set name to ".text"
        data[0] = b'.';
        data[1] = b't';
        data[2] = b'e';
        data[3] = b'x';
        data[4] = b't';
        
        // Set virtual size to 0x1000
        data[8] = 0x00;
        data[9] = 0x10;
        data[10] = 0x00;
        data[11] = 0x00;
        
        // Set characteristics to code + execute + read
        let chars = SectionCharacteristics::CNT_CODE | 
                   SectionCharacteristics::MEM_EXECUTE | 
                   SectionCharacteristics::MEM_READ;
        
        data[36] = (chars & 0xFF) as u8;
        data[37] = ((chars >> 8) & 0xFF) as u8;
        data[38] = ((chars >> 16) & 0xFF) as u8;
        data[39] = ((chars >> 24) & 0xFF) as u8;
        
        let section = SectionHeader::parse(&data).unwrap();
        
        assert_eq!(section.get_name(), ".text");
        assert_eq!(section.virtual_size, 0x1000);
        assert!(section.characteristics.is_code());
        assert!(section.characteristics.is_executable());
        assert!(section.characteristics.is_readable());
        assert!(!section.characteristics.is_writable());
        assert!(section.is_text_section());
    }
    
    #[test]
    fn test_base_relocation_entry() {
        // Test a HIGHLOW type relocation with offset 0x123
        let entry_value: u16 = (3 << 12) | 0x123;
        let entry = BaseRelocationEntry::from(entry_value);
        
        assert!(matches!(entry.reloc_type, BaseRelocationType::HighLow));
        assert_eq!(entry.offset, 0x123);
    }
}