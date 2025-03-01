//! PE import handling
//!
//! This module provides structures and functions for working with PE file imports.

use byteorder::{ByteOrder, LittleEndian};
use std::ffi::{CStr, CString};
use std::fmt;
use crate::pe::{PeError, Result};

/// Import descriptor structure
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// RVA to the Import Lookup Table (ILT)
    pub original_first_thunk: u32,
    /// Time/date stamp
    pub time_date_stamp: u32,
    /// Forwarder chain
    pub forwarder_chain: u32,
    /// RVA to the DLL name
    pub name: u32,
    /// RVA to the Import Address Table (IAT)
    pub first_thunk: u32,
    /// Name of the imported DLL
    pub dll_name: String,
    /// Import entries for this descriptor
    pub entries: Vec<ImportEntry>,
}

impl ImportDescriptor {
    /// Size of an import descriptor in bytes
    pub const SIZE: usize = 20;
    
    /// Parse an import descriptor from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(PeError::InvalidFormat("Data too small for import descriptor".to_string()));
        }
        
        Ok(Self {
            original_first_thunk: LittleEndian::read_u32(&data[0..4]),
            time_date_stamp: LittleEndian::read_u32(&data[4..8]),
            forwarder_chain: LittleEndian::read_u32(&data[8..12]),
            name: LittleEndian::read_u32(&data[12..16]),
            first_thunk: LittleEndian::read_u32(&data[16..20]),
            dll_name: String::new(), // Will be set later
            entries: Vec::new(),     // Will be set later
        })
    }
    
    /// Check if this is a valid import descriptor
    pub fn is_valid(&self) -> bool {
        // An import descriptor is valid if it has a name and either an ILT or IAT
        self.name != 0 && (self.original_first_thunk != 0 || self.first_thunk != 0)
    }
    
    /// Check if this is a terminating import descriptor (all zeros)
    pub fn is_terminator(&self) -> bool {
        self.original_first_thunk == 0 &&
        self.time_date_stamp == 0 &&
        self.forwarder_chain == 0 &&
        self.name == 0 &&
        self.first_thunk == 0
    }
}

/// Import entry
#[derive(Debug, Clone)]
pub enum ImportEntry {
    /// Import by name
    ByName {
        /// Hint value
        hint: u16,
        /// Name of the imported function
        name: String,
    },
    /// Import by ordinal
    ByOrdinal {
        /// Ordinal value
        ordinal: u16,
    },
}

impl ImportEntry {
    /// Size of an import entry in 32-bit PE files
    pub const SIZE_32: usize = 4;
    
    /// Size of an import entry in 64-bit PE files
    pub const SIZE_64: usize = 8;
    
    /// Mask for import by ordinal in 32-bit PE files
    pub const ORDINAL_FLAG_32: u32 = 0x80000000;
    
    /// Mask for import by ordinal in 64-bit PE files
    pub const ORDINAL_FLAG_64: u64 = 0x8000000000000000;
    
    /// Parse an import entry from a byte slice in a 32-bit PE
    pub fn parse_32(data: &[u8], pe_data: &[u8], rva_to_offset: impl Fn(u32) -> Option<u32>) -> Result<Self> {
        if data.len() < Self::SIZE_32 {
            return Err(PeError::InvalidFormat("Data too small for import entry (32-bit)".to_string()));
        }
        
        let value = LittleEndian::read_u32(data);
        
        // Check if this is an import by ordinal
        if value & Self::ORDINAL_FLAG_32 != 0 {
            let ordinal = (value & 0xFFFF) as u16;
            return Ok(ImportEntry::ByOrdinal { ordinal });
        } else if value == 0 {
            // This is a terminating entry
            return Err(PeError::InvalidFormat("Terminating import entry".to_string()));
        } else {
            // This is an import by name
            // The value is an RVA to a HINT/NAME structure
            let rva = value;
            let offset = rva_to_offset(rva)
                .ok_or_else(|| PeError::InvalidFormat(format!("Invalid RVA for import name: 0x{:08x}", rva)))?;
            
            if offset as usize + 2 >= pe_data.len() {
                return Err(PeError::InvalidFormat("Import name pointer out of bounds".to_string()));
            }
            
            let hint = LittleEndian::read_u16(&pe_data[offset as usize..offset as usize + 2]);
            
            // Read the name (null-terminated ASCII string)
            let name_offset = offset as usize + 2;
            let name = extract_c_string(&pe_data[name_offset..])?;
            
            Ok(ImportEntry::ByName { hint, name })
        }
    }
    
    /// Parse an import entry from a byte slice in a 64-bit PE
    pub fn parse_64(data: &[u8], pe_data: &[u8], rva_to_offset: impl Fn(u32) -> Option<u32>) -> Result<Self> {
        if data.len() < Self::SIZE_64 {
            return Err(PeError::InvalidFormat("Data too small for import entry (64-bit)".to_string()));
        }
        
        let value = LittleEndian::read_u64(data);
        
        // Check if this is an import by ordinal
        if value & Self::ORDINAL_FLAG_64 != 0 {
            let ordinal = (value & 0xFFFF) as u16;
            return Ok(ImportEntry::ByOrdinal { ordinal });
        } else if value == 0 {
            // This is a terminating entry
            return Err(PeError::InvalidFormat("Terminating import entry".to_string()));
        } else {
            // This is an import by name
            // The value is an RVA to a HINT/NAME structure
            let rva = value as u32;
            let offset = rva_to_offset(rva)
                .ok_or_else(|| PeError::InvalidFormat(format!("Invalid RVA for import name: 0x{:08x}", rva)))?;
            
            if offset as usize + 2 >= pe_data.len() {
                return Err(PeError::InvalidFormat("Import name pointer out of bounds".to_string()));
            }
            
            let hint = LittleEndian::read_u16(&pe_data[offset as usize..offset as usize + 2]);
            
            // Read the name (null-terminated ASCII string)
            let name_offset = offset as usize + 2;
            let name = extract_c_string(&pe_data[name_offset..])?;
            
            Ok(ImportEntry::ByName { hint, name })
        }
    }
}

impl fmt::Display for ImportEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportEntry::ByName { hint, name } => write!(f, "{}@{}", name, hint),
            ImportEntry::ByOrdinal { ordinal } => write!(f, "Ordinal#{}", ordinal),
        }
    }
}

/// Delayed import descriptor structure
#[derive(Debug, Clone)]
pub struct DelayImportDescriptor {
    /// Reserved, must be zero
    pub attributes: u32,
    /// RVA to the name of the DLL
    pub name: u32,
    /// RVA to the HMODULE handle
    pub module: u32,
    /// RVA to the IAT
    pub delay_import_address_table: u32,
    /// RVA to the INT
    pub delay_import_name_table: u32,
    /// RVA to the bound IAT
    pub bound_delay_import_table: u32,
    /// RVA to the Unload IAT
    pub unload_delay_import_table: u32,
    /// Same as time stamp in the header
    pub timestamp: u32,
    /// Name of the imported DLL
    pub dll_name: String,
    /// Import entries for this descriptor
    pub entries: Vec<ImportEntry>,
}

impl DelayImportDescriptor {
    /// Size of a delay import descriptor in bytes
    pub const SIZE: usize = 32;
    
    /// Parse a delay import descriptor from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(PeError::InvalidFormat("Data too small for delay import descriptor".to_string()));
        }
        
        Ok(Self {
            attributes: LittleEndian::read_u32(&data[0..4]),
            name: LittleEndian::read_u32(&data[4..8]),
            module: LittleEndian::read_u32(&data[8..12]),
            delay_import_address_table: LittleEndian::read_u32(&data[12..16]),
            delay_import_name_table: LittleEndian::read_u32(&data[16..20]),
            bound_delay_import_table: LittleEndian::read_u32(&data[20..24]),
            unload_delay_import_table: LittleEndian::read_u32(&data[24..28]),
            timestamp: LittleEndian::read_u32(&data[28..32]),
            dll_name: String::new(), // Will be set later
            entries: Vec::new(),     // Will be set later
        })
    }
    
    /// Check if this is a valid delay import descriptor
    pub fn is_valid(&self) -> bool {
        // A delay import descriptor is valid if it has a name and a name table
        self.name != 0 && self.delay_import_name_table != 0
    }
    
    /// Check if this is a terminating delay import descriptor (all zeros or name is zero)
    pub fn is_terminator(&self) -> bool {
        self.name == 0
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_import_descriptor_parse() {
        let mut data = vec![0; ImportDescriptor::SIZE];
        
        // Set original_first_thunk to 0x1000
        data[0] = 0x00;
        data[1] = 0x10;
        data[2] = 0x00;
        data[3] = 0x00;
        
        // Set name to 0x2000
        data[12] = 0x00;
        data[13] = 0x20;
        data[14] = 0x00;
        data[15] = 0x00;
        
        // Set first_thunk to 0x3000
        data[16] = 0x00;
        data[17] = 0x30;
        data[18] = 0x00;
        data[19] = 0x00;
        
        let descriptor = ImportDescriptor::parse(&data).unwrap();
        
        assert_eq!(descriptor.original_first_thunk, 0x1000);
        assert_eq!(descriptor.name, 0x2000);
        assert_eq!(descriptor.first_thunk, 0x3000);
        assert!(descriptor.is_valid());
        assert!(!descriptor.is_terminator());
    }
    
    #[test]
    fn test_import_descriptor_terminator() {
        let data = vec![0; ImportDescriptor::SIZE];
        
        let descriptor = ImportDescriptor::parse(&data).unwrap();
        
        assert_eq!(descriptor.original_first_thunk, 0);
        assert_eq!(descriptor.name, 0);
        assert_eq!(descriptor.first_thunk, 0);
        assert!(!descriptor.is_valid());
        assert!(descriptor.is_terminator());
    }
    
}