//! Tests for parsing PE headers from a file

use pe_tests::DosHeader;
use std::fs::read;

#[test]
fn test_dos_header_from_file() {
    // Read test file
    let data = match read("test-pe-header.bin") {
        Ok(data) => data,
        Err(e) => {
            println!("Failed to read test file: {}", e);
            panic!("Test file not found");
        }
    };
    
    println!("Read {} bytes from test file", data.len());
    
    match DosHeader::parse(&data) {
        Some(header) => {
            println!("Successfully parsed DOS header from file:");
            println!("  Magic: 0x{:04X}", header.e_magic);
            println!("  New EXE header offset: 0x{:08X}", header.e_lfanew);
            
            assert_eq!(header.e_magic, 0x5A4D); // "MZ" in little-endian
            assert_eq!(header.e_lfanew, 0x80);
            println!("✓ DOS header values verified from file");
        },
        None => {
            panic!("Failed to parse DOS header from file");
        }
    }
}