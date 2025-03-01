// PE file parsing concepts test
//
// This is a separate, isolated project to verify our understanding of PE file parsing
// without relying on the main codebase. We're testing the core concepts that will be
// used in the main project.

use pe_tests::{DosHeader, extract_c_string};

fn main() {
    println!("===== Testing DOS Header Parsing =====");
    test_dos_header();
    
    println!("\n===== Testing C String Extraction =====");
    test_c_string();
    
    println!("\nAll tests passed successfully!");
}

fn test_dos_header() {
    // Create a realistic DOS header with proper fields
    // This is a minimal DOS header with correct structure
    let mut sample_dos_header = vec![0u8; 64];
    
    // DOS Header signature "MZ"
    sample_dos_header[0] = b'M';  // 0x4D
    sample_dos_header[1] = b'Z';  // 0x5A
    
    // Set e_lfanew to 0x80 (Little endian: 80 00 00 00)
    sample_dos_header[0x3C] = 0x80;
    sample_dos_header[0x3D] = 0x00;
    sample_dos_header[0x3E] = 0x00;
    sample_dos_header[0x3F] = 0x00;
    
    match DosHeader::parse(&sample_dos_header) {
        Some(header) => {
            println!("Successfully parsed DOS header:");
            println!("  Magic: 0x{:04X}", header.e_magic);
            println!("  New EXE header offset: 0x{:08X}", header.e_lfanew);
            
            assert_eq!(header.e_magic, 0x5A4D); // "MZ" in little-endian
            assert_eq!(header.e_lfanew, 0x80);
            println!("✓ DOS header values verified");
        },
        None => {
            panic!("Failed to parse DOS header");
        }
    }
}

fn test_c_string() {
    // Test C string extraction
    let data = b"test\0string";
    let result = extract_c_string(data);
    println!("Extracted C string: \"{}\"", result);
    assert_eq!(result, "test");
    println!("✓ C string extraction works correctly");
    
    // Test empty string
    let empty = b"\0more data";
    let result = extract_c_string(empty);
    println!("Extracted empty C string: \"{}\"", result);
    assert_eq!(result, "");
    println!("✓ Empty C string handling works correctly");
    
    // Test string with no null terminator
    let no_null = b"no null terminator";
    let result = extract_c_string(no_null);
    println!("Extracted non-terminated string: \"{}\"", result);
    assert_eq!(result, "no null terminator");
    println!("✓ Non-terminated string handling works correctly");
}
