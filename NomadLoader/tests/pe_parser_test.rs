#[cfg(test)]
mod tests {
    use NomadLoader::pe::*;
    use std::path::Path;
    
    #[test]
    #[cfg(target_os = "windows")]
    fn test_parse_exe() {
        // This test requires windows.exe to exist in the test directory
        // Skip if not present
        let exe_path = Path::new("tests/data/windows.exe");
        if !exe_path.exists() {
            println!("Skipping test_parse_exe - test file not found");
            return;
        }
        
        // Try parsing the file
        let result = PeFile::from_file(exe_path);
        assert!(result.is_ok(), "Failed to parse PE file: {:?}", result.err());
        
        let pe = result.unwrap();
        
        // Basic validations
        assert_eq!(pe.dos_header.e_magic, 0x5A4D, "DOS magic number mismatch");
        assert!(pe.dos_header.e_lfanew > 0, "e_lfanew should be positive");
        assert_eq!(pe.nt_headers.signature, 0x00004550, "NT signature mismatch");
        
        // Validate file header
        assert_eq!(pe.nt_headers.file_header.machine, Machine::X64, "Machine type mismatch");
        assert!(pe.nt_headers.file_header.number_of_sections > 0, "No sections found");
        
        // Validate optional header
        assert!(pe.nt_headers.optional_header.address_of_entry_point > 0, "No entry point");
        assert!(pe.nt_headers.optional_header.image_base > 0, "Invalid image base");
        assert!(pe.nt_headers.optional_header.size_of_image > 0, "Invalid image size");
        
        // Validate sections
        assert!(!pe.sections.is_empty(), "No sections found");
        
        // Find .text section
        let text_section = pe.sections.iter()
            .find(|s| s.get_name().starts_with(".text"))
            .expect("No .text section found");
        
        assert!(text_section.virtual_size > 0, "Invalid .text section size");
        assert!(text_section.characteristics.is_code(), ".text should be code");
        assert!(text_section.characteristics.is_executable(), ".text should be executable");
        
        // Validate imports
        assert!(!pe.imports.is_empty(), "No imports found");
        
        // Check for kernel32.dll
        let kernel32 = pe.imports.iter()
            .find(|i| i.dll_name.to_lowercase() == "kernel32.dll")
            .expect("No kernel32.dll imports found");
        
        assert!(!kernel32.entries.is_empty(), "No kernel32.dll functions imported");
    }
}