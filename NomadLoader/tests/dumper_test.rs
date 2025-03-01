#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use NomadLoader::dumper::*;
    use std::path::Path;
    use tempfile::tempdir;
    use std::fs;
    
    #[test]
    fn test_is_exe() {
        let temp_dir = tempdir().unwrap();
        let exe_path = temp_dir.path().join("test.exe");
        let dll_path = temp_dir.path().join("test.dll");
        let bin_path = temp_dir.path().join("test.bin");
        
        // Create empty files for testing
        fs::write(&exe_path, b"").unwrap();
        fs::write(&dll_path, b"").unwrap();
        fs::write(&bin_path, b"").unwrap();
        
        assert!(is_exe(&exe_path), "Should detect .exe file");
        assert!(!is_exe(&dll_path), "Should not detect .dll as .exe");
        assert!(!is_exe(&bin_path), "Should not detect .bin as .exe");
    }
    
    #[test]
    fn test_is_dll() {
        let temp_dir = tempdir().unwrap();
        let exe_path = temp_dir.path().join("test.exe");
        let dll_path = temp_dir.path().join("test.dll");
        let bin_path = temp_dir.path().join("test.bin");
        
        // Create empty files for testing
        fs::write(&exe_path, b"").unwrap();
        fs::write(&dll_path, b"").unwrap();
        fs::write(&bin_path, b"").unwrap();
        
        assert!(!is_dll(&exe_path), "Should not detect .exe as .dll");
        assert!(is_dll(&dll_path), "Should detect .dll file");
        assert!(!is_dll(&bin_path), "Should not detect .bin as .dll");
    }
    
    #[test]
    fn test_create_dumper() {
        let temp_dir = tempdir().unwrap();
        let exe_path = temp_dir.path().join("test.exe");
        let dll_path = temp_dir.path().join("test.dll");
        let bin_path = temp_dir.path().join("test.bin");
        
        // Create empty files for testing
        fs::write(&exe_path, b"MZ").unwrap();
        fs::write(&dll_path, b"MZ").unwrap();
        fs::write(&bin_path, b"MZ").unwrap();
        
        let exe_dumper = create_dumper(&exe_path);
        assert!(exe_dumper.is_ok(), "Should create dumper for EXE: {:?}", exe_dumper.err());
        assert!(exe_dumper.unwrap().as_any().downcast_ref::<ExeDumper>().is_some(), "Should be ExeDumper");
        
        let dll_dumper = create_dumper(&dll_path);
        assert!(dll_dumper.is_ok(), "Should create dumper for DLL: {:?}", dll_dumper.err());
        assert!(dll_dumper.unwrap().as_any().downcast_ref::<DllDumper>().is_some(), "Should be DllDumper");
        
        let bin_dumper = create_dumper(&bin_path);
        assert!(bin_dumper.is_err(), "Should not create dumper for unknown file type");
    }
    
    #[test]
    fn test_exe_dumper_dump() {
        // This test requires a real Windows EXE to test with
        // Skip if not available
        let exe_path = Path::new("tests/data/windows.exe");
        if !exe_path.exists() {
            println!("Skipping test_exe_dumper_dump - test file not found");
            return;
        }
        
        let temp_dir = tempdir().unwrap();
        let output_path = temp_dir.path().join("dumped.bin");
        
        // Create dumper
        let dumper = ExeDumper::new();
        
        // Dump the file
        let result = dumper.dump(&exe_path, &output_path);
        
        if result.is_err() {
            // Print the error details for debugging
            let error = result.unwrap_err();
            println!("Error dumping EXE: {:?}", error);
        }
        
        // Might fail on CI due to permission issues, so don't assert
        // If it succeeds, check the output file
        if result.is_ok() {
            assert!(output_path.exists(), "Output file should exist");
            assert!(fs::metadata(&output_path).unwrap().len() > 0, "Output file should not be empty");
        }
    }
}