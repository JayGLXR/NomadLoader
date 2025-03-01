//! DLL dumping functionality
//!
//! This module provides functionality for dumping DLL files from disk.

use crate::dumper::{PeDumper, Result, DumperError};
use std::path::Path;
use std::fs::File;
use std::io::Write;
use std::any::Any;
use log::{debug, info};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_SHARE_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
};
use windows::Win32::System::Memory::{
    CreateFileMappingA, MapViewOfFile, FILE_MAP_READ, SEC_IMAGE_NO_EXECUTE,
    UnmapViewOfFile, PAGE_READONLY,
};
use windows::core::PCSTR;

/// Structure for dumping DLL files
pub struct DllDumper {
    is_64bit: bool,
}

impl DllDumper {
    /// Create a new DLL dumper
    pub fn new() -> Self {
        // We could detect architecture here, but we'll use the same approach
        // as in ExeDumper for consistency
        #[cfg(target_os = "windows")]
        let is_64bit = {
            let mut system_info = windows::Win32::System::SystemInformation::SYSTEM_INFO::default();
            unsafe { windows::Win32::System::SystemInformation::GetNativeSystemInfo(&mut system_info); }
            
            match unsafe { system_info.Anonymous.Anonymous.wProcessorArchitecture } {
                windows::Win32::System::Diagnostics::Debug::PROCESSOR_ARCHITECTURE_AMD64 => true,
                windows::Win32::System::Diagnostics::Debug::PROCESSOR_ARCHITECTURE_INTEL => false,
                _ => {
                    debug!("Unknown processor architecture, assuming 64-bit");
                    true
                }
            }
        };
        
        #[cfg(not(target_os = "windows"))]
        let is_64bit = true; // Default to 64-bit for non-Windows builds
        
        Self { is_64bit }
    }
}

impl PeDumper for DllDumper {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    #[cfg(target_os = "windows")]
    fn dump(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        info!("Dumping DLL file: {}", input_path.display());
        
        // Convert the path to a C string
        let input_path_str = input_path.to_string_lossy().to_string();
        let mut input_path_cstr = input_path_str.clone().into_bytes();
        input_path_cstr.push(0); // Null terminator
        
        // Open the DLL file
        let file_handle = unsafe {
            CreateFileA(
                PCSTR(input_path_cstr.as_ptr()),
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            )
        };
        
        if file_handle.is_invalid() {
            return Err(DumperError::WindowsApi(windows::Win32::Foundation::GetLastError().0));
        }
        
        // Ensure the file handle will be closed when we're done
        let _file_guard = scopeguard::guard(file_handle, |handle| {
            unsafe { CloseHandle(handle); }
        });
        
        // Create a file mapping
        let mapping_handle = unsafe {
            CreateFileMappingA(
                file_handle,
                None,
                PAGE_READONLY | SEC_IMAGE_NO_EXECUTE,
                0,
                0,
                PCSTR::null(),
            )
        };
        
        if mapping_handle.is_invalid() {
            return Err(DumperError::WindowsApi(windows::Win32::Foundation::GetLastError().0));
        }
        
        // Ensure the mapping handle will be closed when we're done
        let _mapping_guard = scopeguard::guard(mapping_handle, |handle| {
            unsafe { CloseHandle(handle); }
        });
        
        // Map the file into memory
        let base_address = unsafe {
            MapViewOfFile(
                mapping_handle,
                FILE_MAP_READ,
                0,
                0,
                0,
            )
        };
        
        if base_address.is_null() {
            return Err(DumperError::WindowsApi(windows::Win32::Foundation::GetLastError().0));
        }
        
        // Ensure the view will be unmapped when we're done
        let _view_guard = scopeguard::guard(base_address, |addr| {
            unsafe { UnmapViewOfFile(addr); }
        });
        
        info!("DLL mapped at address: 0x{:X}", base_address as usize);
        
        // Read the DOS header to get e_lfanew
        let dos_header_ptr = base_address as *const u8;
        let e_lfanew_offset = unsafe { std::slice::from_raw_parts(dos_header_ptr, 0x40) };
        let e_lfanew = u32::from_le_bytes([
            e_lfanew_offset[0x3C], 
            e_lfanew_offset[0x3D], 
            e_lfanew_offset[0x3E], 
            e_lfanew_offset[0x3F]
        ]);
        info!("e_lfanew: 0x{:X}", e_lfanew);
        
        // Read the optional header to get the image size
        let pe_header_ptr = unsafe { dos_header_ptr.add(e_lfanew as usize) };
        let optional_header_ptr = unsafe { pe_header_ptr.add(24) }; // Skip PE signature (4) and file header (20)
        
        // Read the image size
        let image_size_ptr = unsafe { optional_header_ptr.add(0x50 - 24) };
        let image_size_bytes = unsafe { std::slice::from_raw_parts(image_size_ptr, 4) };
        let image_size = u32::from_le_bytes([
            image_size_bytes[0],
            image_size_bytes[1],
            image_size_bytes[2],
            image_size_bytes[3],
        ]);
        info!("Size of image: 0x{:X}", image_size);
        
        // Get the size of the optional header
        let file_header_ptr = unsafe { pe_header_ptr.add(4) };
        let size_of_optional_header_ptr = unsafe { file_header_ptr.add(16) };
        let size_of_optional_header_bytes = unsafe { std::slice::from_raw_parts(size_of_optional_header_ptr, 2) };
        let size_of_optional_header = u16::from_le_bytes([
            size_of_optional_header_bytes[0],
            size_of_optional_header_bytes[1],
        ]);
        info!("Size of optional header: 0x{:X}", size_of_optional_header);
        
        // Calculate the offset to the first section header
        let first_section_ptr = unsafe { 
            pe_header_ptr.add(4 + 20 + size_of_optional_header as usize) 
        };
        
        // Read the first section header (assumed to be .text)
        let text_section_header_bytes = unsafe { 
            std::slice::from_raw_parts(first_section_ptr, 40) 
        };
        
        // Extract the virtual size of the .text section
        let text_size = u32::from_le_bytes([
            text_section_header_bytes[8],
            text_section_header_bytes[9],
            text_section_header_bytes[10],
            text_section_header_bytes[11],
        ]);
        
        // Align to page boundary
        let text_size_aligned = (text_size + 0x0FFF) & !0x0FFF;
        info!("Size of .text section: 0x{:X} (aligned: 0x{:X})", text_size, text_size_aligned);
        
        // Calculate the size of other sections
        let other_sections_size = image_size - text_size_aligned - 0x1000; // Subtract text section and headers
        let other_sections_size_aligned = (other_sections_size + 0x0FFF) & !0x0FFF;
        info!("Size of other sections: 0x{:X} (aligned: 0x{:X})", other_sections_size, other_sections_size_aligned);
        
        // Suggest memory allocation
        self.suggest_memory_allocation(text_size_aligned, other_sections_size_aligned);
        
        // Create a buffer for the entire image
        let image_data = unsafe { 
            std::slice::from_raw_parts(base_address as *const u8, image_size as usize).to_vec() 
        };
        
        // Write the image to the output file
        let mut output_file = File::create(output_path)?;
        output_file.write_all(&image_data)?;
        
        info!("Image successfully dumped to: {}", output_path.display());
        info!("Total bytes written: 0x{:X}", image_data.len());
        
        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    fn dump(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        Err(DumperError::Unsupported("DLL dumping is only supported on Windows".to_string()))
    }
    
    fn suggest_memory_allocation(&self, text_size: u32, other_section_size: u32) {
        println!("\n[!] Suggested memory allocations, please adjust accordingly with other memory allocation APIs and languages\n");
        println!("// Allocate memory with RX permission for shellcode stub");
        println!("LPVOID buffer = VirtualAlloc(NULL, 0x1000, 0x3000, 0x20);");
        println!("// Allocate memory with RW permission for PE Header");
        println!("VirtualAlloc(buffer + 0x1000, 0x1000, 0x3000, 0x04);");
        println!("// Allocate memory with RX permission for text section");
        println!("VirtualAlloc(buffer + 0x2000, 0x{:X}, 0x3000, 0x20);", text_size);
        println!("// Allocate memory with RW permission for other sections");
        println!("VirtualAlloc(buffer + 0x2000 + 0x{:X}, 0x{:X}, 0x3000, 0x04);", text_size, other_section_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    
    #[test]
    #[cfg(target_os = "windows")]
    fn test_create_dumper() {
        let temp_dir = tempdir().unwrap();
        let dll_path = temp_dir.path().join("test.dll");
        
        // Create empty file for testing
        fs::write(&dll_path, b"MZ").unwrap();
        
        let dumper = crate::dumper::create_dumper(&dll_path).unwrap();
        assert!(dumper.as_any().downcast_ref::<DllDumper>().is_some());
    }
}