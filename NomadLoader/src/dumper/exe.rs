//! EXE dumping functionality
//!
//! This module provides functionality for dumping EXE files from memory.

use crate::dumper::{PeDumper, Result, DumperError};
use std::path::Path;
use std::fs::File;
use std::io::Write;
use std::any::Any;
use log::{debug, info};

use windows::Win32::Foundation::{CloseHandle, HANDLE, BOOL};
use windows::Win32::System::Threading::{
    CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA,
    PROCESS_CREATION_FLAGS, CREATE_SUSPENDED, CREATE_NEW_CONSOLE,
    TerminateProcess, ResumeThread,
};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, PROCESSOR_ARCHITECTURE_INTEL, PROCESSOR_ARCHITECTURE_AMD64};
use windows::Win32::System::ProcessStatus::{
    K32GetModuleInformation, K32EnumProcessModules, MODULEINFO,
};
use windows::core::{PCSTR, PSTR};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::Foundation::INFINITE;

#[cfg(target_os = "windows")]
use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO, SYSTEM_INFO_0, SYSTEM_INFO_0_0};

/// Structure for dumping EXE files
pub struct ExeDumper {
    is_64bit: bool,
}

impl ExeDumper {
    /// Create a new EXE dumper
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        let is_64bit = {
            let mut system_info = SYSTEM_INFO::default();
            unsafe { GetNativeSystemInfo(&mut system_info); }
            
            match unsafe { system_info.Anonymous.Anonymous.wProcessorArchitecture } {
                PROCESSOR_ARCHITECTURE_AMD64 => true,
                PROCESSOR_ARCHITECTURE_INTEL => false,
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
    
    /// Helper function to get the base address of the main module in a suspended process
    #[cfg(target_os = "windows")]
    fn get_process_base_address(&self, process_handle: HANDLE) -> Result<usize> {
        let mut module_handles = [HANDLE::default(); 1024];
        let mut bytes_needed = 0;
        
        let result = unsafe { 
            K32EnumProcessModules(
                process_handle,
                module_handles.as_mut_ptr(),
                std::mem::size_of_val(&module_handles) as u32,
                &mut bytes_needed,
            )
        };
        
        if !result.as_bool() {
            return Err(DumperError::WindowsApi(windows::Win32::Foundation::GetLastError().0));
        }
        
        // Get information about the first module (the main executable)
        let mut module_info = MODULEINFO::default();
        let result = unsafe {
            K32GetModuleInformation(
                process_handle,
                module_handles[0],
                &mut module_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        };
        
        if !result.as_bool() {
            return Err(DumperError::WindowsApi(windows::Win32::Foundation::GetLastError().0));
        }
        
        Ok(module_info.lpBaseOfDll as usize)
    }
    
    /// Helper function to read memory from a process
    #[cfg(target_os = "windows")]
    fn read_process_memory(&self, process_handle: HANDLE, base_address: usize, size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;
        
        let result = unsafe {
            ReadProcessMemory(
                process_handle,
                base_address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            )
        };
        
        if !result.as_bool() || bytes_read != size {
            return Err(DumperError::WindowsApi(windows::Win32::Foundation::GetLastError().0));
        }
        
        Ok(buffer)
    }
}

impl PeDumper for ExeDumper {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    #[cfg(target_os = "windows")]
    fn dump(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        info!("Dumping EXE file: {}", input_path.display());
        
        // Convert the path to a C string
        let input_path_str = input_path.to_string_lossy().to_string();
        let mut input_path_cstr = input_path_str.clone().into_bytes();
        input_path_cstr.push(0); // Null terminator
        
        // Create the process in suspended state
        let mut startup_info = STARTUPINFOA::default();
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        
        let mut process_info = PROCESS_INFORMATION::default();
        
        let result = unsafe {
            CreateProcessA(
                PCSTR(input_path_cstr.as_ptr()),
                PSTR(std::ptr::null_mut()),
                None,
                None,
                BOOL::from(false),
                CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                None,
                PCSTR(std::ptr::null()),
                &startup_info,
                &mut process_info,
            )
        };
        
        if !result.as_bool() {
            return Err(DumperError::WindowsApi(windows::Win32::Foundation::GetLastError().0));
        }
        
        // Ensure the process will be terminated and handle closed when we're done
        let _process_guard = scopeguard::guard(process_info.hProcess, |handle| {
            unsafe {
                TerminateProcess(handle, 0);
                CloseHandle(handle);
            }
        });
        
        let _thread_guard = scopeguard::guard(process_info.hThread, |handle| {
            unsafe { CloseHandle(handle); }
        });
        
        info!("Process created with PID: {}", process_info.dwProcessId);
        
        // Get the base address of the main module
        let base_address = self.get_process_base_address(process_info.hProcess)?;
        info!("Image base address: 0x{:X}", base_address);
        
        // Read the DOS header to get e_lfanew
        let dos_header = self.read_process_memory(process_info.hProcess, base_address, 0x40)?;
        let e_lfanew = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]);
        info!("e_lfanew: 0x{:X}", e_lfanew);
        
        // Read the optional header to get the image size
        let pe_header_offset = base_address + e_lfanew as usize;
        let optional_header_offset = pe_header_offset + 24; // Skip PE signature (4) and file header (20)
        
        // Read the optional header
        let optional_header = self.read_process_memory(
            process_info.hProcess, 
            optional_header_offset, 
            if self.is_64bit { 240 } else { 224 }
        )?;
        
        // Get the image size
        let image_size = u32::from_le_bytes([
            optional_header[0x50 - 24], 
            optional_header[0x51 - 24], 
            optional_header[0x52 - 24], 
            optional_header[0x53 - 24]
        ]);
        info!("Size of image: 0x{:X}", image_size);
        
        // Get the size of the optional header
        let file_header = self.read_process_memory(process_info.hProcess, pe_header_offset + 4, 20)?;
        let size_of_optional_header = u16::from_le_bytes([file_header[16], file_header[17]]);
        info!("Size of optional header: 0x{:X}", size_of_optional_header);
        
        // Calculate the offset to the first section header
        let first_section_offset = pe_header_offset + 4 + 20 + size_of_optional_header as usize;
        
        // Read the first section header (assumed to be .text)
        let text_section_header = self.read_process_memory(process_info.hProcess, first_section_offset, 40)?;
        
        // Extract the virtual size of the .text section
        let text_size = u32::from_le_bytes([
            text_section_header[8], text_section_header[9], 
            text_section_header[10], text_section_header[11]
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
        
        // Read the entire image from the process memory
        let image_data = self.read_process_memory(process_info.hProcess, base_address, image_size as usize)?;
        
        // Write the image to the output file
        let mut output_file = File::create(output_path)?;
        output_file.write_all(&image_data)?;
        
        info!("Image successfully dumped to: {}", output_path.display());
        info!("Total bytes written: 0x{:X}", image_data.len());
        
        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    fn dump(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        Err(DumperError::Unsupported("EXE dumping is only supported on Windows".to_string()))
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
        let exe_path = temp_dir.path().join("test.exe");
        let dll_path = temp_dir.path().join("test.dll");
        
        // Create empty files for testing
        fs::write(&exe_path, b"MZ").unwrap();
        fs::write(&dll_path, b"MZ").unwrap();
        
        let dumper = crate::dumper::create_dumper(&exe_path).unwrap();
        assert!(dumper.as_any().downcast_ref::<ExeDumper>().is_some());
    }
}