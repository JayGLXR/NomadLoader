//! PE file dumping functionality
//!
//! This module provides functionality for dumping PE files from memory or disk.

mod exe;
mod dll;

pub use exe::ExeDumper;
pub use dll::DllDumper;

use thiserror::Error;
use std::path::Path;
use std::io;

/// Errors that can occur during PE dumping
#[derive(Error, Debug)]
pub enum DumperError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Windows API error: {0}")]
    WindowsApi(u32),
    
    #[error("Process error: {0}")]
    Process(String),
    
    #[error("Invalid PE file: {0}")]
    InvalidPe(String),
    
    #[error("Unsupported operation: {0}")]
    Unsupported(String),
}

/// Result type for dumper operations
pub type Result<T> = std::result::Result<T, DumperError>;

/// Common interface for PE dumpers
pub trait PeDumper {
    /// Dump a PE file to a binary file
    fn dump(&self, input_path: &Path, output_path: &Path) -> Result<()>;
    
    /// Print memory allocation suggestion for the dumped PE
    fn suggest_memory_allocation(&self, text_size: u32, other_section_size: u32);
    
    /// Convert to Any for downcasting in tests
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Factory function to create the appropriate dumper for a given file
pub fn create_dumper(file_path: &Path) -> Result<Box<dyn PeDumper>> {
    if !file_path.exists() {
        return Err(DumperError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("File not found: {}", file_path.display())
        )));
    }
    
    let extension = file_path.extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase());
    
    match extension.as_deref() {
        Some("exe") => Ok(Box::new(ExeDumper::new())),
        Some("dll") => Ok(Box::new(DllDumper::new())),
        _ => Err(DumperError::Unsupported(format!(
            "Unsupported file type: {}", file_path.display()
        ))),
    }
}

/// Determine if a given path is a DLL
pub fn is_dll(file_path: &Path) -> bool {
    file_path.extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase() == "dll")
        .unwrap_or(false)
}

/// Determine if a given path is an EXE
pub fn is_exe(file_path: &Path) -> bool {
    file_path.extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase() == "exe")
        .unwrap_or(false)
}