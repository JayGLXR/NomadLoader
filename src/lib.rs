pub mod pe;
pub mod dumper;
pub mod generator;
pub mod executor;
pub mod stages;
pub mod iat;
pub mod cmdline;

// Export the main functionality
pub use pe::PeFile;
pub use dumper::{create_dumper, PeDumper, ExeDumper, DllDumper};
pub use generator::ShellcodeGenerator;
pub use executor::ShellcodeExecutor;