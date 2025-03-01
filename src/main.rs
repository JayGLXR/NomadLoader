mod pe;
mod dumper;
mod generator;
mod executor;
mod stages;
mod iat;
mod cmdline;

use clap::{Parser, Subcommand};
use log::{debug, error, info, warn, LevelFilter};
use env_logger::Builder;
use std::path::PathBuf;
use std::process;

/// NomadLoader
/// Advanced utility for converting PE files to position-independent code
#[derive(Parser)]
#[command(name = "NomadLoader")]
#[command(author = "JayGLXR")]
#[command(version = "0.1.0")]
#[command(about = "Advanced utility for converting PE files to position-independent code", long_about = None)]
struct Args {
    /// Subcommands for different operations
    #[command(subcommand)]
    command: Command,
    
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Extract PE file from memory or disk
    Dump {
        /// Input PE file path
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,
        
        /// Output dump file path
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    
    /// Generate shellcode from PE file
    Generate {
        /// Input dump file path
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,
        
        /// Output shellcode file path
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
        
        /// Command line to pass to PE
        #[arg(short, long, value_name = "STRING")]
        cmdline: Option<String>,
        
        /// Enable PE header obfuscation
        #[arg(long)]
        obfuscate: bool,
        
        /// Enable multi-stage loading
        #[arg(long)]
        multi_stage: bool,
        
        /// Enable just-in-time IAT patching
        #[arg(long)]
        jit_imports: bool,
        
        /// Enable command line encryption
        #[arg(long)]
        encrypt_cmdline: bool,
        
        /// Set encryption strength (1-3)
        #[arg(long, value_name = "N", default_value = "1")]
        encryption_level: u8,
    },
    
    /// Generate and execute shellcode
    Execute {
        /// Input PE or dump file path
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,
        
        /// Command line to pass to PE
        #[arg(short, long, value_name = "STRING")]
        cmdline: Option<String>,
        
        /// Wait for user input before execution
        #[arg(long)]
        wait: bool,
    },
}

fn main() {
    // Parse command line arguments
    let args = Args::parse();
    
    // Setup logger based on verbosity
    let mut builder = Builder::new();
    builder.filter_level(if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    });
    builder.init();
    
    // Print banner
    print_banner();
    
    // Process the command
    match &args.command {
        Command::Dump { input, output } => {
            info!("Dumping PE file: {}", input.display());
            info!("Output dump file: {}", output.display());
            
            match dumper::create_dumper(input) {
                Ok(dumper) => {
                    match dumper.dump(input, output) {
                        Ok(_) => info!("PE file successfully dumped"),
                        Err(e) => {
                            error!("Error dumping PE file: {}", e);
                            process::exit(1);
                        }
                    }
                },
                Err(e) => {
                    error!("Error creating dumper: {}", e);
                    process::exit(1);
                }
            }
        },
        
        Command::Generate { input, output, cmdline, obfuscate, multi_stage, jit_imports, encrypt_cmdline, encryption_level } => {
            info!("Generating shellcode from: {}", input.display());
            info!("Output shellcode file: {}", output.display());
            
            if let Some(cmd) = cmdline {
                info!("Command line: {}", cmd);
            }
            
            if *obfuscate {
                info!("PE header obfuscation enabled");
            }
            
            if *multi_stage {
                info!("Multi-stage loading enabled");
            }
            
            if *jit_imports {
                info!("Just-in-time IAT patching enabled");
            }
            
            if *encrypt_cmdline {
                info!("Command line encryption enabled (level: {})", encryption_level);
            }
            
            // Create generator config
            let config = generator::GeneratorConfig {
                cmdline: cmdline.clone(),
                obfuscate: *obfuscate,
                multi_stage: *multi_stage,
                jit_imports: *jit_imports,
                encrypt_cmdline: *encrypt_cmdline,
                encryption_level: *encryption_level,
            };
            
            // Create generator
            let generator = generator::ShellcodeGenerator::with_config(config);
            
            // Generate shellcode
            match generator.generate(input, output) {
                Ok(_) => info!("Shellcode successfully generated"),
                Err(e) => {
                    error!("Error generating shellcode: {}", e);
                    process::exit(1);
                }
            }
        },
        
        Command::Execute { input, cmdline, wait } => {
            info!("Executing PE file: {}", input.display());
            
            if let Some(cmd) = cmdline {
                info!("Command line: {}", cmd);
            }
            
            // Create temporary file for the shellcode if needed
            let temp_file = if dumper::is_dll(input) || dumper::is_exe(input) {
                // Need to dump and convert to shellcode first
                use std::env::temp_dir;
                use std::ffi::OsString;
                
                // Create temporary paths
                let mut dump_path = temp_dir();
                dump_path.push("NomadLoader_dump.bin");
                
                let mut shellcode_path = temp_dir();
                shellcode_path.push("NomadLoader_shellcode.bin");
                
                // Dump the PE file
                info!("Dumping PE file to temporary file: {}", dump_path.display());
                match dumper::create_dumper(input) {
                    Ok(dumper) => {
                        if let Err(e) = dumper.dump(input, &dump_path) {
                            error!("Error dumping PE file: {}", e);
                            process::exit(1);
                        }
                    },
                    Err(e) => {
                        error!("Error creating dumper: {}", e);
                        process::exit(1);
                    }
                }
                
                // Generate shellcode
                info!("Generating shellcode to temporary file: {}", shellcode_path.display());
                let config = generator::GeneratorConfig {
                    cmdline: cmdline.clone(),
                    obfuscate: false, // Use default settings
                    multi_stage: false,
                    jit_imports: false,
                    encrypt_cmdline: false,
                    encryption_level: 1,
                };
                
                let generator = generator::ShellcodeGenerator::with_config(config);
                if let Err(e) = generator.generate(&dump_path, &shellcode_path) {
                    error!("Error generating shellcode: {}", e);
                    process::exit(1);
                }
                
                // Return the temporary shellcode path
                Some(shellcode_path)
            } else {
                // Already a shellcode file, use it directly
                None
            };
            
            // Get the final path to the shellcode
            let shellcode_path = temp_file.as_ref().unwrap_or(input);
            
            // Create executor config
            let config = executor::ExecutorConfig {
                wait: *wait,
                cmdline: cmdline.clone(),
            };
            
            // Create executor
            let executor = executor::ShellcodeExecutor::with_config(config);
            
            // Execute shellcode
            match executor.execute(shellcode_path) {
                Ok(_) => info!("Shellcode execution completed"),
                Err(e) => {
                    error!("Error executing shellcode: {}", e);
                    process::exit(1);
                }
            }
            
            // Clean up temporary files if they were created
            if let Some(path) = &temp_file {
                if let Err(e) = std::fs::remove_file(path) {
                    warn!("Failed to remove temporary file: {}", e);
                }
                
                // Also remove the dump file
                let mut dump_path = path.clone();
                dump_path.set_file_name("NomadLoader_dump.bin");
                if let Err(e) = std::fs::remove_file(&dump_path) {
                    warn!("Failed to remove temporary dump file: {}", e);
                }
            }
        },
    }
}

fn print_banner() {
    println!("
███╗   ██╗ ██████╗ ███╗   ███╗ █████╗ ██████╗ ██╗      ██████╗  █████╗ ██████╗ ███████╗██████╗ 
████╗  ██║██╔═══██╗████╗ ████║██╔══██╗██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
██╔██╗ ██║██║   ██║██╔████╔██║███████║██║  ██║██║     ██║   ██║███████║██║  ██║█████╗  ██████╔╝
██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██║██║  ██║██║     ██║   ██║██╔══██║██║  ██║██╔══╝  ██╔══██╗
██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║  ██║██████╔╝███████╗╚██████╔╝██║  ██║██████╔╝███████╗██║  ██║
╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝                                            
");
    
    println!("Advanced utility for converting PE files to position-independent code");
    println!("Author: JayGLXR");
    println!("Version: 0.1.0");
    println!();
}