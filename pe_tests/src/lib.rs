use byteorder::{ByteOrder, LittleEndian};

// Export extract_c_string for tests
pub fn extract_c_string(data: &[u8]) -> String {
    // Find the position of the null terminator
    let null_pos = data.iter()
        .position(|&c| c == 0)
        .unwrap_or(data.len());
    
    // Extract the string up to the null terminator
    let str_bytes = &data[0..null_pos];
    
    // Convert to a String
    String::from_utf8_lossy(str_bytes).to_string()
}

#[derive(Debug, Default)]
pub struct DosHeader {
    pub e_magic: u16,     // Magic number (MZ)
    // There are other fields here in a real DOS header, but we're focusing on just these two
    pub e_lfanew: u32,    // File address of new exe header (PE Header)
}

impl DosHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }
        
        let e_magic = LittleEndian::read_u16(&data[0..2]);
        // e_lfanew is at offset 0x3C
        let e_lfanew = LittleEndian::read_u32(&data[0x3C..0x40]);
        println!("Read e_lfanew = 0x{:08X} from offset 0x3C", e_lfanew);
        
        if e_magic != 0x5A4D { // "MZ" in little-endian
            return None;
        }
        
        Some(Self {
            e_magic,
            e_lfanew,
        })
    }
}