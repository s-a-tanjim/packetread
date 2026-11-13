//! SMB over a NetBIOS session header: SMB2/3 header fields and SMB1 commands.
use super::{Decoder, Protocol};

const COMMANDS: [&str; 19] = [
    "Negotiate",
    "Session Setup",
    "Logoff",
    "Tree Connect",
    "Tree Disconnect",
    "Create",
    "Close",
    "Flush",
    "Read",
    "Write",
    "Lock",
    "Ioctl",
    "Cancel",
    "Echo",
    "Query Directory",
    "Change Notify",
    "Query Info",
    "Set Info",
    "Oplock Break",
];

impl Decoder<'_> {
    pub(super) fn smb(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        // NetBIOS session message (type 0) followed by an SMB magic.
        if end - start < 8 || bytes[start] != 0 || &bytes[start + 5..start + 8] != b"SMB" {
            return false;
        }
        let smb = start + 4;
        let le = |at: usize, len: usize| {
            bytes[at..at + len]
                .iter()
                .rev()
                .fold(0u64, |v, b| (v << 8) | u64::from(*b))
        };
        match bytes[smb] {
            0xfe if end - smb >= 64 => {
                let command = le(smb + 12, 2) as usize;
                let name = COMMANDS.get(command).copied().unwrap_or("Unknown command");
                let response = le(smb + 16, 4) & 1 != 0;
                let status = le(smb + 8, 4);
                self.summary.info = format!(
                    "SMB2 {name} {}",
                    if response {
                        format!("Response · status 0x{status:08x}")
                    } else {
                        "Request".into()
                    }
                );
                self.layer("SMB2", smb, end);
                self.field(smb + 12, smb + 14, || {
                    format!("Command: {name} ({command})")
                });
                self.field(smb + 8, smb + 12, || format!("NT status: 0x{status:08x}"));
                self.field(smb + 16, smb + 20, || {
                    format!("Flags: 0x{:08x}", le(smb + 16, 4))
                });
                self.field(smb + 24, smb + 32, || {
                    format!("Message ID: {}", le(smb + 24, 8))
                });
                self.field(smb + 36, smb + 40, || {
                    format!("Tree ID: 0x{:08x}", le(smb + 36, 4))
                });
                self.field(smb + 40, smb + 48, || {
                    format!("Session ID: 0x{:016x}", le(smb + 40, 8))
                });
            }
            0xfd => {
                self.summary.info = "SMB3 encrypted message".into();
                self.layer("SMB3 transform header", smb, end);
            }
            0xff if end - smb >= 32 => {
                let command = bytes[smb + 4];
                self.summary.info = format!("SMB1 command 0x{command:02x}");
                self.layer("SMB1", smb, end);
                self.field(smb + 4, smb + 5, || format!("Command: 0x{command:02x}"));
                self.field(smb + 5, smb + 9, || {
                    format!("Status: 0x{:08x}", le(smb + 5, 4))
                });
            }
            _ => return false,
        }
        self.summary.protocol = Protocol::Smb;
        true
    }
}
