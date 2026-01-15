"""
Executable encoding/decoding library for Fr Arch.

Control Word Format (32-bit base, optionally +16-bit extended immediate):
  Bytes 0-1:  Base control word (16 bits)
  Byte 2:     8-bit immediate (or low byte of 16-bit immediate)
  Byte 3:     Extended flags
  Bytes 4-5:  High byte of 16-bit immediate (only if imm16 flag set)

Base control word layout:
  15    MEM_EN     Enable memory
  14    MEM_RW     Memory mode: 0=read, 1=write
  13    PC_WE      Write RESULT to PC
  12    FLAG_WE    Update flags from RESULT
  11-8  ALU_OP     ALU operation
  7-5   DST        Destination register
  4-2   SRC_A      Source register A
  1-0   SRC_B_low  Lower 2 bits of SRC_B register

Extended flags (byte 3):
  0     CLEAR_PRIV  Clear privilege mode
  1     COND_Z      Conditional on Z flag
  2     COND_NZ     Conditional on not Z flag  
  3     COND_N      Conditional on N flag
  4     SRC_B_2     3rd bit of SRC_B
  5     DST_EN      Enable write to R0
  6     XOR_IMM     1=XOR immediate with bus (default), 0=use immediate directly
  7     IMM16       1=16-bit immediate (instruction is 6 bytes)
"""

from zstd import compress, decompress
from dataclasses import dataclass
from typing import List
import struct

# Magic bytes for executable format
MAGIC = b'FRVM'
VERSION = 2

# ALU Operations
ALU_OPS = {
    'PASS':    0b0000,
    'SEL_A':   0b0001,
    'SEL_B':   0b0010,
    'ADD':     0b0011,
    'SUB':     0b0100,
    'AND':     0b0101,
    'OR':      0b0110,
    'XOR':     0b0111,
    'SHL':     0b1000,
    'SHR':     0b1001,
    'INC':     0b1010,
    'DEC':     0b1011,
    'MUL':     0b1100,
    'DIV':     0b1101,
    'ROL':     0b1110,
    'ROR':     0b1111,
}

ALU_OP_NAMES = {v: k for k, v in ALU_OPS.items()}

# Register names
REGISTERS = {
    'R0': 0, 'R1': 1, 'R2': 2, 'R3': 3,
    'R4': 4, 'R5': 5, 'R6': 6, 'R7': 7,
}

REG_NAMES = {v: k for k, v in REGISTERS.items()}


@dataclass
class MicroOp:
    """Represents a single micro-operation."""
    mem_en: bool = False
    mem_rw: bool = False  # 0=read, 1=write
    pc_we: bool = False
    flag_we: bool = False
    alu_op: int = 0
    dst: int = 0
    src_a: int = 0
    src_b: int = 0
    imm: int = 0
    # Extended fields
    clear_priv: bool = False
    cond_z: bool = False      # Conditional on Z flag
    cond_nz: bool = False     # Conditional on not Z flag
    cond_n: bool = False      # Conditional on N flag
    dst_en: bool = False      # Enable write to destination (allows writing to R0)
    xor_imm: bool = True      # XOR immediate with bus (default True for backward compat)
    imm16: bool = False       # 16-bit immediate (makes instruction 6 bytes)
    
    def encode(self) -> bytes:
        """Encode micro-op to 4 bytes."""
        # Base control word (16 bits)
        base = 0
        base |= (self.mem_en & 1) << 15
        base |= (self.mem_rw & 1) << 14
        base |= (self.pc_we & 1) << 13
        base |= (self.flag_we & 1) << 12
        base |= (self.alu_op & 0xF) << 8
        base |= (self.dst & 0x7) << 5
        base |= (self.src_a & 0x7) << 2
        base |= (self.src_b & 0x3)
        
        # Immediate (8 bits)
        imm_byte = self.imm & 0xFF
        
        # Extended flags (8 bits)
        ext = 0
        ext |= (self.clear_priv & 1) << 0
        ext |= (self.cond_z & 1) << 1
        ext |= (self.cond_nz & 1) << 2
        ext |= (self.cond_n & 1) << 3
        ext |= ((self.src_b >> 2) & 1) << 4  # 3rd bit of src_b
        ext |= (self.dst_en & 1) << 5
        ext |= (self.xor_imm & 1) << 6
        ext |= (self.imm16 & 1) << 7
        
        if self.imm16:
            # 6 bytes: base (2), imm_lo (1), ext (1), imm_hi (1), padding (1)
            imm_lo = self.imm & 0xFF
            imm_hi = (self.imm >> 8) & 0xFF
            return struct.pack('<HBBBB', base, imm_lo, ext, imm_hi, 0)
        else:
            # 4 bytes: base (2), imm (1), ext (1)
            return struct.pack('<HBB', base, imm_byte, ext)
    
    @classmethod
    def decode(cls, data: bytes) -> 'MicroOp':
        """Decode bytes to micro-op. Returns (MicroOp, bytes_consumed)."""
        if len(data) < 4:
            raise ValueError("Need at least 4 bytes to decode micro-op")
        
        base, imm_byte, ext = struct.unpack('<HBB', data[:4])
        
        op = cls()
        op.mem_en = bool((base >> 15) & 1)
        op.mem_rw = bool((base >> 14) & 1)
        op.pc_we = bool((base >> 13) & 1)
        op.flag_we = bool((base >> 12) & 1)
        op.alu_op = (base >> 8) & 0xF
        op.dst = (base >> 5) & 0x7
        op.src_a = (base >> 2) & 0x7
        op.src_b = base & 0x3
        
        op.clear_priv = bool(ext & 1)
        op.cond_z = bool((ext >> 1) & 1)
        op.cond_nz = bool((ext >> 2) & 1)
        op.cond_n = bool((ext >> 3) & 1)
        op.src_b |= ((ext >> 4) & 1) << 2
        op.dst_en = bool((ext >> 5) & 1)
        op.xor_imm = bool((ext >> 6) & 1)
        op.imm16 = bool((ext >> 7) & 1)
        
        if op.imm16:
            if len(data) < 6:
                raise ValueError("Need 6 bytes for 16-bit immediate instruction")
            imm_hi = data[4]
            op.imm = imm_byte | (imm_hi << 8)
        else:
            op.imm = imm_byte
        
        return op
    
    def size(self) -> int:
        """Return encoded size in bytes."""
        return 6 if self.imm16 else 4
    
    def __str__(self) -> str:
        """Human-readable representation."""
        parts = []
        
        if self.cond_z:
            parts.append("IF_Z")
        if self.cond_nz:
            parts.append("IF_NZ")
        if self.cond_n:
            parts.append("IF_N")
        
        if self.clear_priv:
            parts.append("CLEAR_PRIV")
        
        alu_name = ALU_OP_NAMES.get(self.alu_op, f"ALU_{self.alu_op}")
        if self.alu_op != 0:
            parts.append(f"{alu_name}({REG_NAMES[self.src_a]}, {REG_NAMES[self.src_b]})")

        if self.imm != 0:
            if self.imm16:
                parts.append(f"IMM16=0x{self.imm:04X}")
            else:
                parts.append(f"IMM=0x{self.imm:02X}")
            if not self.xor_imm:
                parts.append("(DIRECT)")

        if self.mem_en:
            if self.mem_rw:
                parts.append("MEM_WR")
            else:
                parts.append("MEM_RD")

        if self.dst != 0 or self.dst_en:
            parts.append(f"-> {REG_NAMES[self.dst]}")

        if self.pc_we:
            parts.append("-> PC")

        if self.flag_we:
            parts.append("FLAGS")

        return " ".join(parts) if parts else "NOP"


@dataclass
class Executable:
    """Represents an executable binary."""
    entry_point: int = 0
    kernel_size: int = 0x8000  # Default kernel region size
    code: List[MicroOp] = None
    data: bytes = b''
    is_kernel: bool = False

    def __post_init__(self):
        if self.code is None:
            self.code = []

    def encode(self) -> bytes:
        """Encode executable to bytes."""
        # Code section (variable-size instructions)
        code_bytes = b''.join(op.encode() for op in self.code)

        # Header: MAGIC (4) + VERSION (2) + ENTRY (4) + KERNEL_SIZE (4) + CODE_BYTES (4) + DATA_LEN (4)
        # Note: CODE_BYTES is the byte length of code section (not instruction count)
        if self.is_kernel:
            header = struct.pack(
                '<4sHIIII',
                MAGIC,
                VERSION,
                self.entry_point,
                (len(code_bytes)+len(self.data)+22),
                len(code_bytes),
                len(self.data)
            )
        else:
            header = struct.pack(
                '<4sHIIII',
                MAGIC,
                VERSION,
                self.entry_point,
                self.kernel_size,
                len(code_bytes),
                len(self.data)
            )

        data = header + code_bytes + self.data

        return compress(data, 22)

    @classmethod
    def decode(cls, data: bytes) -> 'Executable':
        """Decode bytes to executable."""
        data = decompress(data)

        if len(data) < 22:
            raise ValueError("Data too short for executable header")

        magic, version, entry, kernel_size, code_bytes_len, data_len = struct.unpack('<4sHIIII', data[:22])

        if magic != MAGIC:
            raise ValueError(f"Invalid magic bytes: {magic}")
        if version > VERSION:
            raise ValueError(f"Unsupported version: {version}")

        exe = cls()
        exe.entry_point = entry
        exe.kernel_size = kernel_size

        # Decode code section (variable-size instructions)
        code_start = 22
        code_end = code_start + code_bytes_len
        
        offset = code_start
        while offset < code_end:
            # Read first 4 bytes to check instruction size
            if offset + 4 > len(data):
                raise ValueError(f"Truncated instruction at offset {offset}")
            
            chunk = data[offset:offset+4]
            # Check if imm16 flag is set (bit 7 of ext byte at offset 3)
            ext = chunk[3]
            if ext & 0x80:  # imm16 flag set
                if offset + 6 > len(data):
                    raise ValueError("Need 6 bytes for 16-bit immediate instruction")
                op = MicroOp.decode(data[offset:offset+6])
                offset += 6
            else:
                op = MicroOp.decode(chunk)
                offset += 4
            exe.code.append(op)

        # Data section
        exe.data = data[code_end:code_end + data_len]

        return exe

def disassemble(exe: Executable) -> str:
    """Disassemble executable to human-readable format."""
    lines = [
        f"; Entry point: 0x{exe.entry_point:04X}",
        f"; Kernel size: 0x{exe.kernel_size:04X}",
        f"; Code length: {len(exe.code)} micro-ops",
        "",
    ]

    for i, op in enumerate(exe.code):
        addr = f"0x{i:04X}"
        lines.append(f"{addr}: {op}")

    if exe.data:
        lines.append("")
        lines.append("; Data section:")
        for i in range(0, len(exe.data), 16):
            chunk = exe.data[i:i+16]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            lines.append(f"0x{i:04X}: {hex_str}")

    return '\n'.join(lines)
