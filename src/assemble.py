#!/usr/bin/env python3
"""
Fr Arch

Usage: python assemble.py <infile> [outfile=out.bin]

Assembly language syntax:
    ; comment
    label:
    instruction operands

Instructions:
    Arithmetic: add, sub, xor, and, or, mul, div, shl, shr, inc, dec, rol, ror
    Memory:     ld, st
    Control:    jmp, jz, jnz, jn, call, ret, halt, nop
    System:     syscall, retk
    Data:       mov, movi, li (load immediate - uses direct mode)

Operands:
    r0-r7       Registers
    #imm        Immediate value (8-bit, or 16-bit with li)
    [rx]        Memory at address in rx
    label       Label reference

Micro-op syntax (raw micro-op control):
    .micro [flags] [alu=OP] [dst=Rx] [src_a=Rx] [src_b=Rx] [imm=N]
           [xor_imm=0|1] [imm16=0|1]

    Flags: mem_en, mem_rw, pc_we, flag_we, dst_en, clear_priv,
           cond_z, cond_nz, cond_n, no_xor (alias: direct)
    ALU ops: PASS, SEL_A, SEL_B, ADD, SUB, AND, OR, XOR,
             SHL, SHR, INC, DEC, MUL, DIV, ROL, ROR
    
    New flags:
      xor_imm=0 / no_xor / direct : Use immediate directly (OR) instead of XOR
      imm16=1 : Enable 16-bit immediate (auto-enabled if imm > 255)
"""

import sys
import os
import re
from typing import Dict, List, Tuple, Optional, Set, Any
from executable import Executable, MicroOp, ALU_OPS, REGISTERS

# Standard MMIO Constants - Mapped at 0x0000
MMIO_CONSTANTS = {
    'MMIO_BASE': 0x0000,
    # Character I/O
    'MMIO_PRINT_CHAR': 0x0000,
    'MMIO_PRINT_INT': 0x0002,
    'MMIO_PRINT_HEX': 0x0004,
    'MMIO_PRINT_STR': 0x0006,
    'MMIO_INPUT_CHAR': 0x0008,
    'MMIO_INPUT_READY': 0x000A,
    'MMIO_INPUT_LINE': 0x000C,
    'MMIO_NEWLINE': 0x000E,
    
    # Timer
    'MMIO_TIMER_LO': 0x0010,
    'MMIO_TIMER_HI': 0x0012,
    'MMIO_TIMER_INTERVAL': 0x0014,
    'MMIO_RANDOM': 0x0016,
    'MMIO_EXIT': 0x0018,
    'MMIO_SCREEN_CLEAR': 0x001C,
    'MMIO_FLUSH': 0x001E,

    # File I/O
    'MMIO_FILE_OPEN': 0x0020,
    'MMIO_FILE_READ': 0x0022,
    'MMIO_FILE_CLOSE': 0x0024,
    'MMIO_FILE_SIZE': 0x0026,
    'MMIO_FILE_SEEK': 0x0028,

    # Arguments
    'MMIO_ARG_COUNT': 0x0030,
    'MMIO_ARG_LEN': 0x0032,
    'MMIO_ARG_COPY': 0x0034,

    # Screen (80x25 text mode)
    'MMIO_SCREEN_WIDTH': 0x0040,
    'MMIO_SCREEN_HEIGHT': 0x0042,
    'MMIO_SCREEN_PUTC': 0x0044,
    'MMIO_SCREEN_SETXY': 0x0046,
    'MMIO_SCREEN_FLUSH': 0x0048,
    'MMIO_SCREEN_GETC': 0x004A,
    'MMIO_SCREEN_BUF': 0x004C,

    # Keyboard / Mouse
    'MMIO_KB_AVAILABLE': 0x0050,
    'MMIO_KB_READ': 0x0052,
    'MMIO_KB_MODIFIERS': 0x0054,
    'MMIO_MOUSE_X': 0x0060,
    'MMIO_MOUSE_Y': 0x0062,
    'MMIO_MOUSE_BUTTONS': 0x0064,
    'MMIO_MOUSE_WHEEL': 0x0066,

    # Process Control
    'MMIO_SET_PROC_BASE': 0x0070,
    'MMIO_SET_PROC_LIMIT': 0x0072,
    
    # Kernel / Trap Constants (Not MMIO, but useful)
    'TRAP_VECTOR': 0x0100,
    'TRAP_INFO_CAUSE': 0x0080,
    'TRAP_INFO_ADDR': 0x0082,
    'TRAP_INFO_PC': 0x0084,
    'TRAP_INFO_VALUE': 0x0086,
    'USER_REGS_ADDR': 0x0090,
}


class AssemblerError(Exception):
    """Assembler error with line information."""
    def __init__(self, message: str, line_num: int = 0, line: str = ""):
        self.message = message
        self.line_num = line_num
        self.line = line
        super().__init__(f"Line {line_num}: {message}\n  {line}")


class Assembler:
    """Fr Assembler."""

    def __init__(self):
        self.labels: Dict[str, int] = MMIO_CONSTANTS.copy()
        self.data_labels: Dict[str, int] = {}  # Labels in data section (label -> offset in data)
        self.code: List[MicroOp] = []
        self.data: bytes = b''
        self.unresolved: List[Tuple[int, str, int, str]] = []  # (addr, label, line_num, line)
        self.line_num = 0
        self.current_line = ""
        self.entry_point = 0
        self.kernel_size = 0x8000
        self.base_addr = 0  # Base address for code (added to all addresses)
        self.included_files: Set[str] = set()  # Track included files to prevent duplicates
        self.source_dir = ""  # Directory of main source file for relative includes
        self.pending_data_label = None  # Label to assign to next data directive
        self.auto_kernel_size = False  # Whether to automatically determine kernel size
        self.deferred_includes: List[str] = []

    def error(self, message: str):
        """Raise an assembler error."""
        raise AssemblerError(message, self.line_num, self.current_line)

    def split_operands(self, operand_str: str) -> List[str]:
        """Split operand string by comma, respecting quoted strings."""
        operands = []
        current = ""
        in_string = False
        string_char = None

        for c in operand_str:
            if in_string:
                current += c
                if c == string_char:
                    in_string = False
            elif c in ('"', "'"):
                in_string = True
                string_char = c
                current += c
            elif c == ',':
                operands.append(current.strip())
                current = ""
            else:
                current += c

        if current.strip():
            operands.append(current.strip())

        return operands

    def parse_register(self, token: str) -> int:
        """Parse register name, return register number."""
        token = token.upper().strip()
        if token in REGISTERS:
            return REGISTERS[token]
        # Handle lowercase
        if token.upper() in REGISTERS:
            return REGISTERS[token.upper()]
        self.error(f"Invalid register: {token}")

    def parse_immediate(self, token: str) -> int:
        """Parse immediate value with support for labels and offsets."""
        token = token.strip()
        if token.startswith('#'):
            token = token[1:]

        # Check for character literal first to avoid splitting '+' inside quotes
        if token.startswith("'") and token.endswith("'") and len(token) == 3:
            return ord(token[1])

        offset = 0
        if '+' in token:
            parts = token.split('+', 1)
            token = parts[0].strip()
            try:
                offset = int(parts[1].strip(), 0)
            except ValueError:
                self.error(f"Invalid offset: {parts[1]}")

        # Try to parse as integer (hex, binary, decimal handled by int(x, 0))
        try:
            val = int(token, 0)
        except ValueError:
            # Not an integer, check if it is a known label/constant
            if token in self.labels:
                val = self.labels[token]
            else:
                # If we are in a pass where labels should be known, error.
                # However, parse_immediate is called for ALL immediates.
                # If it's a forward reference label, we can't maintain int return type.
                # But strict immediates (like for ST) require resolution now.
                self.error(f"Invalid immediate value or unknown label: {token}")
        
        return val + offset

    def parse_operand(self, token: str) -> Tuple[str, Any]:
        """Parse operand, return (type, value)."""
        token = token.strip()

        if not token:
            return ('none', None)

        # Register
        if token.upper() in REGISTERS:
            return ('reg', self.parse_register(token))

        # Immediate
        if token.startswith('#'):
            return ('imm', self.parse_immediate(token))

        # Memory reference [rx] or [#imm]
        if token.startswith('[') and token.endswith(']'):
            inner = token[1:-1].strip()
            # Check if immediate addressing [#imm]
            if inner.startswith('#'):
                return ('imm', self.parse_immediate(inner))
            else:
                return ('mem', self.parse_register(inner))

        # Number (treat as immediate)
        if token[0].isdigit() or token.startswith('-'):
            return ('imm', self.parse_immediate(token))

        # Label
        return ('label', token)

    def emit(self, op: MicroOp):
        """Emit a micro-op."""
        # Auto-set dst_en if writing to R0
        if op.dst == 0 and not op.dst_en:
            # Check if this op is actually writing to a destination
            if op.alu_op != 0 or op.mem_en or op.imm != 0:
                pass  # don't auto-enable, let explicit dst_en control it
        self.code.append(op)

    def emit_with_dst(self, dst: int, **kwargs):
        """Emit a micro-op with proper dst_en handling."""
        if dst == 0:
            kwargs['dst_en'] = True
        self.emit(MicroOp(dst=dst, **kwargs))

    def emit_nop(self):
        """Emit a no-op."""
        self.emit(MicroOp())

    def current_addr(self) -> int:
        """Get current code address in bytes (includes base_addr for relocatable code)."""
        # Calculate byte offset by summing sizes of all emitted instructions
        byte_offset = sum(op.size() for op in self.code)
        return self.base_addr + byte_offset

    def assemble_mov(self, operands: List[str]):
        """Assemble mov instruction: mov rd, rs"""
        if len(operands) != 2:
            self.error("mov requires 2 operands: mov rd, rs")

        dst_type, dst = self.parse_operand(operands[0])
        src_type, src = self.parse_operand(operands[1])

        if dst_type != 'reg':
            self.error("Destination must be a register")

        dst_en = (dst == 0)  # Enable R0 write explicitly

        if src_type == 'reg':
            # mov rd, rs -> SEL_A rs -> rd
            self.emit(MicroOp(alu_op=ALU_OPS['SEL_A'], dst=dst, src_a=src, dst_en=dst_en))
        elif src_type == 'imm':
            # mov rd, #imm
            # Check if we need 16-bit immediate
            use_imm16 = (src > 0xFF) or (src < 0 and src < -128)
            
            self.emit(MicroOp(
                alu_op=ALU_OPS['PASS'], 
                dst=dst, 
                imm=src & 0xFFFF if use_imm16 else src & 0xFF, 
                dst_en=dst_en,
                imm16=use_imm16
            ))
        else:
            self.error(f"Invalid source operand type: {src_type}")

    def assemble_movi(self, operands: List[str]):
        """Assemble movi instruction: movi rd, #imm"""
        if len(operands) != 2:
            self.error("movi requires 2 operands: movi rd, #imm")

        dst_type, dst = self.parse_operand(operands[0])
        src_type, src = self.parse_operand(operands[1])

        if dst_type != 'reg':
            self.error("Destination must be a register")
        if src_type not in ('imm', 'label'):
            self.error("Source must be an immediate or label")

        if src_type == 'label':
            # Store unresolved reference (use code array index, not logical address)
            self.unresolved.append((len(self.code), src, self.line_num, self.current_line))
            src = 0

        self.emit_with_dst(dst, alu_op=ALU_OPS['PASS'], imm=src & 0xFF)

    def assemble_li(self, operands: List[str]):
        """Assemble li (load immediate) instruction: li rd, #imm
        
        Uses direct mode (xor_imm=False) for faster constant loading.
        Supports 16-bit immediates in a single instruction.
        """
        if len(operands) != 2:
            self.error("li requires 2 operands: li rd, #imm")

        dst_type, dst = self.parse_operand(operands[0])
        src_type, src = self.parse_operand(operands[1])

        if dst_type != 'reg':
            self.error("Destination must be a register")
        if src_type not in ('imm', 'label'):
            self.error("Source must be an immediate or label")

        if src_type == 'label':
            # Store unresolved reference - mark as needing imm16
            self.unresolved.append((len(self.code), src, self.line_num, self.current_line))
            src = 0
            # Create micro-op with imm16 and xor_imm=False (direct mode)
            op = MicroOp(
                alu_op=ALU_OPS['PASS'],
                dst=dst,
                dst_en=True,
                imm=0,
                xor_imm=False,  # Direct mode - OR instead of XOR
                imm16=True      # Use 16-bit immediate for labels
            )
        else:
            # Check if we need 16-bit immediate
            use_imm16 = (src > 0xFF) or (src < 0 and src < -128)
            
            op = MicroOp(
                alu_op=ALU_OPS['PASS'],
                dst=dst,
                dst_en=True,
                imm=src & 0xFFFF if use_imm16 else src & 0xFF,
                xor_imm=False,  # Direct mode - OR instead of XOR
                imm16=use_imm16
            )
        
        self.emit(op)

    def assemble_arithmetic(self, mnemonic: str, operands: List[str]):
        """Assemble arithmetic instructions."""
        alu_op_map = {
            'add': 'ADD', 'sub': 'SUB', 'xor': 'XOR',
            'and': 'AND', 'or': 'OR', 'mul': 'MUL', 'div': 'DIV',
            'shl': 'SHL', 'shr': 'SHR', 'rol': 'ROL', 'ror': 'ROR',
        }

        alu_name = alu_op_map.get(mnemonic)
        if not alu_name:
            self.error(f"Unknown arithmetic instruction: {mnemonic}")

        if len(operands) == 3:
            # add rd, rs1, rs2 or add rd, rs1, #imm
            dst_type, dst = self.parse_operand(operands[0])
            src_a_type, src_a = self.parse_operand(operands[1])
            src_b_type, src_b = self.parse_operand(operands[2])

            if dst_type != 'reg' or src_a_type != 'reg':
                self.error("Destination and first source must be registers")

            if src_b_type == 'reg':
                self.emit_with_dst(dst, alu_op=ALU_OPS[alu_name], src_a=src_a, src_b=src_b, flag_we=True)
            elif src_b_type == 'imm':
                # Use register and XOR immediate
                self.emit_with_dst(dst, alu_op=ALU_OPS[alu_name], src_a=src_a, src_b=0, imm=src_b & 0xFF, flag_we=True)
            else:
                self.error("Third operand must be register or immediate")

        elif len(operands) == 2:
            # add rd, rs -> add rd, rd, rs
            dst_type, dst = self.parse_operand(operands[0])
            src_type, src = self.parse_operand(operands[1])

            if dst_type != 'reg':
                self.error("Destination must be a register")

            if src_type == 'reg':
                self.emit_with_dst(dst, alu_op=ALU_OPS[alu_name], src_a=dst, src_b=src, flag_we=True)
            elif src_type == 'imm':
                self.emit_with_dst(dst, alu_op=ALU_OPS[alu_name], src_a=dst, src_b=0, imm=src & 0xFF, flag_we=True)
            else:
                self.error("Source must be register or immediate")
        else:
            self.error(f"{mnemonic} requires 2 or 3 operands")

    def assemble_unary(self, mnemonic: str, operands: List[str]):
        """Assemble unary instructions (inc, dec)."""
        alu_map = {'inc': 'INC', 'dec': 'DEC'}
        alu_name = alu_map.get(mnemonic)

        if len(operands) == 1:
            # inc rd -> inc rd, rd
            dst_type, dst = self.parse_operand(operands[0])
            if dst_type != 'reg':
                self.error("Operand must be a register")
            self.emit_with_dst(dst, alu_op=ALU_OPS[alu_name], src_a=dst, flag_we=True)

        elif len(operands) == 2:
            # inc rd, rs
            dst_type, dst = self.parse_operand(operands[0])
            src_type, src = self.parse_operand(operands[1])
            if dst_type != 'reg' or src_type != 'reg':
                self.error("Operands must be registers")
            self.emit_with_dst(dst, alu_op=ALU_OPS[alu_name], src_a=src, flag_we=True)
        else:
            self.error(f"{mnemonic} requires 1 or 2 operands")

    def assemble_load(self, operands: List[str]):
        """Assemble ld instruction: ld rd, [rs]"""
        if len(operands) != 2:
            self.error("ld requires 2 operands: ld rd, [rs]")

        dst_type, dst = self.parse_operand(operands[0])
        src_type, src_addr_reg = self.parse_operand(operands[1])

        if dst_type != 'reg':
            self.error("Destination must be a register")
        if src_type != 'mem':
            self.error("Source must be memory reference [rx]")

        # Load from memory using src_a as address
        self.emit_with_dst(dst, src_a=src_addr_reg, mem_en=True, mem_rw=False)

    def assemble_store(self, operands: List[str]):
        """Assemble st instruction: st [rd], rs or st [#imm], rs"""
        if len(operands) != 2:
            self.error("st requires 2 operands: st [rd], rs or st [#imm], rs")

        dst_type, dst_addr_reg = self.parse_operand(operands[0])
        src_type, src_val = self.parse_operand(operands[1])

        if dst_type not in ('mem', 'imm'):
            self.error("Destination must be memory reference [rx] or immediate address [#imm]")
        if src_type not in ('reg', 'imm'):
            self.error("Source must be register or immediate")

        # Handle immediate addressing: st [#addr], rs
        if dst_type == 'imm':
            if src_type != 'reg':
                self.error("Immediate addressing requires register source")
            # Need to build address in a temp register, then store
            # Use R0 as temp (will be overwritten, but that's okay for immediate stores)
            # Actually, we need a more efficient approach using imm16 if available
            addr = dst_addr_reg  # This is the immediate address value
            if addr <= 0xFF:
                # Single micro-op: Use xor_imm=False to get address directly from imm
                # Store value from src_val (register) to address in imm
                # We use src_b for the data, and imm for the address (with xor_imm=False)
                self.emit(MicroOp(alu_op=ALU_OPS['SEL_B'], src_b=src_val, imm=addr, mem_en=True, mem_rw=True, xor_imm=False))
            else:
                # Need 16-bit address - use R0 as temp
                # 1. Load address into R0
                self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=0, imm=addr, dst_en=True, imm16=True))
                # 2. Store from src_val to [R0]
                self.emit(MicroOp(alu_op=ALU_OPS['SEL_B'], src_a=0, src_b=src_val, mem_en=True, mem_rw=True))
            return

        # Store to memory: Addr in src_a, Data in src_b/imm
        if src_type == 'reg':
            # Data from src_b, Address from src_a. Result = ALU(src_b) -> written to Mem[src_a]
            self.emit(MicroOp(alu_op=ALU_OPS['SEL_B'], src_a=dst_addr_reg, src_b=src_val, mem_en=True, mem_rw=True))
        else:
            # Data from Imm, Address from src_a. Result = Imm.
            self.emit(MicroOp(src_a=dst_addr_reg, imm=src_val & 0xFF, mem_en=True, mem_rw=True, xor_imm=False))

    def assemble_jump(self, mnemonic: str, operands: List[str]):
        """Assemble jump instructions with 16-bit address support."""
        if len(operands) != 1:
            self.error(f"{mnemonic} requires 1 operand")

        target_type, target = self.parse_operand(operands[0])

        if target_type == 'reg':
            # Jump to register - simple, direct
            op = MicroOp(pc_we=True, alu_op=ALU_OPS['SEL_A'], src_a=target)
            if mnemonic == 'jz':
                op.cond_z = True
            elif mnemonic == 'jnz':
                op.cond_nz = True
            elif mnemonic == 'jn':
                op.cond_n = True
            self.emit(op)
        elif target_type == 'imm':
            # Jump to immediate - expand to 16-bit if needed
            if target <= 0xFF:
                # Simple 8-bit jump
                op = MicroOp(pc_we=True, imm=target)
                if mnemonic == 'jz':
                    op.cond_z = True
                elif mnemonic == 'jnz':
                    op.cond_nz = True
                elif mnemonic == 'jn':
                    op.cond_n = True
                self.emit(op)
            else:
                # 16-bit jump using imm16 immediate (no register clobbering)
                op = MicroOp(pc_we=True, imm=target & 0xFFFF, imm16=True)
                if mnemonic == 'jz':
                    op.cond_z = True
                elif mnemonic == 'jnz':
                    op.cond_nz = True
                elif mnemonic == 'jn':
                    op.cond_n = True
                self.emit(op)
        elif target_type == 'label':
            # Always use 16-bit imm jump for labels (byte-addressed PC)
            self.unresolved.append((len(self.code), f'__jmp16imm__{mnemonic}__{target}', self.line_num, self.current_line))
            # Mark as imm16 here so instruction size is correct while computing subsequent addresses
            op = MicroOp(pc_we=True, imm=0, imm16=True)
            if mnemonic == 'jz':
                op.cond_z = True
            elif mnemonic == 'jnz':
                op.cond_nz = True
            elif mnemonic == 'jn':
                op.cond_n = True
            self.emit(op)
        else:
            self.error(f"Invalid jump target: {target_type}")

    def _emit_16bit_jump(self, mnemonic: str, target: int):
        """Emit a 16-bit jump sequence using R5 as temp."""
        high_byte = (target >> 8) & 0xFF
        low_byte = target & 0xFF

        # Build 16-bit address in R5:
        # 1. R5 = high_byte
        # 2. R4 = 8
        # 3. R5 = R5 << 8
        # 4. R5 = R5 | low_byte
        # 5. Jump to R5
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=5, imm=high_byte))
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=4, imm=8))
        self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=5, src_a=5, src_b=4, dst_en=True))
        self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=5, src_a=5, src_b=5, imm=low_byte, dst_en=True))

        # Final jump
        op = MicroOp(pc_we=True, alu_op=ALU_OPS['SEL_A'], src_a=5)
        if mnemonic == 'jz':
            op.cond_z = True
        elif mnemonic == 'jnz':
            op.cond_nz = True
        elif mnemonic == 'jn':
            op.cond_n = True
        self.emit(op)

    def _emit_16bit_jump_placeholder(self, mnemonic: str):
        """Emit placeholder for 16-bit jump that will be resolved later."""
        # Same structure as _emit_16bit_jump but with zeros
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=5, imm=0))  # Will be high_byte
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=4, imm=8))
        self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=5, src_a=5, src_b=4, dst_en=True))
        self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=5, src_a=5, src_b=5, imm=0, dst_en=True))  # Will be low_byte

        op = MicroOp(pc_we=True, alu_op=ALU_OPS['SEL_A'], src_a=5)
        if mnemonic == 'jz':
            op.cond_z = True
        elif mnemonic == 'jnz':
            op.cond_nz = True
        elif mnemonic == 'jn':
            op.cond_n = True
        self.emit(op)

    def assemble_call(self, operands: List[str]):
        """Assemble call instruction with 16-bit return address and target."""
        if len(operands) != 1:
            self.error("call requires 1 operand")

        target_type, target = self.parse_operand(operands[0])

        if target_type == 'reg':
            # Call to register - 5 ops for return addr, 1 for jump (6 micro-ops total)
            # Each micro-op is 4 bytes (no imm16 here), so advance PC by 24 bytes.
            return_addr = self.current_addr() + 24
            high_byte = (return_addr >> 8) & 0xFF
            low_byte = return_addr & 0xFF

            # Build return address in R7:
            self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=7, imm=high_byte))
            self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=4, imm=8))
            self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=7, src_a=7, src_b=4, dst_en=True))
            self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=7, src_a=7, src_b=7, imm=low_byte, dst_en=True))
            # Jump to register
            self.emit(MicroOp(pc_we=True, alu_op=ALU_OPS['SEL_A'], src_a=target))
            self.emit_nop()  # Padding to 6 ops
        elif target_type == 'imm' or target_type == 'label':
            # Call to address - 5 ops for return addr + 1 padding + 4 ops to build target + 1 jump
            # 10 micro-ops, all 4 bytes (no imm16 here) -> 40 bytes total
            return_addr = self.current_addr() + 40
            high_byte = (return_addr >> 8) & 0xFF
            low_byte = return_addr & 0xFF

            # Build return address in R7:
            self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=7, imm=high_byte))
            self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=4, imm=8))
            self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=7, src_a=7, src_b=4, dst_en=True))
            self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=7, src_a=7, src_b=7, imm=low_byte, dst_en=True))
            self.emit_nop()  # Padding

            if target_type == 'imm':
                # Build target in R5 and jump
                target_high = (target >> 8) & 0xFF
                target_low = target & 0xFF
                self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=5, imm=target_high))
                self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=4, imm=8))
                self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=5, src_a=5, src_b=4, dst_en=True))
                self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=5, src_a=5, src_b=5, imm=target_low, dst_en=True))
                self.emit(MicroOp(pc_we=True, alu_op=ALU_OPS['SEL_A'], src_a=5))
            else:  # label
                # Store unresolved reference for 16-bit call target
                self.unresolved.append((len(self.code), f'__call16__{target}', self.line_num, self.current_line))
                # Emit placeholder for 16-bit jump
                self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=5, imm=0))
                self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=4, imm=8))
                self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=5, src_a=5, src_b=4, dst_en=True))
                self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=5, src_a=5, src_b=5, imm=0, dst_en=True))
                self.emit(MicroOp(pc_we=True, alu_op=ALU_OPS['SEL_A'], src_a=5))
        else:
            self.error("Invalid call target")

    def assemble_ret(self, operands: List[str]):
        """Assemble ret instruction."""
        if operands:
            self.error("ret takes no operands")

        # PC <- R7
        self.emit(MicroOp(alu_op=ALU_OPS['SEL_A'], src_a=7, pc_we=True))

    def assemble_syscall(self, operands: List[str]):
        """Assemble syscall instruction."""
        if operands:
            self.error("syscall takes no operands")

        # Syscall takes 6 micro-ops to properly save a 16-bit return address
        # Each micro-op is 4 bytes, so advance by 24 bytes to land after the sequence
        return_addr = self.current_addr() + 24
        high_byte = (return_addr >> 8) & 0xFF
        low_byte = return_addr & 0xFF

        # Build 16-bit return address in R7:
        # 1. R7 = high_byte
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=7, imm=high_byte, dst_en=True))
        # 2. R5 = 8 (shift amount, using R5 as temp)
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=5, imm=8, dst_en=True))
        # 3. R7 = R7 << R5 (R7 = high_byte << 8)
        self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=7, src_a=7, src_b=5, dst_en=True))
        # 4. R7 = R7 | low_byte (NOTE: src_b must be same as src_a to avoid XOR bus issues!)
        self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=7, src_a=7, src_b=7, imm=low_byte, dst_en=True))
        # 5. Jump to address 0 (kernel entry)
        self.emit(MicroOp(pc_we=True, imm=0))
        # Padding NOP to align to 6 ops (in case we miscounted)
        self.emit_nop()

    def assemble_retk(self, operands: List[str]):
        """Assemble kernel return instruction (retk).
           Restores PC from TRAP_INFO_PC (0x0014) and clears privilege.
           Does NOT clobber any registers (uses direct memory addressing).
        """
        if operands:
            self.error("retk takes no operands")

        # jmp [0x0014] (Load into PC) + clear_priv
        # Direct addressing using IMM as address (xor_imm=False)
        self.emit(MicroOp(
            mem_en=True, 
            mem_rw=False, 
            pc_we=True, 
            clear_priv=True,
            xor_imm=False,
            imm=0x14
        ))

    def assemble_halt(self, operands: List[str]):
        """Assemble halt instruction (jump to self)."""
        if operands:
            self.error("halt takes no operands")

        addr = self.current_addr()
        # Load current address into R0 (clobbering is fine as we are halting)
        use_imm16 = (addr > 0xFF)
        self.emit(MicroOp(
            alu_op=ALU_OPS['PASS'], 
            dst=0, 
            imm=addr & 0xFFFF if use_imm16 else addr & 0xFF, 
            dst_en=True, 
            imm16=use_imm16
        ))
        
        # Jump to R0
        self.emit(MicroOp(pc_we=True, alu_op=ALU_OPS['SEL_A'], src_a=0))

    def assemble_nop(self, operands: List[str]):
        """Assemble nop instruction."""
        if operands:
            self.error("nop takes no operands")
        self.emit_nop()

    def assemble_cmp(self, operands: List[str]):
        """Assemble cmp instruction: cmp ra, rb (sets flags from ra - rb)."""
        if len(operands) != 2:
            self.error("cmp requires 2 operands")

        src_a_type, src_a = self.parse_operand(operands[0])
        src_b_type, src_b = self.parse_operand(operands[1])

        if src_a_type != 'reg':
            self.error("First operand must be a register")

        if src_b_type == 'reg':
            # SUB without storing result, just update flags
            self.emit(MicroOp(alu_op=ALU_OPS['SUB'], src_a=src_a, src_b=src_b, flag_we=True))
        elif src_b_type == 'imm':
            self.emit(MicroOp(alu_op=ALU_OPS['SUB'], src_a=src_a, imm=src_b & 0xFF, flag_we=True))
        else:
            self.error("Second operand must be register or immediate")

    def assemble_push(self, operands: List[str]):
        """Assemble push instruction: push rs (uses R6 as stack pointer)."""
        if len(operands) != 1:
            self.error("push requires 1 operand")

        src_type, src = self.parse_operand(operands[0])
        if src_type != 'reg':
            self.error("Operand must be a register")

        # Decrement R6 (stack pointer) by 2 (16-bit values need 2 bytes)
        self.emit(MicroOp(alu_op=ALU_OPS['DEC'], dst=6, src_a=6))
        self.emit(MicroOp(alu_op=ALU_OPS['DEC'], dst=6, src_a=6))

        # Store register to memory [R6] = src_reg
        # Memory writes use src_a for address and ALU(src_b) for data
        self.emit(MicroOp(alu_op=ALU_OPS['SEL_B'], src_a=6, src_b=src, mem_en=True, mem_rw=True))

    def assemble_pop(self, operands: List[str]):
        """Assemble pop instruction: pop rd (uses R6 as stack pointer)."""
        if len(operands) != 1:
            self.error("pop requires 1 operand")

        dst_type, dst = self.parse_operand(operands[0])
        if dst_type != 'reg':
            self.error("Operand must be a register")

        # Load from memory [R6] -> dst_reg
        # Memory reads use src_a for address
        self.emit_with_dst(dst, src_a=6, mem_en=True, mem_rw=False)
        # Increment R6 (stack pointer) by 2 (16-bit values need 2 bytes)
        self.emit(MicroOp(alu_op=ALU_OPS['INC'], dst=6, src_a=6))
        self.emit(MicroOp(alu_op=ALU_OPS['INC'], dst=6, src_a=6))

    def assemble_out(self, operands: List[str]):
        """Assemble out instruction: out rs (output character to console via MMIO)."""
        if len(operands) != 1:
            self.error("out requires 1 operand")

        src_type, src = self.parse_operand(operands[0])
        if src_type != 'reg':
            self.error("Operand must be a register")

        # Build MMIO address 0xFF00 in R0, then store
        # R0 = 0xFF (high byte)
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=0, imm=0xFF, dst_en=True))
        # R5 = 8 (shift amount)
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=5, imm=8))
        # R0 = R0 << 8 = 0xFF00
        self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=0, src_a=0, src_b=5, dst_en=True))
        # Store src to [R0] = memory[0xFF00]
        self.emit(MicroOp(alu_op=ALU_OPS['SEL_A'], src_a=src, mem_en=True, mem_rw=True))

    def assemble_lea(self, operands: List[str]):
        """Assemble lea instruction: lea rd, label (load 16-bit address into register)."""
        if len(operands) != 2:
            self.error("lea requires 2 operands: lea rd, label")

        dst_type, dst = self.parse_operand(operands[0])
        label_type, label = self.parse_operand(operands[1])

        if dst_type != 'reg':
            self.error("Destination must be a register")
        if label_type != 'label':
            self.error("Second operand must be a label")

        # We need to load a 16-bit address using multiple instructions
        # Similar to syscall: 6 micro-ops to build full address
        # For now, store as unresolved and fix in resolve_labels
        # Format: emit 5 ops, mark as "lea_unresolved" type

        # Save the current code index and label for resolution
        # We'll use a special marker format
        lea_idx = len(self.code)

        # Emit placeholder ops:
        # 1. dst = high_byte
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=dst, imm=0))
        # 2. R5 = 8 (shift amount) - use R5 as temp
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=5, imm=8))
        # 3. dst = dst << R5
        self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=dst, src_a=dst, src_b=5, dst_en=True))
        # 4. dst = dst | low_byte
        self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=dst, src_a=dst, src_b=dst, imm=0, dst_en=True))

        # Store for resolution (mark with special prefix)
        self.unresolved.append((lea_idx, f"__lea__{label}", self.line_num, self.current_line))

    def assemble_leab(self, operands: List[str]):
        """Assemble leab instruction: leab rd, label (load byte address of data label into register).

        This is for loading addresses of data (strings, bytes, words) in the data section.
        The address is computed as: (base_addr + code_length) * 4 + data_offset
        """
        if len(operands) != 2:
            self.error("leab requires 2 operands: leab rd, label")

        dst_type, dst = self.parse_operand(operands[0])
        label_type, label = self.parse_operand(operands[1])

        if dst_type != 'reg':
            self.error("Destination must be a register")
        if label_type != 'label':
            self.error("Second operand must be a label")

        # We need to load a 16-bit byte address using multiple instructions
        # Same format as lea, but resolved differently
        leab_idx = len(self.code)

        # Emit placeholder ops:
        # 1. dst = high_byte
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=dst, imm=0))
        # 2. R5 = 8 (shift amount) - use R5 as temp
        self.emit(MicroOp(alu_op=ALU_OPS['PASS'], dst=5, imm=8))
        # 3. dst = dst << R5
        self.emit(MicroOp(alu_op=ALU_OPS['SHL'], dst=dst, src_a=dst, src_b=5, dst_en=True))
        # 4. dst = dst | low_byte
        self.emit(MicroOp(alu_op=ALU_OPS['OR'], dst=dst, src_a=dst, src_b=dst, imm=0, dst_en=True))

        # Store for resolution (mark with special prefix for data address)
        self.unresolved.append((leab_idx, f"__leab__{label}", self.line_num, self.current_line))

    def assemble_micro(self, operands: List[str]):
        """Assemble raw micro-op: .micro [flags...] [alu=OP] [dst=Rx] [src_a=Rx] [src_b=Rx] [imm=N]"""
        op = MicroOp()

        # Boolean flags
        flags = {
            'mem_en': False, 'mem_rw': False, 'pc_we': False,
            'flag_we': False, 'dst_en': False, 'clear_priv': False,
            'cond_z': False, 'cond_nz': False, 'cond_n': False,
        }
        
        # Special flags that set values to False (negated flags)
        negated_flags = {
            'no_xor': ('xor_imm', False),       # xor_imm=False (use immediate directly)
            'direct': ('xor_imm', False),       # same as no_xor
        }

        for operand in operands:
            operand = operand.strip().lower()

            # Check for boolean flag
            if operand in flags:
                setattr(op, operand, True)
                continue
            
            # Check for negated/special flags
            if operand in negated_flags:
                attr, value = negated_flags[operand]
                setattr(op, attr, value)
                continue

            # Check for key=value
            if '=' in operand:
                key, value = operand.split('=', 1)
                key = key.strip()
                value = value.strip()

                if key == 'alu':
                    # ALU operation
                    alu_name = value.upper()
                    if alu_name not in ALU_OPS:
                        self.error(f"Unknown ALU operation: {alu_name}")
                    op.alu_op = ALU_OPS[alu_name]

                elif key == 'dst':
                    # Destination register
                    op.dst = self.parse_register(value)
                    if op.dst == 0:
                        op.dst_en = True

                elif key == 'src_a':
                    op.src_a = self.parse_register(value)

                elif key == 'src_b':
                    op.src_b = self.parse_register(value)

                elif key == 'imm':
                    # Check if it's a label
                    try:
                        imm_val = self.parse_immediate(value)
                        if imm_val > 0xFF or imm_val < -128:
                            # Need 16-bit immediate
                            op.imm16 = True
                            op.imm = imm_val & 0xFFFF
                        else:
                            op.imm = imm_val & 0xFF
                    except:
                        # Treat as label (use code array index)
                        self.unresolved.append((len(self.code), value, self.line_num, self.current_line))
                        op.imm = 0
                
                elif key == 'xor_imm':
                    # xor_imm=0 or xor_imm=1
                    op.xor_imm = (value != '0')
                
                elif key == 'imm16':
                    # Force 16-bit immediate mode
                    op.imm16 = (value != '0')

                else:
                    self.error(f"Unknown micro-op field: {key}")
            else:
                self.error(f"Unknown micro-op operand: {operand}")

        self.emit(op)

    def assemble_directive(self, directive: str, operands: List[str]):
        """Assemble assembler directives."""
        if directive == '.org':
            if len(operands) != 1:
                self.error(".org requires 1 operand")
            addr = self.parse_immediate(operands[0])
            # Pad with NOPs to reach address
            while self.current_addr() < addr:
                self.emit_nop()

        elif directive == '.entry':
            if len(operands) != 1:
                self.error(".entry requires 1 operand")
            op_type, op_val = self.parse_operand(operands[0])
            if op_type == 'imm':
                self.entry_point = op_val
            elif op_type == 'label':
                # Will be resolved later
                self.entry_point = op_val  # Store label name temporarily
            else:
                self.error(".entry requires address or label")

        elif directive == '.kernel':
            if len(operands) != 1:
                self.error(".kernel requires 1 operand")
            
            if operands[0].lower() == 'auto':
                self.auto_kernel_size = True
            else:
                self.kernel_size = self.parse_immediate(operands[0])
                self.auto_kernel_size = False

        elif directive == '.base':
            # Set base address for code (for relocatable user programs)
            # This also sets the entry point unless explicitly overridden with .entry
            if len(operands) != 1:
                self.error(".base requires 1 operand")
            self.base_addr = self.parse_immediate(operands[0])
            # Set entry point to base address (first instruction)
            self.entry_point = self.base_addr

        elif directive == '.byte':
            # Data bytes (stored in data section)
            # If there's a pending data label, assign it
            if self.pending_data_label:
                self.data_labels[self.pending_data_label] = len(self.data)
                self.pending_data_label = None
            for op in operands:
                val = self.parse_immediate(op)
                self.data += bytes([val & 0xFF])

        elif directive == '.word':
            # Data words (16-bit)
            # If there's a pending data label, assign it
            if self.pending_data_label:
                self.data_labels[self.pending_data_label] = len(self.data)
                self.pending_data_label = None
            for op in operands:
                val = self.parse_immediate(op)
                self.data += bytes([val & 0xFF, (val >> 8) & 0xFF])

        elif directive == '.space':
            # Reserve space (zero-filled bytes)
            # If there's a pending data label, assign it
            if self.pending_data_label:
                self.data_labels[self.pending_data_label] = len(self.data)
                self.pending_data_label = None
            if len(operands) != 1:
                self.error(".space requires 1 operand (number of bytes)")
            size = self.parse_immediate(operands[0])
            self.data += bytes(size)  # Add 'size' zero bytes

        elif directive == '.micro':
            # Raw micro-op: .micro [flags...] [alu=OP] [dst=Rx] [src_a=Rx] [src_b=Rx] [imm=N]
            self.assemble_micro(operands)

        elif directive == '.string':
            # String data (null-terminated) - store in data section
            # If there's a pending data label, record it
            if len(operands) != 1:
                self.error(".string requires 1 operand (quoted string)")

            s = operands[0].strip()
            if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
                s = s[1:-1]
            # Handle escape sequences
            s = s.replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t').replace('\\0', '\0')

            # If there's a pending data label, assign it to current data offset
            if self.pending_data_label:
                self.data_labels[self.pending_data_label] = len(self.data)
                self.pending_data_label = None

            # Store string bytes in data section
            self.data += s.encode('latin-1') + b'\x00'

        elif directive == '.include':
            # Include another assembly file - defer to end
            if len(operands) != 1:
                self.error(".include requires 1 operand (filename)")
            filename = operands[0].strip()
            if (filename.startswith('"') and filename.endswith('"')) or (filename.startswith("'") and filename.endswith("'")):
                filename = filename[1:-1]
            # Defer processing
            self.deferred_includes.append(filename)

        else:
            self.error(f"Unknown directive: {directive}")

    def include_file(self, filename: str):
        """Include and assemble another file."""
        # Resolve relative path from source directory
        if not os.path.isabs(filename):
            filename = os.path.join(self.source_dir, filename)

        # Normalize path for comparison
        filename = os.path.normpath(filename)

        # Check if already included (prevent infinite recursion)
        if filename in self.included_files:
            return  # Already included, skip

        self.included_files.add(filename)

        # Read and assemble the included file
        try:
            with open(filename, 'r') as f:
                included_source = f.read()
        except FileNotFoundError:
            self.error(f"Include file not found: {filename}")

        # Save current state
        old_line_num = self.line_num
        old_current_line = self.current_line

        # Assemble included file
        lines = included_source.split('\n')
        for i, line in enumerate(lines, 1):
            self.line_num = i
            self.current_line = f"[{os.path.basename(filename)}:{i}] {line}"
            try:
                self.assemble_line(line)
            except AssemblerError:
                raise
            except Exception as e:
                raise AssemblerError(str(e), i, line)

        # Restore state
        self.line_num = old_line_num
        self.current_line = old_current_line

    def assemble_line(self, line: str):
        """Assemble a single line."""
        # Remove comments
        if ';' in line:
            line = line[:line.index(';')]

        line = line.strip()
        if not line:
            return

        # Check for label (but not if colon is inside quotes)
        label = None
        # Find first colon that's not inside a quoted string
        colon_pos = -1
        in_string = False
        string_char = None
        for i, c in enumerate(line):
            if in_string:
                if c == string_char and (i == 0 or line[i-1] != '\\'):
                    in_string = False
            elif c in ('"', "'"):
                in_string = True
                string_char = c
            elif c == ':' and not in_string:
                colon_pos = i
                break
        
        if colon_pos != -1:
            label = line[:colon_pos].strip()
            line = line[colon_pos+1:].strip()
            if not line:
                # Label on its own line - store as pending, will be resolved on next line
                if label:
                    if label in self.labels or label in self.data_labels:
                        self.error(f"Duplicate label: {label}")
                    # Store as pending - next line will determine if code or data label
                    self.pending_label = label
                    self.pending_label_addr = self.current_addr()
                return

        # Resolve any pending label from previous line
        if hasattr(self, 'pending_label') and self.pending_label:
            pending = self.pending_label
            self.pending_label = None
            # Will be assigned below based on what follows
            label = label or pending  # Use pending if no label on this line

        # Split into mnemonic and operands
        parts = line.split(None, 1)
        mnemonic = parts[0].lower()

        operands = []
        if len(parts) > 1:
            # For .string directive, don't split - keep the whole thing
            if mnemonic == '.string':
                operands = [parts[1]]
            else:
                # Split operands by comma, respecting quoted strings
                operands = self.split_operands(parts[1])

        # Check for directive
        if mnemonic.startswith('.'):
            # For data directives, handle the label as a data label
            if mnemonic in ('.string', '.byte', '.word', '.space') and label:
                if label in self.labels or label in self.data_labels:
                    self.error(f"Duplicate label: {label}")
                self.pending_data_label = label
            elif label:
                # Regular label before non-data directive
                if label in self.labels or label in self.data_labels:
                    self.error(f"Duplicate label: {label}")
                self.labels[label] = self.current_addr()
            self.assemble_directive(mnemonic, operands)
            return

        # Regular instruction - assign label to code address
        if label:
            if label in self.labels or label in self.data_labels:
                self.error(f"Duplicate label: {label}")
            self.labels[label] = self.current_addr()

        # Assemble instruction
        if mnemonic == 'mov':
            self.assemble_mov(operands)
        elif mnemonic == 'movi':
            self.assemble_movi(operands)
        elif mnemonic == 'li':
            self.assemble_li(operands)
        elif mnemonic in ('add', 'sub', 'xor', 'and', 'or', 'mul', 'div', 'shl', 'shr', 'rol', 'ror'):
            self.assemble_arithmetic(mnemonic, operands)
        elif mnemonic in ('inc', 'dec'):
            self.assemble_unary(mnemonic, operands)
        elif mnemonic == 'ld':
            self.assemble_load(operands)
        elif mnemonic == 'st':
            self.assemble_store(operands)
        elif mnemonic in ('jmp', 'jz', 'jnz', 'jn'):
            self.assemble_jump(mnemonic, operands)
        elif mnemonic == 'call':
            self.assemble_call(operands)
        elif mnemonic == 'ret':
            self.assemble_ret(operands)
        elif mnemonic == 'syscall':
            self.assemble_syscall(operands)
        elif mnemonic == 'retk':
            self.assemble_retk(operands)
        elif mnemonic == 'halt':
            self.assemble_halt(operands)
        elif mnemonic == 'nop':
            self.assemble_nop(operands)
        elif mnemonic == 'cmp':
            self.assemble_cmp(operands)
        elif mnemonic == 'push':
            self.assemble_push(operands)
        elif mnemonic == 'pop':
            self.assemble_pop(operands)
        elif mnemonic == 'out':
            self.assemble_out(operands)
        elif mnemonic == 'lea':
            self.assemble_lea(operands)
        elif mnemonic == 'leab':
            self.assemble_leab(operands)
        else:
            self.error(f"Unknown instruction: {mnemonic}")

    def resolve_labels(self):
        """Resolve unresolved label references."""
        # Calculate base byte address for data section
        # Data starts after all code
        code_byte_size = sum(op.size() for op in self.code)
        data_base_addr = self.base_addr + code_byte_size

        for code_idx, label, line_num, line in self.unresolved:
            # Check for lea instruction (special format)
            if label.startswith('__lea__'):
                actual_label = label[7:]  # Remove __lea__ prefix
                if actual_label not in self.labels:
                    raise AssemblerError(f"Undefined label: {actual_label}", line_num, line)

                target_addr = self.labels[actual_label]
                high_byte = (target_addr >> 8) & 0xFF
                low_byte = target_addr & 0xFF

                # Update the lea instructions:
                # code_idx+0: PASS with high_byte
                # code_idx+3: OR with low_byte
                self.code[code_idx].imm = high_byte
                self.code[code_idx + 3].imm = low_byte

            # Check for leab instruction (load byte address for data)
            elif label.startswith('__leab__'):
                actual_label = label[8:]  # Remove __leab__ prefix
                if actual_label not in self.data_labels:
                    raise AssemblerError(f"Undefined data label: {actual_label}", line_num, line)

                # Compute byte address: data_base + offset_in_data
                data_offset = self.data_labels[actual_label]
                target_addr = data_base_addr + data_offset
                high_byte = (target_addr >> 8) & 0xFF
                low_byte = target_addr & 0xFF

                # Update the leab instructions (same format as lea):
                # code_idx+0: PASS with high_byte
                # code_idx+3: OR with low_byte
                self.code[code_idx].imm = high_byte
                self.code[code_idx + 3].imm = low_byte

            elif label.startswith('__jmp16imm__'):
                # Format: __jmp16imm__<mnemonic>__<label>
                parts = label.split('__')
                actual_label = parts[3]
                if actual_label not in self.labels:
                    raise AssemblerError(f"Undefined label: {actual_label}", line_num, line)

                target_addr = self.labels[actual_label]
                self.code[code_idx].imm = target_addr & 0xFFFF
                self.code[code_idx].imm16 = True

            # Check for 16-bit jump (special format)
            elif label.startswith('__jmp16__'):
                # Format: __jmp16__<mnemonic>__<label>
                parts = label.split('__')
                # parts = ['', 'jmp16', '<mnemonic>', '<label>']
                actual_label = parts[3]
                if actual_label not in self.labels:
                    raise AssemblerError(f"Undefined label: {actual_label}", line_num, line)

                target_addr = self.labels[actual_label]
                high_byte = (target_addr >> 8) & 0xFF
                low_byte = target_addr & 0xFF
                # Update the 16-bit jump instructions:
                # code_idx+0: PASS with high_byte
                # code_idx+3: OR with low_byte
                self.code[code_idx].imm = high_byte
                self.code[code_idx + 3].imm = low_byte

            # Check for 16-bit call target (special format)
            elif label.startswith('__call16__'):
                actual_label = label[10:]  # Remove __call16__ prefix
                if actual_label not in self.labels:
                    raise AssemblerError(f"Undefined label: {actual_label}", line_num, line)

                target_addr = self.labels[actual_label]
                high_byte = (target_addr >> 8) & 0xFF
                low_byte = target_addr & 0xFF

                # Update the 16-bit call instructions:
                # code_idx+0: PASS with high_byte
                # code_idx+3: OR with low_byte
                self.code[code_idx].imm = high_byte
                self.code[code_idx + 3].imm = low_byte

            else:
                target_addr = 0
                if label in self.labels:
                    target_addr = self.labels[label]
                elif label in self.data_labels:
                    # Data label: Address = Code End + Offset
                    target_addr = data_base_addr + self.data_labels[label]
                else:
                    raise AssemblerError(f"Undefined label: {label}", line_num, line)

                # Update the immediate field in the micro-op (use 8-bit or 16-bit?)
                # If the opcode supports imm16 (PASS/MOV), we should update imm16 if needed?
                # The existing code unconditionally sets .imm = target & 0xFF.
                # If target_addr > 255, this truncates!
                # But 'li' (movi) handles >255 by using imm16 path if value known?
                # If value unknown (label), it might have generated a byte-only op?
                # parse_operand -> movi -> emit MicroOp with imm16=True if needed?
                # When emitting movi with label, we don't know the value yet.
                # So we assume it fits? Or we force imm16 support?
                
                # Check if the instruction expects imm16
                if self.code[code_idx].imm16:
                     self.code[code_idx].imm = target_addr & 0xFFFF
                else:
                     self.code[code_idx].imm = target_addr & 0xFF


        # Resolve entry point if it's a label
        if isinstance(self.entry_point, str):
            if self.entry_point not in self.labels:
                raise AssemblerError(f"Undefined entry point label: {self.entry_point}")
            self.entry_point = self.labels[self.entry_point]

    def assemble(self, source: str, source_file: str = "") -> Executable:
        """Assemble source code into an executable."""
        self.code = []
        self.labels = MMIO_CONSTANTS.copy()
        self.data_labels = {}
        self.unresolved = []
        self.data = b''
        self.entry_point = 0
        self.included_files = set()
        self.deferred_includes = []
        self.pending_data_label = None
        self.pending_label = None

        # Set source directory for relative includes
        if source_file:
            self.source_dir = os.path.dirname(os.path.abspath(source_file))
            self.included_files.add(os.path.normpath(os.path.abspath(source_file)))
        else:
            self.source_dir = os.getcwd()

        lines = source.split('\n')
        for i, line in enumerate(lines, 1):
            self.line_num = i
            self.current_line = line
            try:
                self.assemble_line(line)
            except AssemblerError:
                raise
            except Exception as e:
                raise AssemblerError(str(e), i, line)

        # Process deferred includes
        while self.deferred_includes:
            inc_file = self.deferred_includes.pop(0)
            self.include_file(inc_file)

        self.resolve_labels()

        # Determine kernel size if auto
        if self.auto_kernel_size:
            # Kernel size is the size of the code section
            # Assuming code starts at base_addr (usually 0 for kernel)
            self.kernel_size = self.current_addr() - self.base_addr
            
        exe = Executable()
        exe.entry_point = self.entry_point
        exe.kernel_size = self.kernel_size
        exe.code = self.code
        exe.data = self.data

        return exe


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Fr Arch Assembler')
    parser.add_argument('infile', help='Input assembly file')
    parser.add_argument('outfile', nargs='?', default=None, help='Output binary file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--dump-labels', action='store_true', help='Print label addresses (byte-based) after assembly')

    args = parser.parse_args()

    # Read source file
    try:
        with open(args.infile, 'r') as f:
            source = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {args.infile}", file=sys.stderr)
        sys.exit(1)

    # Assemble
    assembler = Assembler()
    try:
        exe = assembler.assemble(source, args.infile)
    except AssemblerError as e:
        print(f"Assembler error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"Assembled {len(exe.code)} micro-ops")
        print(f"Entry point: 0x{exe.entry_point:04X}")
        print(f"Labels: {assembler.labels}")

    if args.dump_labels:
        for name, addr in sorted(assembler.labels.items(), key=lambda kv: kv[1]):
            print(f"{name}: 0x{addr:04X}")

    if not args.outfile:
        args.outfile = args.infile.removesuffix('.asm')+'.bin'

    # Write output
    try:
        with open(args.outfile, 'wb') as f:
            f.write(exe.encode())
        print(f"Output written to {args.outfile}")
    except Exception as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
