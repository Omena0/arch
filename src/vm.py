#!/usr/bin/env python3
"""
Fr VM

Usage: python vm.py <kernel.bin> [user.bin*] [--debug] [--trace]

Loads kernel into memory, passes user binary path to kernel.
Kernel is responsible for loading the user program.

Memory-Mapped I/O (BIOS):
  0xFF00 - PRINT_CHAR:    Write a character to stdout
  0xFF02 - PRINT_INT:     Write a 16-bit integer to stdout (decimal)
  0xFF04 - PRINT_HEX:     Write a 16-bit integer to stdout (hex)
  0xFF06 - PRINT_STR:     Write null-terminated string at address (R1)
  0xFF08 - INPUT_CHAR:    Read a character (blocking), result in read
  0xFF0A - INPUT_READY:   Read: 1 if input available, 0 otherwise
  0xFF0C - INPUT_LINE:    Read line to buffer at R1, max length R2
  0xFF0E - NEWLINE:       Write newline to stdout
  0xFF10 - TIMER_LO:      Read: low 16 bits of cycle counter
  0xFF12 - TIMER_HI:      Read: high 16 bits of cycle counter
  0xFF14 - RANDOM:        Read: random 16-bit value
  0xFF16 - EXIT:          Write: exit with code (value written)
  0xFF18 - SCREEN_X:      Write: set cursor X position (for future use)
  0xFF1A - SCREEN_Y:      Write: set cursor Y position (for future use)
  0xFF1C - SCREEN_CLEAR:  Write any value: clear screen
  0xFF1E - FLUSH:         Write any value: flush stdout

File I/O (kernel only):
  0xFF20 - FILE_OPEN:     Write: open file, path at R1, R0=handle or 0xFFFF on error
  0xFF22 - FILE_READ:     Write: read from R1=handle, buf=R2, len=R3, R0=bytes read
  0xFF24 - FILE_CLOSE:    Write: close file handle in R1
  0xFF26 - FILE_SIZE:     Read: get size of file handle in R1, R0=size (low), R1=size (high)
  0xFF28 - FILE_SEEK:     Write: seek handle=R1, pos_lo=R2, pos_hi=R3

Arguments:
  0xFF30 - ARG_COUNT:     Read: number of arguments passed to kernel
  0xFF32 - ARG_LEN:       Read: length of argument R1 (index)
  0xFF34 - ARG_COPY:      Write: copy arg R1 to buffer R2, max len R3

Screen (80x25 text mode):
  0xFF40 - SCREEN_WIDTH:  Read: screen width in characters (80)
  0xFF42 - SCREEN_HEIGHT: Read: screen height in characters (25)
  0xFF44 - SCREEN_PUTC:   Write: put char at cursor (R1=char, R2=color)
  0xFF46 - SCREEN_SETXY:  Write: set cursor position (R1=x, R2=y)
  0xFF48 - SCREEN_FLUSH:  Write any value: update screen display
  0xFF4A - SCREEN_GETC:   Read: get char at position R1=x, R2=y, returns char
  0xFF4C - SCREEN_BUF:    Write: write to screen buffer at R1=offset, value=char|color

Keyboard:
  0xFF50 - KB_AVAILABLE:  Read: 1 if key event available, 0 otherwise
  0xFF52 - KB_READ:       Read: pop key event (bits 0-7=ASCII, bit 8=release flag)
  0xFF54 - KB_MODIFIERS:  Read: modifier state (bit 0=shift, 1=ctrl, 2=alt)

Mouse:
  0xFF60 - MOUSE_X:       Read: mouse X position (0-79)
  0xFF62 - MOUSE_Y:       Read: mouse Y position (0-24)
  0xFF64 - MOUSE_BUTTONS: Read: button state (bit 0=left, 1=right, 2=middle)
  0xFF66 - MOUSE_WHEEL:   Read: wheel delta since last read
"""


import sys
import os

os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = '1'

import select
import time
import random
try:
    import pygame
except ImportError:
    pygame = None
import threading
from collections import deque
from executable import Executable, MicroOp


# Memory-mapped I/O addresses
MMIO_BASE = 0x0000

# Character I/O
MMIO_PRINT_CHAR   = 0x0000
MMIO_PRINT_INT    = 0x0002
MMIO_PRINT_HEX    = 0x0004
MMIO_PRINT_STR    = 0x0006
MMIO_INPUT_CHAR   = 0x0008
MMIO_INPUT_READY  = 0x000A
MMIO_INPUT_LINE   = 0x000C
MMIO_NEWLINE      = 0x000E

# Timer
MMIO_TIMER_LO     = 0x0010
MMIO_TIMER_HI     = 0x0012
MMIO_TIMER_INTERVAL = 0x0014
MMIO_RANDOM       = 0x0016
MMIO_EXIT         = 0x0018
MMIO_SCREEN_CLEAR = 0x001C
MMIO_FLUSH        = 0x001E

# File I/O
MMIO_FILE_OPEN    = 0x0020
MMIO_FILE_READ    = 0x0022
MMIO_FILE_CLOSE   = 0x0024
MMIO_FILE_SIZE    = 0x0026
MMIO_FILE_SEEK    = 0x0028

# Arguments
MMIO_ARG_COUNT    = 0x0030
MMIO_ARG_LEN      = 0x0032
MMIO_ARG_COPY     = 0x0034

# Screen (80x25 text mode)
MMIO_SCREEN_WIDTH  = 0x0040
MMIO_SCREEN_HEIGHT = 0x0042
MMIO_SCREEN_PUTC   = 0x0044
MMIO_SCREEN_SETXY  = 0x0046
MMIO_SCREEN_FLUSH  = 0x0048
MMIO_SCREEN_GETC   = 0x004A
MMIO_SCREEN_BUF    = 0x004C

# Keyboard / Mouse
MMIO_KB_AVAILABLE  = 0x0050
MMIO_KB_READ       = 0x0052
MMIO_KB_MODIFIERS  = 0x0054
MMIO_MOUSE_X       = 0x0060
MMIO_MOUSE_Y       = 0x0062
MMIO_MOUSE_BUTTONS = 0x0064
MMIO_MOUSE_WHEEL   = 0x0066

# Process Control
MMIO_SET_PROC_BASE  = 0x0070
MMIO_SET_PROC_LIMIT = 0x0072

# Kernel / Trap Constants
KERNEL_LOAD_ADDR    = 0x0100  # Start of kernel code
TRAP_VECTOR         = 0x0100  # Jump here on trap
TRAP_INFO_CAUSE     = 0x0080
TRAP_INFO_ADDR      = 0x0082 
TRAP_INFO_PC        = 0x0084 
TRAP_INFO_VALUE     = 0x0086

# MMIO Region End (Exclusive)
MMIO_END            = 0x0100

# Trap cause codes
TRAP_MMIO_READ    = 0x0001  # Unprivileged MMIO read
TRAP_MMIO_WRITE   = 0x0002  # Unprivileged MMIO write
TRAP_INVALID_OP   = 0x0003  # Invalid operation
TRAP_DIV_ZERO     = 0x0004  # Division by zero
TRAP_TIMER        = 0x0005  # Timer interrupt
TRAP_MEM_VIOLATION = 0x0006  # Memory protection violation


class VM:
    """Fr Arch VM."""

    def __init__(self, memory_size: int = 0x10000):
        self.memory_size = memory_size
        self.memory = bytearray(memory_size)

        # Registers R0-R7
        self.regs = [0] * 8

        # Special registers
        self.pc = 0
        self.ir = 0

        # Flags
        self.flag_z = False  # Zero flag
        self.flag_n = False  # Negative flag

        # Privilege mode
        self.privileged = False
        self.kernel_size = 0x8000

        # Process memory isolation
        self.process_mem_base = 0x0000
        self.process_mem_limit = 0x10000  # Default: full access (for kernel)

        # Execution state
        self.halted = False
        self.cycles = 0
        self.exit_code = None  # Set by MMIO_EXIT

        # Debug options
        self.trace = False
        self.debug = False

        # Input buffer for non-blocking input
        self.input_buffer = ""
        self.input_pos = 0

        # File handles (max 8 open files)
        self.file_handles = {}  # handle_id -> file object
        self.next_handle = 1

        # Command line arguments for kernel
        self.args = []

        # Timer interrupt
        self.timer_interval = 0  # 0 = disabled

        # Screen support (80x25 text mode)
        self.screen_width = 80
        self.screen_height = 25
        # Screen buffer: each cell is (char, color) where color is 0-255 (fg*16+bg)
        self.screen_buffer = [[(' ', 0x07) for _ in range(self.screen_width)] for _ in range(self.screen_height)]
        self.cursor_x = 0
        self.cursor_y = 0
        self.screen_dirty = False
        self.screen_enabled = False  # Set to True when first screen operation occurs

        # Keyboard support
        self.kb_queue = deque(maxlen=256)  # Queue of key events
        self.kb_modifiers = 0  # Bit 0=shift, 1=ctrl, 2=alt
        self.kb_thread = None
        self.kb_running = False

        # Mouse support
        self.mouse_x = 0
        self.mouse_y = 0
        self.mouse_buttons = 0  # Bit 0=left, 1=right, 2=middle
        self.mouse_wheel = 0

        # Pygame GUI support
        self.window = None
        self.font = None
        self.char_width = 8
        self.char_height = 16
        self.window_width = self.screen_width * self.char_width
        self.window_height = self.screen_height * self.char_height

    def trap(self, cause: int, fault_addr: int, value: int = 0):
        """Trigger a trap - write info to kernel memory and jump to trap vector."""
        if self.debug:
            cause_names = {1: "MMIO_READ", 2: "MMIO_WRITE", 5: "TIMER", 6: "MEM_VIOLATION"}
            cause_name = cause_names.get(cause, f"UNKNOWN({cause})")
            print(f"TRAP: {cause_name} addr=0x{fault_addr:04X} value=0x{value:04X}")

        # Write trap info to kernel memory area
        self.memory[TRAP_INFO_CAUSE] = cause & 0xFF
        self.memory[TRAP_INFO_CAUSE + 1] = (cause >> 8) & 0xFF
        self.memory[TRAP_INFO_ADDR] = fault_addr & 0xFF
        self.memory[TRAP_INFO_ADDR + 1] = (fault_addr >> 8) & 0xFF
        self.memory[TRAP_INFO_PC] = self.pc & 0xFF
        self.memory[TRAP_INFO_PC + 1] = (self.pc >> 8) & 0xFF
        self.memory[TRAP_INFO_VALUE] = value & 0xFF
        self.memory[TRAP_INFO_VALUE + 1] = (value >> 8) & 0xFF

        # Save registers R0-R7 to 0x0060 (Kernel Temp / Trap Frame)
        # This allows the kernel to restore clobbered registers
        trap_regs_base = 0x0060
        for i in range(8):
            val = self.regs[i]
            self.memory[trap_regs_base + i*2] = val & 0xFF
            self.memory[trap_regs_base + i*2 + 1] = (val >> 8) & 0xFF

        # Enter privileged mode and jump to trap vector
        self.privileged = True
        # Reset process memory bounds to allow full kernel access
        self.process_mem_base = 0x0000
        self.process_mem_limit = 0x10000
        self.pc = TRAP_VECTOR

    def load(self, exe: Executable):
        """Load executable into memory."""
        # Load kernel at KERNEL_LOAD_ADDR
        load_addr = KERNEL_LOAD_ADDR
        
        # Load code into memory (variable-size instructions)
        # Build byte-offset-to-instruction map for cached code
        self.code_map = {}  # byte_offset -> MicroOp

        byte_offset = 0
        current_phys_addr = load_addr

        for op in exe.code:
            self.code_map[current_phys_addr] = op
            data = op.encode()
            
            if current_phys_addr + len(data) > self.memory_size:
                raise MemoryError("Kernel code too large for memory")
                
            self.memory[current_phys_addr:current_phys_addr+len(data)] = data
            byte_offset += len(data)
            current_phys_addr += len(data)

        # Load data after code
        data_start = current_phys_addr
        if data_start + len(exe.data) > self.memory_size:
             raise MemoryError("Kernel data too large for memory")
             
        self.memory[data_start:data_start+len(exe.data)] = exe.data

        # Store code for reference
        self.code = exe.code
        
        # Calculate kernel end
        self.kernel_size = data_start + len(exe.data)

        # Entry point is a byte address
        self.pc = exe.entry_point

        # Clear the kernel data/trap area (0x0010-0x00FF) so flags/boot markers start at 0
        # Don't clear 0x0000-0x000F which contains the trap vector (kernel entry point)
        for i in range(0x0010, min(self.memory_size, 0x0100)):
            self.memory[i] = 0

    def fetch(self) -> tuple[MicroOp, int]:
        """Fetch micro-op at current PC (byte address). Returns (MicroOp, size_in_bytes)."""
        addr = self.pc
        if not self.privileged:
            # Address translation for user mode
            addr += self.process_mem_base

        # Check if we have cached code at this address
        # Only use cache for kernel code (addr < kernel_size), not user code
        # because user code can be loaded dynamically into memory
        # Note: addr here is physical address
        if self.privileged and addr < self.kernel_size and addr in self.code_map:
            op = self.code_map[addr]
            return (op, op.size())

        # Otherwise decode from memory
        # Check against memory size
        if addr + 4 > self.memory_size:
            # This might be a valid trap condition in user mode, but for now raise runtime error or trap
            # Raising trap during fetch isn't fully implemented, so just runtime error
            raise RuntimeError(f"PC out of bounds: 0x{self.pc:04X} (Phys: 0x{addr:04X})")

        # Read initial 4 bytes
        data = bytes(self.memory[addr:addr+4])
        # Check if imm16 flag is set (bit 7 of ext byte at offset 3)
        ext = data[3]
        if ext & 0x80:  # imm16 flag set
            if addr + 6 > self.memory_size:
                raise RuntimeError(f"PC out of bounds for imm16 instruction: 0x{self.pc:04X} (Phys: 0x{addr:04X})")
            data = bytes(self.memory[addr:addr+6])
        op = MicroOp.decode(data)
        return (op, op.size())

    def update_flags(self, result: int):
        """Update Z and N flags from result."""
        # Use 16-bit result for flag computation
        result_16 = result & 0xFFFF
        self.flag_z = (result_16 == 0)
        self.flag_n = bool(result_16 & 0x8000)

    def check_condition(self, op: MicroOp) -> bool:
        """Check if conditional execution should proceed."""
        if op.cond_z and not self.flag_z:
            return False
        if op.cond_nz and self.flag_z:
            return False
        if op.cond_n and not self.flag_n:
            return False
        return True

    def alu_execute(self, op: MicroOp, src_a: int, src_b: int) -> int:
        """Execute ALU operation and return result."""
        # All operations work on 16-bit values
        src_a &= 0xFFFF
        src_b &= 0xFFFF

        alu_op = op.alu_op

        if alu_op == 0:    # PASS - drive 0
            return 0
        elif alu_op == 1:  # SELECT A
            return src_a
        elif alu_op == 2:  # SELECT B
            return src_b
        elif alu_op == 3:  # ADD
            return (src_a + src_b) & 0xFFFF
        elif alu_op == 4:  # SUB
            return (src_a - src_b) & 0xFFFF
        elif alu_op == 5:  # AND
            return src_a & src_b
        elif alu_op == 6:  # OR
            return src_a | src_b
        elif alu_op == 7:  # XOR
            return src_a ^ src_b
        elif alu_op == 8:  # SHL A
            return (src_a << (src_b & 0xF)) & 0xFFFF
        elif alu_op == 9:  # SHR A
            return (src_a >> (src_b & 0xF)) & 0xFFFF
        elif alu_op == 10: # INC A
            return (src_a + 1) & 0xFFFF
        elif alu_op == 11: # DEC A
            return (src_a - 1) & 0xFFFF
        elif alu_op == 12: # MUL
            return (src_a * src_b) & 0xFFFF
        elif alu_op == 13: # DIV
            if src_b == 0:
                return 0xFFFF  # Division by zero returns max
            return (src_a // src_b) & 0xFFFF
        elif alu_op == 14: # ROL A
            shift = src_b & 0xF
            return ((src_a << shift) | (src_a >> (16 - shift))) & 0xFFFF
        elif alu_op == 15: # ROR A
            shift = src_b & 0xF
            return ((src_a >> shift) | (src_a << (16 - shift))) & 0xFFFF
        else:
            return 0

    def mem_read(self, addr: int) -> int:
        """Read 16-bit value from memory or MMIO."""
        addr &= 0xFFFF

        target_addr = addr
        if not self.privileged:
            target_addr = (addr + self.process_mem_base) & 0xFFFF

            if target_addr < self.kernel_size:
                 self.trap(TRAP_MEM_VIOLATION, target_addr)
                 return 0

            if target_addr >= self.process_mem_limit and target_addr < MMIO_BASE:
                 self.trap(TRAP_MEM_VIOLATION, target_addr)
                 return 0

            if target_addr >= MMIO_BASE:
                 self.trap(TRAP_MMIO_READ, target_addr)
                 return 0
        else:
             if target_addr >= MMIO_BASE:
                 return self.mmio_read(target_addr)

        if target_addr + 1 >= self.memory_size:
            return 0
        return self.memory[target_addr] | (self.memory[target_addr + 1] << 8)

    def mem_write(self, addr: int, value: int):
        """Write 16-bit value to memory or MMIO."""
        addr &= 0xFFFF
        value &= 0xFFFF

        target_addr = addr
        if not self.privileged:
            target_addr = (addr + self.process_mem_base) & 0xFFFF

            if target_addr < self.kernel_size:
                self.trap(TRAP_MEM_VIOLATION, target_addr, value)
                return

            if target_addr >= self.process_mem_limit and target_addr < MMIO_BASE:
                self.trap(TRAP_MEM_VIOLATION, target_addr, value)
                return

            if target_addr >= MMIO_BASE:
                self.trap(TRAP_MMIO_WRITE, target_addr, value)
                return
        else:
            if target_addr >= MMIO_BASE:
                self.mmio_write(target_addr, value)
                return

        if target_addr + 1 >= self.memory_size:
            return

        self.memory[target_addr] = value & 0xFF
        self.memory[target_addr + 1] = (value >> 8) & 0xFF

    def mmio_read(self, addr: int) -> int:
        """Handle memory-mapped I/O reads. Requires privileged mode."""
        if self.debug:
            print(f'[MMIO/read] addr=0x{addr:04X}')
        if not self.privileged:
            # MMIO access denied in user mode - trigger trap
            self.trap(TRAP_MMIO_READ, addr)
            return 0

        if addr == MMIO_INPUT_CHAR:
            # Blocking character read (waits for Pygame or Stdin)
            while True:
                # 1. Check Pygame Queue
                if self.kb_queue:
                    return self.kb_queue.popleft()

                # 2. Check Stdin (via select to avoid blocking the GUI)
                try:
                    # Only calculate rlist if stdin is valid
                    if sys.stdin:
                        rlist, _, _ = select.select([sys.stdin], [], [], 0)
                        if rlist:
                            ch = sys.stdin.read(1)
                            if ch: 
                                return ord(ch)
                            # If ch is empty, it's EOF. Return 0? 
                            # If we return 0, kernel loops. But at EOF strict loop is maybe inevitable?
                            return 0
                except:
                    pass

                # 3. Process Pygame events (keep window alive)
                if self.window is not None:
                    self._process_pygame_events()
                    if self.halted:
                        return 0

                # 4. Yield CPU
                time.sleep(0.01)

        elif addr == MMIO_INPUT_READY:
            # Non-blocking check if input is available
            try:
                # Check if there's buffered input
                if self.input_pos < len(self.input_buffer):
                    return 1
                # Check stdin for available data (Unix-like systems)
                if sys.stdin.isatty():
                    rlist, _, _ = select.select([sys.stdin], [], [], 0)
                    return 1 if rlist else 0
                return 1  # Non-TTY always has data available
            except:
                return 0

        elif addr == MMIO_TIMER_LO:
            return self.cycles & 0xFFFF

        elif addr == MMIO_TIMER_HI:
            return (self.cycles >> 16) & 0xFFFF

        elif addr == MMIO_RANDOM:
            return random.randint(0, 0xFFFF)

        elif addr == MMIO_FILE_SIZE:
            # Get file size - handle in R1
            handle = self.regs[1]
            if handle in self.file_handles:
                try:
                    f = self.file_handles[handle]
                    pos = f.tell()
                    f.seek(0, 2)  # Seek to end
                    size = f.tell()
                    f.seek(pos)  # Seek back
                    # Return low word in R0, high word in R1
                    self.regs[1] = (size >> 16) & 0xFFFF
                    return size & 0xFFFF
                except:
                    return 0xFFFF
            return 0xFFFF

        elif addr == MMIO_ARG_COUNT:
            return len(self.args)

        elif addr == MMIO_ARG_LEN:
            # Get length of argument at index R1
            idx = self.regs[1]
            if idx < len(self.args):
                return len(self.args[idx])
            return 0

        elif addr == MMIO_SCREEN_WIDTH:
            return self.screen_width

        elif addr == MMIO_SCREEN_HEIGHT:
            return self.screen_height

        elif addr == MMIO_SCREEN_GETC:
            # Get character at position R1=x, R2=y
            x = self.regs[1]
            y = self.regs[2]
            if 0 <= x < self.screen_width and 0 <= y < self.screen_height:
                char, color = self.screen_buffer[y][x]
                return (ord(char) & 0xFF) | ((color & 0xFF) << 8)
            return 0

        elif addr == MMIO_KB_AVAILABLE:
            # Check if keyboard event is available
            return 1 if len(self.kb_queue) > 0 else 0

        elif addr == MMIO_KB_READ:
            # Read and pop keyboard event
            if len(self.kb_queue) > 0:
                return self.kb_queue.popleft()
            return 0

        elif addr == MMIO_KB_MODIFIERS:
            # Read keyboard modifiers
            return self.kb_modifiers

        elif addr == MMIO_MOUSE_X:
            return self.mouse_x

        elif addr == MMIO_MOUSE_Y:
            return self.mouse_y

        elif addr == MMIO_MOUSE_BUTTONS:
            return self.mouse_buttons

        elif addr == MMIO_MOUSE_WHEEL:
            # Read and reset wheel delta
            delta = self.mouse_wheel
            self.mouse_wheel = 0
            return delta & 0xFFFF

        return 0

    def mmio_write(self, addr: int, value: int):
        """Handle memory-mapped I/O writes. Requires privileged mode."""
        if self.debug:
            print(f'[MMIO/write] addr=0x{addr:04X} value=0x{value:04X}')

        if not self.privileged:
            # MMIO access denied in user mode - trigger trap
            self.trap(TRAP_MMIO_WRITE, addr, value)
            return

        if addr == MMIO_PRINT_CHAR:
            # Print single character
            try:
                print(f"DEBUG: CHAR {chr(value & 0xFF)}")
                sys.stdout.write(chr(value & 0xFF))
                sys.stdout.flush()
            except:
                pass

        elif addr == MMIO_PRINT_INT:
            # Print as decimal integer (signed)
            if value & 0x8000:
                value = value - 0x10000  # Convert to signed
            sys.stdout.write(str(value))
            sys.stdout.flush()

        elif addr == MMIO_PRINT_HEX:
            # Print as hex
            sys.stdout.write(f"{value:04X}")
            sys.stdout.flush()

        elif addr == MMIO_PRINT_STR:
            # Print null-terminated string from address in R1
            str_addr = self.regs[1]

            output = []
            max_len = 4096  # Maximum string length
            bytes_read = 0
            while str_addr < self.memory_size and bytes_read < max_len:
                # Use mem_read to enforce memory protection
                word = self.mem_read(str_addr)
                ch = word & 0xFF  # Get low byte
                if ch == 0:
                    break
                output.append(chr(ch))
                str_addr += 1
                bytes_read += 1
            sys.stdout.write(''.join(output))
            sys.stdout.flush()

        elif addr == MMIO_INPUT_LINE:
            # Read line to buffer at R1, max length R2
            buf_addr = self.regs[1]
            max_len = self.regs[2]

            # Validate buffer size
            if max_len > 4096:
                max_len = 4096

            try:
                line = sys.stdin.readline()
                # Strip newline and limit length
                line = line.rstrip('\n\r')[:max_len - 1]
                # Write to memory with null terminator using mem_write
                for i, ch in enumerate(line):
                    if buf_addr + i < self.memory_size:
                        # Write single byte by reading word, modifying byte, writing back
                        addr = buf_addr + i
                        if addr % 2 == 0:
                            # Even address - modify low byte
                            word = self.mem_read(addr) if addr + 1 < self.memory_size else 0
                            word = (word & 0xFF00) | ord(ch)
                            self.mem_write(addr, word)
                        else:
                            # Odd address - modify high byte of previous word
                            word = self.mem_read(addr - 1)
                            word = (word & 0x00FF) | (ord(ch) << 8)
                            self.mem_write(addr - 1, word)
                # Null terminator
                if buf_addr + len(line) < self.memory_size:
                    addr = buf_addr + len(line)
                    if addr % 2 == 0:
                        word = self.mem_read(addr) if addr + 1 < self.memory_size else 0
                        word = (word & 0xFF00)
                        self.mem_write(addr, word)
                    else:
                        word = self.mem_read(addr - 1)
                        word = (word & 0x00FF)
                        self.mem_write(addr - 1, word)
                # Return length in R0
                self.regs[0] = len(line)
            except:
                self.regs[0] = 0

        elif addr == MMIO_NEWLINE:
            sys.stdout.write('\n')

        elif addr == MMIO_EXIT:
            # Exit with given code
            self.exit_code = value
            self.halted = True

        elif addr == 0x002C: # MMIO_SCREEN_CLEAR
            # Clear screen (ANSI escape)
            sys.stdout.write('\033[2J\033[H')

        elif addr == 0x002E: # MMIO_FLUSH
            sys.stdout.flush()

        elif addr == MMIO_FILE_OPEN:
            # Open file - path string at R1, returns handle in R0
            path_addr = self.regs[1]

            # Read null-terminated path from memory with length limit
            path_chars = []
            max_path_len = 256
            bytes_read = 0
            while path_addr < self.memory_size and bytes_read < max_path_len:
                # Use mem_read to enforce protection
                word = self.mem_read(path_addr)
                ch = word & 0xFF  # Get low byte
                if ch == 0:
                    break
                path_chars.append(chr(ch))
                path_addr += 1
                bytes_read += 1

            if bytes_read >= max_path_len:
                self.regs[0] = 0xFFFF  # Path too long
                return

            path = ''.join(path_chars)
            try:
                f = open(path, 'rb')
                # If it's a .bin file, decompress it and provide a BytesIO wrapper
                if path.endswith('.bin'):
                    compressed_data = f.read()
                    f.close()
                    try:
                        from zstd import decompress
                        from io import BytesIO
                        decompressed_data = decompress(compressed_data)
                        f = BytesIO(decompressed_data)
                    except:
                        # If decompression fails, try reading as-is
                        f = open(path, 'rb')
                handle = self.next_handle
                self.next_handle += 1
                self.file_handles[handle] = f
                self.regs[0] = handle
            except:
                self.regs[0] = 0xFFFF  # Error

        elif addr == MMIO_FILE_READ:
            # Read from file - handle=R1, buf=R2, len=R3, returns bytes read in R0
            handle = self.regs[1]
            buf_addr = self.regs[2]
            length = self.regs[3]

            # Validate buffer bounds and check for integer overflow
            if length > 0x10000 or buf_addr + length < buf_addr:  # Overflow check
                self.regs[0] = 0xFFFF
                return

            if buf_addr + length > self.memory_size:
                self.regs[0] = 0xFFFF
                return

            if self.debug: print(f"DEBUG: FILE_READ handle={handle} buf={buf_addr:04X} len={length}")
            if handle in self.file_handles:
                try:
                    data = self.file_handles[handle].read(length)
                    if self.debug: print(f"DEBUG: READ data len={len(data)} first bytes={data[:4].hex()}")
                    # Write using mem_write to enforce protection
                    for i, b in enumerate(data):
                        if buf_addr + i < self.memory_size:
                            addr = buf_addr + i
                            if addr % 2 == 0:
                                # Even address - modify low byte
                                word = self.mem_read(addr) if addr + 1 < self.memory_size else 0
                                word = (word & 0xFF00) | b
                                self.mem_write(addr, word)
                            else:
                                # Odd address - modify high byte of previous word
                                word = self.mem_read(addr - 1)
                                word = (word & 0x00FF) | (b << 8)
                                self.mem_write(addr - 1, word)
                    self.regs[0] = len(data)
                except:
                    self.regs[0] = 0xFFFF
            else:
                self.regs[0] = 0xFFFF

        elif addr == MMIO_FILE_CLOSE:
            # Close file - handle in R1
            handle = self.regs[1]
            if handle in self.file_handles:
                try:
                    self.file_handles[handle].close()
                    del self.file_handles[handle]
                    self.regs[0] = 0
                except:
                    self.regs[0] = 0xFFFF
            else:
                self.regs[0] = 0xFFFF

        elif addr == MMIO_FILE_SEEK:
            # Seek file - handle=R1, pos_lo=R2, pos_hi=R3
            handle = self.regs[1]
            pos = self.regs[2] | (self.regs[3] << 16)
            if handle in self.file_handles:
                try:
                    self.file_handles[handle].seek(pos)
                    self.regs[0] = 0
                except:
                    self.regs[0] = 0xFFFF
            else:
                self.regs[0] = 0xFFFF

        elif addr == MMIO_ARG_COPY:
            # Copy argument R1 to buffer R2, max len R3
            idx = self.regs[1]
            buf_addr = self.regs[2]
            max_len = self.regs[3]

            # Validate max_len
            if max_len > 4096:
                max_len = 4096

            if idx < len(self.args):
                arg = self.args[idx]
                length = min(len(arg), max_len - 1)
                # Write using mem_write to enforce protection
                for i in range(length):
                    if buf_addr + i < self.memory_size:
                        addr = buf_addr + i
                        if addr % 2 == 0:
                            # Even address - modify low byte
                            word = self.mem_read(addr) if addr + 1 < self.memory_size else 0
                            word = (word & 0xFF00) | ord(arg[i])
                            self.mem_write(addr, word)
                        else:
                            # Odd address - modify high byte
                            word = self.mem_read(addr - 1)
                            word = (word & 0x00FF) | (ord(arg[i]) << 8)
                            self.mem_write(addr - 1, word)
                # Null terminate
                if buf_addr + length < self.memory_size:
                    addr = buf_addr + length
                    if addr % 2 == 0:
                        word = self.mem_read(addr) if addr + 1 < self.memory_size else 0
                        word = (word & 0xFF00)
                        self.mem_write(addr, word)
                    else:
                        word = self.mem_read(addr - 1)
                        word = (word & 0x00FF)
                        self.mem_write(addr - 1, word)
                self.regs[0] = length
            else:
                self.regs[0] = 0

        elif addr == MMIO_SCREEN_PUTC:
            # Put character at cursor position: R1=char, R2=color
            if self.debug:
                print(f"SCREEN_PUTC: R1={self.regs[1]:04X} ('{chr(self.regs[1] & 0xFF)}'), R2={self.regs[2]:04X}, cursor=({self.cursor_x},{self.cursor_y})")
            self.screen_enabled = True
            char = chr(self.regs[1] & 0xFF)

            color = self.regs[2] & 0xFF

            if 0 <= self.cursor_x < self.screen_width and 0 <= self.cursor_y < self.screen_height:
                self.screen_buffer[self.cursor_y][self.cursor_x] = (char, color)
                self.screen_dirty = True
                if self.debug:
                    print(f"  -> Set screen_buffer[{self.cursor_y}][{self.cursor_x}] = ('{char}', 0x{color:02X})")

        elif addr == MMIO_SCREEN_SETXY:
            # Set cursor position: R1=x, R2=y
            if self.debug:
                print(f"SCREEN_SETXY: R1={self.regs[1]:04X}, R2={self.regs[2]:04X}")
            self.screen_enabled = True
            self.cursor_x = self.regs[1] % self.screen_width
            self.cursor_y = self.regs[2] % self.screen_height
            if self.debug:
                print(f"  -> cursor now at ({self.cursor_x},{self.cursor_y})")

        elif addr == MMIO_SCREEN_FLUSH:
            # Flush screen buffer to display
            if self.debug:
                print(f"SCREEN_FLUSH: rendering screen")
            self.render_screen()
            self.screen_dirty = False

        elif addr == MMIO_SCREEN_BUF:
            # Write directly to screen buffer at offset R1
            # value = char (low byte) | color (high byte)
            self.screen_enabled = True
            offset = self.regs[1]
            if 0 <= offset < self.screen_width * self.screen_height:
                y = offset // self.screen_width
                x = offset % self.screen_width
                char = chr(value & 0xFF)
                color = (value >> 8) & 0xFF
                self.screen_buffer[y][x] = (char, color)
                self.screen_dirty = True

        elif addr == MMIO_TIMER_INTERVAL:
            self.timer_interval = value

        elif addr == MMIO_SET_PROC_BASE:
            # Set process memory base (for process isolation)
            self.process_mem_base = value & 0xFFFF

        elif addr == MMIO_SET_PROC_LIMIT:
            # Set process memory limit (for process isolation)
            self.process_mem_limit = value & 0xFFFF

    def render_screen(self):
        """Render screen using pygame GUI."""
        if pygame is None:
            return

        if not pygame.get_init():
            pygame.init()

        if self.window is None:
            self.window = pygame.display.set_mode((self.window_width, self.window_height))

            # Use a monospace font - try to get courier
            try:
                self.font = pygame.font.SysFont('courier', 16, bold=True)
            except:
                self.font = pygame.font.Font(None, 16)

            # Recalculate character size based on actual font
            test_surface = self.font.render('W', True, (255, 255, 255))
            self.char_width = test_surface.get_width()
            self.char_height = self.font.get_height()

            # Fill with a test pattern to verify rendering works
            for y in range(5):
                for x in range(20):
                    self.screen_buffer[y][x] = (chr(65 + (x % 26)), 0x0F)

        # Color palette (RGB values for 16-color EGA palette)
        palette = {
            0x0: (0, 0, 0),         # Black
            0x1: (0, 0, 170),       # Blue
            0x2: (0, 170, 0),       # Green
            0x3: (0, 170, 170),     # Cyan
            0x4: (170, 0, 0),       # Red
            0x5: (170, 0, 170),     # Magenta
            0x6: (170, 85, 0),      # Brown
            0x7: (170, 170, 170),   # Light Gray
            0x8: (85, 85, 85),      # Dark Gray
            0x9: (85, 85, 255),     # Light Blue
            0xA: (85, 255, 85),     # Light Green
            0xB: (85, 255, 255),    # Light Cyan
            0xC: (255, 85, 85),     # Light Red
            0xD: (255, 85, 255),    # Light Magenta
            0xE: (255, 255, 85),    # Yellow
            0xF: (255, 255, 255),   # White
        }

        # Clear to black
        self.window.fill((0, 0, 0))

        # Render each character
        for y in range(self.screen_height):
            for x in range(self.screen_width):
                char, color = self.screen_buffer[y][x]
                fg = color & 0x0F
                bg = (color >> 4) & 0x0F

                # Draw background rectangle (always draw, even for spaces)
                bg_color = palette.get(bg, (0, 0, 0))
                rect = pygame.Rect(x * self.char_width, y * self.char_height,
                                  self.char_width, self.char_height)
                pygame.draw.rect(self.window, bg_color, rect)

                # Draw character (render all characters, not just non-spaces)
                fg_color = palette.get(fg, (255, 255, 255))
                try:
                    # Render with background color for better visibility
                    text_surface = self.font.render(char, True, fg_color, bg_color)
                    self.window.blit(text_surface, (x * self.char_width, y * self.char_height))
                except:
                    # If character can't be rendered, just skip it
                    pass

        pygame.display.flip()

        # Process pygame events (keyboard, mouse)
        self._process_pygame_events()

    def _process_pygame_events(self):
        """Process pygame events for keyboard and mouse input."""
        if pygame is None:
            return

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.halted = True
                self.exit_code = 0

            elif event.type == pygame.KEYDOWN:
                # Convert pygame key to ASCII if possible
                if event.unicode and len(event.unicode) == 1:
                    key_code = ord(event.unicode)
                    self.kb_queue.append(key_code)

                # Update modifiers
                mods = pygame.key.get_mods()
                self.kb_modifiers = 0
                if mods & (pygame.KMOD_LSHIFT | pygame.KMOD_RSHIFT):
                    self.kb_modifiers |= 0x01
                if mods & (pygame.KMOD_LCTRL | pygame.KMOD_RCTRL):
                    self.kb_modifiers |= 0x02
                if mods & (pygame.KMOD_LALT | pygame.KMOD_RALT):
                    self.kb_modifiers |= 0x04

            elif event.type == pygame.MOUSEMOTION:
                # Convert pixel position to character position
                self.mouse_x = min(event.pos[0] // self.char_width, self.screen_width - 1)
                self.mouse_y = min(event.pos[1] // self.char_height, self.screen_height - 1)

            elif event.type == pygame.MOUSEBUTTONDOWN:
                if event.button == 1:  # Left
                    self.mouse_buttons |= 0x01
                elif event.button == 3:  # Right
                    self.mouse_buttons |= 0x02
                elif event.button == 2:  # Middle
                    self.mouse_buttons |= 0x04
                elif event.button == 4:  # Wheel up
                    self.mouse_wheel += 1
                elif event.button == 5:  # Wheel down
                    self.mouse_wheel -= 1

            elif event.type == pygame.MOUSEBUTTONUP:
                if event.button == 1:  # Left
                    self.mouse_buttons &= ~0x01
                elif event.button == 3:  # Right
                    self.mouse_buttons &= ~0x02
                elif event.button == 2:  # Middle
                    self.mouse_buttons &= ~0x04

    def start_keyboard_thread(self):
        """Start background thread for keyboard input (for raw mode)."""
        if self.kb_running:
            return

        def kb_loop():
            # This is a simple implementation - production would use termios for raw mode
            while self.kb_running:
                try:
                    if select.select([sys.stdin], [], [], 0.1)[0]:
                        ch = sys.stdin.read(1)
                        if ch:
                            # Queue the key event (ASCII code)
                            key_event = ord(ch) & 0xFF
                            self.kb_queue.append(key_event)
                except:
                    pass

        self.kb_running = True
        self.kb_thread = threading.Thread(target=kb_loop, daemon=True)
        self.kb_thread.start()

    def stop_keyboard_thread(self):
        """Stop keyboard thread."""
        if self.kb_running:
            self.kb_running = False
            if self.kb_thread:
                self.kb_thread.join(timeout=0.5)

    def execute(self, op: MicroOp, inst_size: int = 4):
        """Execute a single micro-op. inst_size is in bytes (4 or 6)."""
        # PC is now always a byte address, increment by instruction size
        pc_inc = inst_size

        # Check conditional execution
        if not self.check_condition(op):
            self.pc += pc_inc
            if op.clear_priv:
                self.privileged = False

            return

        # NOTE: clear_priv is processed at the END of execution, not here,
        # to allow privileged memory operations to complete first

        # Get source register values
        src_a = self.regs[op.src_a]
        src_b = self.regs[op.src_b]

        # Compute RESULT via XOR bus (or direct if xor_imm is False)
        # RESULT = ALU(SRC_A, SRC_B) XOR/OR IMM XOR MEM_DATA (if mem read enabled)
        result = self.alu_execute(op, src_a, src_b)

        if op.xor_imm:
            result ^= op.imm  # XOR bus (original behavior)
        else:
            # Direct - OR the immediate in
            # If this is a direct memory operation (mem_en=True), the immediate
            # is the address, so we don't want to mix it into the data path.
            if not op.mem_en:
                result |= op.imm

        # Memory read contributes to XOR bus
        if op.mem_en and not op.mem_rw:
            if not op.xor_imm:
                # Direct addressing: Address from immediate
                addr = op.imm
            else:
                # Indirect addressing: Address from register
                addr = self.regs[op.src_a]

            mem_data = self.mem_read(addr)
            result ^= mem_data

        result &= 0xFFFF

        # Memory write consumes RESULT
        if op.mem_en and op.mem_rw:
            if not op.xor_imm:
                # Direct addressing: Address from immediate
                addr = op.imm
            else:
                # Indirect addressing: Address from register
                addr = self.regs[op.src_a]
            self.mem_write(addr, result)

        # Update destination register
        if op.dst != 0 or op.dst_en:
            self.regs[op.dst] = result

        # Update flags
        if op.flag_we:
            self.update_flags(result)

        # Update PC
        if op.pc_we:
            new_pc = result
            # Check for privilege escalation (unless clear_priv was requested)
            if new_pc < self.kernel_size and not op.clear_priv:
                self.privileged = True
                # Reset process memory bounds to allow full kernel access
                self.process_mem_base = 0x0000
                self.process_mem_limit = 0x10000
            self.pc = new_pc
        else:
            self.pc += pc_inc

        # Handle privilege clearing AFTER all memory operations and PC update
        # This allows retk to read the saved PC from kernel memory before dropping privilege
        if op.clear_priv:
            self.privileged = False

    def step(self) -> bool:
        """Execute one instruction. Returns False if halted."""
        if self.halted:
            return False

        # Process GUI events periodically (every 100 cycles when GUI is active)
        if self.window is not None:
            if self.cycles % 100 == 0:
                self._process_pygame_events()

        # Check if PC (byte address) is within valid range
        if self.pc + 4 > self.memory_size:
            self.halted = True
            return False

        old_pc = self.pc
        op, inst_size = self.fetch()

        if self.trace:
            self.print_state(op)

        self.execute(op, inst_size)
        self.cycles += 1

        # Timer interrupt (only triggers if in user mode to avoid kernel re-entrancy)
        if self.timer_interval > 0 and (self.cycles % self.timer_interval) == 0:
            if not self.privileged:
                self.trap(TRAP_TIMER, self.pc)

        # Detect halt (jump to self)
        if self.pc == old_pc:
            self.halted = True
            return False

        return True

    def run(self, max_cycles: int = 1000000) -> int:
        """Run until halted or max cycles reached. Returns exit code."""

        while self.cycles < max_cycles:
            if not self.step():
                break

        if self.cycles >= max_cycles:
            print(f"Warning: Execution stopped after {max_cycles} cycles", file=sys.stderr)

        # Return MMIO exit code if set, otherwise R0
        if self.exit_code is not None:
            return self.exit_code & 0xFFFF
        return self.regs[0]

    def print_state(self, op: MicroOp|None = None):
        """Print current VM state."""
        regs_str = ' '.join(f"R{i}={self.regs[i]:04X}" for i in range(8))
        flags_str = f"Z={int(self.flag_z)} N={int(self.flag_n)}"
        priv_str = "PRIV" if self.privileged else "USER"

        print(f"[{self.cycles:06d}] PC={self.pc:04X} {regs_str} {flags_str} {priv_str}")
        if op:
            print(f"         {op}")

    def dump_memory(self, start: int, length: int):
        """Dump memory region."""
        for i in range(start, start + length, 16):
            chunk = self.memory[i:i+16]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"0x{i:04X}: {hex_str}  {ascii_str}")


def main():
    import argparse

    # Custom parser: flags before kernel, everything after kernel passed to it
    parser = argparse.ArgumentParser(
        description='Fr Arch VM',
        usage='%(prog)s [options] kernel [args...]'
    )
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug mode')
    parser.add_argument('--trace', '-t', action='store_true', help='Trace execution')
    parser.add_argument('--max-cycles', '-m', type=int, default=1000000, help='Maximum cycles')
    parser.add_argument('--disasm', action='store_true', help='Disassemble and exit')
    parser.add_argument('kernel', help='Kernel executable file')
    parser.add_argument('kernel_args', nargs='*', help='Arguments passed to kernel')

    args = parser.parse_args()

    # Load kernel executable
    try:
        with open(args.kernel, 'rb') as f:
            data = f.read()
        exe = Executable.decode(data)
        exe.is_kernel = True

    except FileNotFoundError:
        print(f"Error: Kernel not found: {args.kernel}", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"Error loading kernel: {e}", file=sys.stderr)
        sys.exit(1)

    if args.disasm:
        from executable import disassemble
        print(disassemble(exe))
        sys.exit(0)

    # Create and configure VM
    vm = VM()
    vm.trace = args.trace
    vm.debug = args.debug

    # Pass all remaining arguments to kernel
    vm.args = args.kernel_args

    # Load kernel into memory
    vm.load(exe)

    # Start in privileged mode (kernel)
    vm.privileged = True

    if args.debug:
        print(f"Loaded kernel: {len(exe.code)} micro-ops, entry=0x{exe.entry_point:04X}")
        print(f"Arguments: {vm.args}")
        vm.print_state()

    # Run
    exit_code = vm.run(args.max_cycles)

    if args.debug:
        print(f"\nExecution finished after {vm.cycles} cycles")
        vm.print_state()

    sys.exit(exit_code & 0xFF)


if __name__ == '__main__':
    main()
