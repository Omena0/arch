# Fr Arch

This document defines a **minimal CPU architecture** using a **wired-XOR result bus** and **horizontal control words**. The design is intentionally simple, deterministic, and compact, with defined behavior for multi-source result composition.

---

## 1. Design Philosophy

* Single-cycle execution per instruction (1 micro-op = 1 instruction)
* No microcode sequencer or micro-PC
* Horizontal control word directly drives datapath
* Multiple result sources may be enabled simultaneously
* Result is defined as the **bitwise XOR** of all enabled sources
* This XOR behavior is a **first-class architectural feature**, not an error

Invalid or nonsensical combinations are considered programmer / assembler responsibility.

---

## 2. Core Components

### Memory Layout and Privilege

* Address space is divided into **kernel** and **user** regions
* Kernel region size is implementation-defined (e.g. `0x0000–0x7FFF`)
* User region occupies the remaining address space
* Jumping to any kernel address automatically enables privileged mode
* Only privileged mode may execute privileged control-word fields (`*`)
* Privileged mode is cleared explicitly via `CLEAR_PRIV`

### Registers

* General-purpose registers: `R0–R7` (3-bit addressing)
* Program Counter: `PC`
* Instruction Register: `IR`
* Status Flags: `Z` (zero), `N` (negative), optional others

### Memory

* Unified memory (Von Neumann)
* Single memory interface
* Memory reads can drive the RESULT bus
* Memory writes consume the RESULT bus

### ALU

* Operates on `SRC_A` and `SRC_B`
* Can also act as a selector (pass-through)
* Outputs either a computed value or zero
* Supports XOR operations to take advantage of multi-source XOR composition

---

## 3. RESULT Bus (Key Feature)

* Single internal data bus called **RESULT**
* Multiple units may drive RESULT simultaneously
* RESULT value = bitwise XOR of all active drivers
* Units must output **0** when not enabled

### RESULT Sources

* ALU output (if `ALU_OP != 0`)
* Memory read data (if `MEM_EN = 1` and `MEM_RW = 0`)
* Immediate (8-bit extension) to feed SRC_B or XOR directly onto bus

### RESULT Sinks

* Destination register
* Program Counter
* Memory (write)
* Flags

---

## 4. Control Word Format (16-bit base + 8/16-bit immediate + ext byte)

```table
Base Word (16 bits):
15  MEM_EN     Enable memory
14  MEM_RW     Memory mode: 0 = read, 1 = write
13  PC_WE      Write RESULT to PC
12  FLAG_WE    Update flags from RESULT
11–8 ALU_OP    ALU operation (pure, source selection removed)
7–5  DST       Destination register (000 = no write)
4–2  SRC_A     Source register A
1–0  SRC_B_reg Source register B

Immediate Byte (8 bits):
7–0  IMM_LO    Low 8 bits of immediate

Extension Byte (8 bits):
7    IMM16     Enable 16-bit immediate (instruction becomes 6 bytes)
6    XOR_IMM   XOR bus mode: 1 = XOR immediate (default), 0 = direct (OR)
5    DST_EN    Enable write to R0 when DST=000
4    CLEAR_PRIV* Clear privileged mode on next instruction
3    COND_Z    Skip if Z flag is false
2    COND_NZ   Skip if Z flag is true
1    COND_N    Skip if N flag is false
0    (reserved)

IMM_HI Byte (only if IMM16=1):
7–0  IMM_HI    High 8 bits of immediate

Padding Byte (only if IMM16=1):
7–0  (unused)  Padding for alignment
```

* Standard instruction: 4 bytes (base + imm_lo + ext + padding)
* Extended instruction: 6 bytes (base + imm_lo + ext + imm_hi + padding)
* When XOR_IMM=1 (default): RESULT = `ALU(SRC_A, SRC_B_reg) ⊕ IMM ⊕ MEM_DATA`
* When XOR_IMM=0 (direct): RESULT = `ALU(SRC_A, SRC_B_reg) | IMM ⊕ MEM_DATA`
* This allows loading constants in a single instruction without XOR gymnastics

---

## 5. ALU Operations

`ALU_OP = 0` means **ALU drives 0** onto RESULT.

Suggested encoding (XOR preserved, NOT removed):

```table
0000 PASS (do nothing)
0001 SELECT A
0010 SELECT B
0011 ADD
0100 SUB
0101 AND
0110 OR
0111 XOR
1000 SHL A
1001 SHR A
1010 INC A
1011 DEC A
1100 MUL
1101 DIV
1110 ROL A
1111 ROR A / other composable op
```

* ALU_OPs now produce **fully composable values** that can XOR with SRC_B, IMM, and memory
* NOT is removed because XOR-bus can achieve similar functionality

---

## 6. Memory Semantics

### Read

* `MEM_EN = 1`, `MEM_RW = 0`
* Memory drives RESULT (XORed with ALU / SRC_B / IMM)

### Write

* `MEM_EN = 1`, `MEM_RW = 1`
* Memory writes RESULT to address
* Address source is implementation-defined (e.g., SRC_A or ALU result)

---

## 7. Register Write Semantics

* If `DST != 000`, destination register latches RESULT
* Multiple sinks may latch RESULT in the same cycle

---

## 8. PC Semantics

* If `PC_WE = 1`, `PC ← RESULT`
* Otherwise, `PC ← PC + 1`
* Enables jumps, calls, and computed branches

### Privilege Interaction

* Memory is divided into **kernel** and **user** regions
* Jumping to an address in the kernel region automatically sets privileged mode
* Privileged mode remains active until `CLEAR_PRIV` is executed
* Jumping to user memory does **not** change privilege state

---

## 9. Flags

* Flags updated from RESULT if `FLAG_WE = 1`
* Suggested flags:

  * `Z`: RESULT == 0
  * `N`: MSB of RESULT

---

## 10. Example Instructions

This section demonstrates how real programs can be built using the XOR-bus micro-op model. Each example shows how multiple effects are fused into a single micro-op.

---

### 10.1 Register XOR with Memory + Immediate

```txt
R1 ← R2 ⊕ MEM[R3] ⊕ 0x80
```

Control word intent:

* `SRC_A = R2`
* `SRC_B = R3` (address already in R0 or via prior op)
* `ALU_OP = SELECT A`
* `MEM_EN = 1, MEM_RW = 0`
* `IMM_EN = 1, IMM = 0x80`
* `DST = R1`

Single-cycle fusion of register, memory, and immediate data.

---

### 10.2 Add and Jump (Computed Branch)

```txt
PC ← R1 + R2
```

Control word intent:

* `SRC_A = R1`
* `SRC_B = R2`
* `ALU_OP = ADD`
* `PC_WE = 1`

Used for function calls, indirect jumps, and switch tables.

---

### 10.3 Conditional Branch (Zero Flag)

```txt
if Z == 1: PC ← R4
```

Implementation:

* Prior instruction sets flags via `FLAG_WE`
* Branch instruction only enables `PC_WE` if Z is set

No special branch instruction required; condition is handled by the assembler or VM logic.

---

### 10.4 Load from Memory

```txt
R5 ← MEM[R0]
```

Control word intent:

* `MEM_EN = 1, MEM_RW = 0`
* `DST = R5`

ALU disabled; memory directly drives RESULT.

---

### 10.5 Store to Memory with Mask

```txt
MEM[R0] ← R6 ⊕ 0x0F
```

Control word intent:

* `SRC_A = R6`
* `ALU_OP = SELECT A`
* `IMM_EN = 1, IMM = 0x0F`
* `MEM_EN = 1, MEM_RW = 1`

Used for masked writes, flag updates, and bitfield operations.

---

### 10.6 Atomic-Like Critical Section Using FREEZE

```txt
FREEZE
R1 ← MEM[R0]
R1 ← R1 + 1
MEM[R0] ← R1
FREEZE
```

Semantics:

* First `FREEZE` prevents other cores from accessing `R0` address
* Sequence performs read-modify-write safely
* Second `FREEZE` releases memory

No retry loops or CAS required.

---

### 10.7 System Call (User → Kernel)

```txt
PC ← 0x0000
```

Semantics:

* Jumping to kernel region enables privileged mode
* Kernel reads syscall arguments from registers
* Kernel eventually executes `CLEAR_PRIV` and jumps back

This replaces a traditional `syscall` instruction.

---

### 10.8 Kernel Return to User

```txt
CLEAR_PRIV
PC ← R7
```

Returns to user code and drops privilege explicitly.

---

### 10.9 Function Call / Return

Call:

```txt
R7 ← PC + 1
PC ← target
```

Return:

```txt
PC ← R7
```

Link register convention avoids stack hardware.

---

### 10.10 Loop Example

```txt
loop:
R1 ← R1 - 1
if R1 != 0: PC ← loop
```

Uses `DEC`, flag update, and conditional PC write.

---

These examples show that the architecture supports:

* High-level control flow
* Memory-safe concurrency
* Syscalls and privilege separation
* Efficient bitwise and arithmetic operations

All using a small, fixed-format horizontal control word.

* `ALU_OP = SELECT A (R2)`
* `IMM = 0x0F`
* `MEM_EN = 1, MEM_RW = 1`

---

## 11. Architectural Rules (Normative)

1. RESULT-driving units must output 0 when disabled
2. RESULT is the bitwise XOR of all enabled sources
3. Multiple RESULT sinks may latch simultaneously
4. Undefined combinations are allowed but discouraged
5. XOR-composition is intentional and defined behavior

---

## 12. Design Tradeoffs

### Advantages

* Extremely expressive micro-ops
* Safe multi-source combination with XOR bus
* No multiplexers required on data path
* Immediate values and memory can be fused in one cycle
* Easy to emulate and implement

### Disadvantages

* Requires disciplined instruction encoding
* Harder to debug incorrect control words
* Not suitable for high-frequency designs if many XOR drivers are enabled

---

## 13. Assembler Abstraction Layer

Although executables consist purely of micro-ops, a conventional assembly language can be layered on top as a **pure compile-time abstraction**. The assembler lowers each logical instruction into one or more micro-ops.

There is **no hardware distinction** between "instructions" and "microcode" — instructions are macros.

---

### 13.1 Instruction Classes

The assembler exposes a familiar instruction set:

* Arithmetic: `add`, `sub`, `xor`, `and`, `or`, `mul`, `div`
* Memory: `ld`, `st`
* Control flow: `jmp`, `jz`, `jnz`, `call`, `ret`
* System: `syscall`, `retk`

Each maps directly to one or more micro-ops.

---

### 13.2 Arithmetic Instruction Lowering

#### Example: ADD

Assembly:

```asm
add r1, r2, r3   ; r1 = r2 + r3
````

Lowered micro-op:

```text
SRC_A = r2
SRC_B = r3
ALU_OP = ADD
DST = r1
FLAG_WE = 1
```

Single micro-op.

---

#### Example: XOR with Immediate

Assembly:

```asm
xor r1, r2, #0x80
```

Lowered micro-op:

```text
SRC_A = r2
ALU_OP = SELECT A
IMM_EN = 1
IMM = 0x80
DST = r1
```

Immediate is XORed directly onto the RESULT bus.

---

### 13.3 Memory Access Lowering

Memory addressing is explicit via `R0` (memory register).

#### Load

Assembly:

```asm
ld r1, [r2]
```

Lowering:

```text
; address setup
SRC_A = r2
ALU_OP = SELECT A
DST = R0

; load
MEM_EN = 1
MEM_RW = 0
DST = r1
```

Two micro-ops.

---

#### Store with Mask

Assembly:

```asm
st [r2], r3 ^ #0x0F
```

Lowering:

```text
; address setup
SRC_A = r2
ALU_OP = SELECT A
DST = R0

; store
SRC_A = r3
ALU_OP = SELECT A
IMM_EN = 1
IMM = 0x0F
MEM_EN = 1
MEM_RW = 1
```

---

### 13.4 Control Flow Lowering

#### Unconditional Jump

Assembly:

```asm
jmp r4
```

Lowering:

```text
SRC_A = r4
ALU_OP = SELECT A
PC_WE = 1
```

---

#### Conditional Jump (Zero)

Assembly:

```asm
jz r4
```

Lowering:

```text
if Z == 1:
    SRC_A = r4
    ALU_OP = SELECT A
    PC_WE = 1
```

Conditionality is resolved by the assembler or VM, not the datapath.

---

### 13.5 Function Call Convention

#### Call

Assembly:

```asm
call r5
```

Lowering:

```text
; save return
SRC_A = PC
ALU_OP = INC A
DST = r7

; jump
SRC_A = r5
ALU_OP = SELECT A
PC_WE = 1
```

---

#### Return

Assembly:

```asm
ret
```

Lowering:

```text
SRC_A = r7
ALU_OP = SELECT A
PC_WE = 1
```

---

### 13.6 System Calls

#### Syscall

Assembly:

```asm
syscall
```

Lowering:

```text
PC_WE = 1
IMM_EN = 1
IMM = 0x00   ; jump to kernel entry
```

Privilege is gained implicitly by jumping into kernel space.

---

#### Kernel Return

Assembly:

```asm
retk
```

Lowering:

```text
CLEAR_PRIV = 1
SRC_A = r7
ALU_OP = SELECT A
PC_WE = 1
```

---

### 13.7 Why This Works

* Assembly is just syntax sugar
* No instruction decoding hardware required
* Complex instructions decompose naturally
* The programmer can still write readable code

The VM executes **only micro-ops**, but humans never have to.

---

## 14. Summary

This architecture cleanly separates:

* **What programmers write** (assembly)
* **What the VM executes** (micro-ops)

Without adding hidden complexity or semantic gaps.

This CPU is a **minimal horizontal-control architecture** using a **wired-XOR dataflow model**. It trades safety and strictness for simplicity, expressiveness, and compactness, making it ideal for educational use, experimentation, or small FPGA softcores.

---

End of document.
