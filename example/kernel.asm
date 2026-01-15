; Fr Kernel
; Provides syscall interface, trap handling, and user program loading
;
; Memory Layout:
;   0x0000-0x000F: Kernel entry / trap vector
;   0x0010-0x001F: Trap info area (written by VM on trap)
;   0x0018:        Booted flag (1 = kernel initialized)
;   0x001A:        User program loaded flag
;   0x0020-0x00FF: Kernel data (path buffer, etc)
;   0x0100-0x07EF: Kernel code + stack (stack at 0x07F0 grows down)
;   0x0800+:       User code (loaded from file)
;
; Trap Info (set by VM on privilege violation):
;   0x0010: Trap cause (1=MMIO read, 2=MMIO write, 5=Timer)
;   0x0012: Faulting address
;   0x0014: PC when trap occurred
;   0x0016: Value being written (for write traps)
;
; Kernel Variables:
;   0x0018: Booted flag (1 = kernel initialized)
;   0x0020: Current PID
;   0x0022: Process Count
;   0x0024: Alive Process Count
;   0x002A: Init Loop Counter
;   0x0040: Process Table Base (32 bytes per process)
;           PCB Layout per process (32 bytes):
;             +0:  R0-R7 (16 bytes)
;             +16: PC (2 bytes)
;             +18: Backing Store Address (2 bytes)
;             +20: SP (2 bytes)
;             +22: State (2 bytes): 0=dead, 1=alive
;             +24-31: Reserved
;   0x0060: Reg Save Area (Dispatcher/Scheduler Temp)
;   0x0080: Filename Temp Buffer
;
; Syscall Convention:
;   R1 = syscall number
;   R2, R3 = arguments
;   R0 = return value
;   R7 = return address (set by 'syscall' instruction)

.base 0x0100
.entry start
.kernel auto

; ============================================================================
; ENTRY POINT (address 0x0100) - called on boot and syscall
; ============================================================================
start:
    ; FIRST THING: Save all user registers R0-R7 to trap frame
    st [#USER_REGS_ADDR], r0
    st [#USER_REGS_ADDR+2], r1
    st [#USER_REGS_ADDR+4], r2
    st [#USER_REGS_ADDR+6], r3
    st [#USER_REGS_ADDR+8], r4
    st [#USER_REGS_ADDR+10], r5
    st [#USER_REGS_ADDR+12], r6
    st [#USER_REGS_ADDR+14], r7

    jmp dispatcher
dispatcher:
    li r0, #TRAP_INFO_CAUSE
    ld r5, [r0]         ; R5 = Cause

    mov r4, #0
    sub r4, r5, r4
    jnz handle_vm_trap  ; If Cause != 0, go to trap handler

    ; Check if this is boot (first run)
    li r0, kvar_booted
    ld r5, [r0]         ; R5 = booted flag

    ; If R5 == 0, this is boot - go to init
    mov r4, #0
    sub r4, r5, r4      ; Sets Z if R5==0
    jz kernel_boot

    ; Already booted, Cause=0 => Syscall
    ; User registers are saved in trap frame
    ; R1 = syscall number, R7 = return address

    ; Load return address from trap frame for validation
    li r0, #USER_REGS_ADDR+14
    ld r7, [r0]         ; R7 = saved user R7 (return address)

    ; Return address validation removed - user space starts at 0 (logical)
    ; VM hardware enforces protection via privileged bit.
    ; mov r4, #0x0900
    ; sub r4, r7, r4
    ; jn invalid_return


    ; Save Return Address (R7) to TRAP_INFO_PC (0x0014) so retk works
    li r0, #TRAP_INFO_PC
    st [r0], r7

    jmp do_syscall

invalid_return:
    ; Return address validation failed - kill the process.
    jmp sys_exit

handle_vm_trap:
    ; Check if MMIO Read/Write (Cause 1 or 2) - not allowed from user mode
    mov r4, #1
    sub r4, r5, r4
    jz mmio_violation_handler

    mov r4, #2
    sub r4, r5, r4
    jz mmio_violation_handler

    ; Check if Timer (Cause 5)
    mov r4, #5
    sub r4, r5, r4
    jz scheduler_entry

    ; Check if Memory Violation (Cause 6)
    mov r4, #6
    sub r4, r5, r4
    jz mem_violation_handler

    ; Other traps: Ignore or Halt
    jmp sys_exit

mmio_violation_handler:
    ; User mode tried to access MMIO directly - not allowed
    leab r1, mmio_violation_msg
    call print_string
    jmp sys_exit

mem_violation_handler:
    ; Memory violation detected
    ; For now, print error message and halt
    ; In a real OS, we would kill the offending process
    leab r1, mem_violation_msg
    call print_string
    jmp sys_exit

scheduler_entry:
    ; Clear trap cause so we don't re-trigger immediately (in loop) if we check it again
    li r0, #TRAP_INFO_CAUSE
    mov r5, #0
    st [r0], r5

    jmp scheduler

kernel_boot:
    ; Set booted flag to 1
    li r0, kvar_booted
    mov r5, #1
    st [r0], r5

    ; Clear trap cause
    li r0, #TRAP_INFO_CAUSE
    mov r5, #0
    st [r0], r5

    ; Initialize stack pointer to 0x07F0
    li r6, #0x07F0

    ; Initialize alive process count to 0
    li r0, kvar_alive_count
    mov r1, #0
    st [r0], r1

    ; Print boot message
    leab r1, boot_msg
    call print_string

    ; Enable Timer (Interval = 5000 cycles)
    li r0, #MMIO_TIMER_INTERVAL      ; MMIO_TIMER_INTERVAL
    li r1, #5000        ; 5k cycles for context switch
    st [r0], r1

    ; Initialize Process Table
    call init_processes

    ; Check if we found any processes
    ; ld r0, [0x0022]
    li r1, kvar_proc_count
    ld r0, [r1]     ; num_procs

    mov r4, #0
    sub r4, r0, r4
    jz no_user_program

    ; Start Process 0
    mov r0, #0
    li r1, kvar_pid
    st [r1], r0     ; current_pid = 0

    ; Jump to restore_context which will load Proc 0 and jump to it
    jmp restore_context

    ; Should not return
    halt

no_user_program:
    ; No user program - print error and exit
    leab r1, no_prog_msg
    call print_string

    li r0, #MMIO_EXIT      ; EXIT
    li r1, #1           ; Code 1
    st [r0], r1
    halt

load_fail:
    ; Just halt for now
    leab r1, load_fail_msg
    call print_string
    jmp sys_exit

; ============================================================================
; Scheduler
; ============================================================================
scheduler:
    ; Save Context of Current Process to PCB[pid]
    call save_context

    ; Yield logic (Round Robin)
    call pick_next_process

    ; Restore Context
    jmp restore_context

; ============================================================================
; Save Context (Current Process -> PCB & Backing Store)
; Input: None
; Clobbers: R0-R7 (Safely stored first)
; ============================================================================
save_context:
    ; R0-R7 were saved to 0x0060 by Dispatcher (NEED TO IMPLEMENT DISPATCHER SAVE)
    ; Assuming R0-R7 are contiguous at 0x0060..0x006F

    ; 1. Identify Current PID
    ; ld r0, [0x0020]
    li r1, kvar_pid
    ld r0, [r1]     ; pid

    ; 2. Calculate PCB Address: 0x0040 + pid*32
    mov r1, #32
    mul r1, r0, r1
    li r2, proc_table_base
    add r1, r1, r2      ; R1 = PCB Base

    ; 3. Store Registers from Temp (0x0060) to PCB (R1+0)
    li r2, #USER_REGS_ADDR      ; Source
    mov r3, #8          ; Count (8 words)
save_regs_loop:
    ld r4, [r2]         ; Load from temp
    st [r1], r4         ; Store to PCB
    inc r2
    inc r2
    inc r1
    inc r1
    dec r3
    jnz save_regs_loop

    ; R1 is now PCB+16 (Offset for PC)

    ; 4. Save PC from TRAP_INFO_PC (0x0014)
    li r2, #TRAP_INFO_PC
    ld r4, [r2]
    st [r1], r4         ; PCB.pc = TrapPC

    ; R1 -> Offset 18
    inc r1
    inc r1

    ; 5. Get Backing Store Ptr
    ld r5, [r1]         ; R5 = Backing Store Address

    ; 6. Swap Out (0x0900..0x1900 -> Backing)
    li r2, #0x0900      ; Source
    li r3, #0x0800      ; Count (Words)

swap_out_loop:
    ld r4, [r2]         ; Read word from User Mem
    st [r5], r4         ; Write word to Backing
    inc r2
    inc r2
    inc r5
    inc r5
    dec r3
    jnz swap_out_loop

    ret

; ============================================================================
; Pick Next Process (Round Robin)
; Skips dead processes and halts if all processes are dead
; ============================================================================
pick_next_process:
    ; Save starting PID to detect full loop
    li r1, kvar_pid
    ld r3, [r1]     ; R3 = starting current_pid

    ; Get total process count
    li r2, kvar_proc_count
    ld r4, [r2]     ; R4 = num_procs

    mov r5, #0      ; R5 = attempts counter

pick_loop:
    ; Increment attempts
    inc r5

    ; Check if we've tried all processes
    sub r0, r5, r4
    jz no_alive_processes   ; If attempts >= num_procs, all are dead

    ; Move to next PID
    li r1, kvar_pid
    ld r0, [r1]     ; current_pid
    inc r0
    sub r2, r0, r4  ; Check if pid >= num_procs
    jz pick_wrap
    jmp pick_check_state

pick_wrap:
    mov r0, #0

pick_check_state:
    ; Check if this process is alive
    ; PCB base = 0x0040 + pid*32
    ; State is at offset +22
    mov r1, #32
    mul r1, r0, r1
    li r2, proc_table_base
    add r1, r1, r2      ; R1 = PCB base

    li r2, #22
    add r2, r1, r2      ; R2 = address of state field
    ld r2, [r2]         ; R2 = state value

    ; If state == 0 (dead), try next
    mov r6, #0
    sub r6, r2, r6
    jz pick_loop        ; Dead, try next

    ; Alive! Set as current PID
    li r1, kvar_pid
    st [r1], r0
    ret

no_alive_processes:
    li r0, #MMIO_EXIT      ; MMIO_EXIT
    mov r1, #0          ; Exit code 0
    st [r0], r1
    halt

; ============================================================================
; Restore Context (PCB -> User Mem & Registers)
; ============================================================================
restore_context:
    ; 1. Identify New PID
    ; ld r0, [0x0020]
    li r1, kvar_pid
    ld r0, [r1]     ; pid

    ; 2. Calculate PCB Address
    mov r1, #32
    mul r1, r0, r1
    li r2, proc_table_base
    add r1, r1, r2      ; R1 = PCB Base

    ; 3. Get Backing Store Ptr (Offset 18)
    li r3, #18
    add r3, r1, r3
    ld r5, [r3]         ; R5 = Backing Addr

    ; 4. Swap In (Backing -> 0x0900)
    li r2, #0x0900      ; Dest
    li r3, #0x0800      ; Count (Words)

swap_in_loop:
    ld r4, [r5]         ; Read from Backing
    st [r2], r4         ; Write to User
    inc r2
    inc r2
    inc r5
    inc r5
    dec r3
    jnz swap_in_loop

    ; 5. Restore PC (Offset 16)
    ; Re-calc Base + 16 (Simplest way)
    ; ld r0, [0x0020]
    li r1, kvar_pid
    ld r0, [r1]

    mov r1, #32
    mul r1, r0, r1
    li r2, proc_table_base
    add r1, r1, r2      ; R1 = PCB Base

    li r2, #16          ; Offset 16
    add r1, r1, r2      ; R1 = PCB.PC address

    ld r4, [r1]         ; R4 = Saved PC

    ; Validate PC is in user space
    ; VM enforces protection.
    ; mov r5, #0x0900
    ; sub r5, r4, r5
    ; jn invalid_saved_pc

    ; mov r5, #0x8000
    ; sub r5, r4, r5
    ; jn pc_valid
    jmp pc_valid

invalid_saved_pc:
    ; Saved PC is invalid - don't restore, halt instead
    leab r1, invalid_saved_pc_msg
    call print_string
    jmp sys_exit

pc_valid:
    li r2, #TRAP_INFO_PC
    st [r2], r4         ; Store to TRAP_INFO_PC

    ; 6. Restore Registers R1..R7
    ; Re-calculate PCB Base (At 0x40) to copy to Temp
    ; ld r0, [0x0020]
    li r1, kvar_pid
    ld r0, [r1]

    mov r1, #32
    mul r1, r0, r1
    li r2, proc_table_base
    add r1, r1, r2      ; R1 = PCB Base (Points to R0)

    ; Copy R0..R7 from PCB to 0x0060
    li r2, #USER_REGS_ADDR
    mov r3, #8

copy_regs_loop:
    ld r4, [r1]
    st [r2], r4
    inc r1
    inc r1
    inc r2
    inc r2
    dec r3
    jnz copy_regs_loop

    ; Now restore actual registers from Temp
    ; BUT FIRST: Set process memory bounds while we can still use R0/R1
    ; Base = 0x0900 (user code start)
    ; Limit = 0x2000 (give each process ~6KB)
    li r0, #MMIO_SET_PROC_BASE      ; MMIO_SET_PROC_BASE
    li r1, #0x0900      ; Base address for user processes
    st [r0], r1
    li r0, #MMIO_SET_PROC_LIMIT      ; MMIO_SET_PROC_LIMIT
    li r1, #0x2000      ; Limit address (end of user memory)
    st [r0], r1

    ; NOW restore all registers from trap frame
    li r0, #USER_REGS_ADDR + 2
    ld r1, [r0]
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]
    li r0, #USER_REGS_ADDR + 6
    ld r3, [r0]
    li r0, #USER_REGS_ADDR + 8
    ld r4, [r0]
    li r0, #USER_REGS_ADDR + 10
    ld r5, [r0]
    li r0, #USER_REGS_ADDR + 12
    ld r6, [r0]
    li r0, #USER_REGS_ADDR + 14
    ld r7, [r0]

    ; Finally Restore R0
    li r0, #USER_REGS_ADDR
    ld r0, [r0]

    ; Jump to User PC (via RETK)
    ; retk will drop privilege, at which point the bounds will be enforced
    retk

; ============================================================================
; Init Processes (Load All Kernel Args)
; ============================================================================
init_processes:
    push r7             ; Save return address
    ; Get Arg Count
    li r0, #MMIO_ARG_COUNT
    ld r5, [r0]         ; R5 = Count
    li r1, kvar_proc_count
    st [r1], r5     ; Store num_procs

    ; Loop i from 0 to Count-1
    mov r4, #0          ; R4 = Current Index (replacing R6 usage)
    ; Use memory counter
    li r1, kvar_init_loop
    st [r1], r4     ; 0x002A = temp counter (init 0)

load_loop:
    li r1, kvar_init_loop
    ld r4, [r1]     ; Load index (R4)

    li r1, kvar_proc_count
    ld r5, [r1]     ; Load count

    sub r3, r4, r5      ; index - count (Use R3 temp)
    jz load_done        ; if index == count, done

    ; Setup PCB for Process i
    ; Base = 0x0040 + i*32
    mov r1, #32
    mul r1, r4, r1
    li r2, proc_table_base
    add r1, r1, r2      ; R1 = PCB Base

    ; Initialize all registers to 0 in PCB (R0-R7)
    mov r5, #0
    mov r3, #8          ; 8 registers

init_regs_loop:
    st [r1], r5         ; Store 0
    inc r1
    inc r1              ; Move to next word
    dec r3
    jnz init_regs_loop

    ; R1 now points to offset 16, reset it to PCB base
    mov r1, #32
    mul r1, r4, r1
    li r2, proc_table_base
    add r1, r1, r2      ; R1 = PCB Base

    ; Calculate Backing Addr: 0x2000 + i*0x1000
    mov r2, #0x10       ; 0x10 << 8 = 0x1000
    mov r5, #8          ; Use R5 temp (count re-loaded later)
    shl r2, r2, r5      ; R2 = 0x1000
    mul r2, r2, r4      ; i * 0x1000
    li r3, #0x2000
    add r2, r2, r3      ; R2 = Backing Addr

    ; Store Backing Addr in PCB (Offset 18)
    li r3, #18
    add r3, r1, r3
    st [r3], r2

    ; Store Initial PC (0x0000) in PCB (Offset 16)
    ; Base + 16
    li r3, #16
    add r3, r1, r3
    mov r5, #0
    st [r3], r5

    ; Store Initial SP (0x1900) in PCB (Offset 12)
    ; SP = 0x1900 (Top of user memory)
    li r3, #12
    add r3, r1, r3
    li r5, #0x1900
    st [r3], r5

    ; Store State = 1 (alive) in PCB (Offset 22)
    li r3, #22
    add r3, r1, r3
    li r5, #1
    st [r3], r5

    ; Increment alive process count
    li r3, kvar_alive_count
    ld r5, [r3]
    inc r5
    st [r3], r5

    ; Load Program from File `Arg[i]` into Backing Store
    ; At this point: R1=PCB base, R2=backing addr, R4=loop index
    ; Function expects: R1=arg index, R2=dest addr
    mov r1, r4          ; R1 = Arg Index
    call load_file_to_memory

    ; Increment Index
    li r1, kvar_init_loop
    ld r4, [r1]
    inc r4
    st [r1], r4
    jmp load_loop

load_done:
    pop r7              ; Restore return address
    ret

; ============================================================================
; Load File (Arg Index -> R1, Dest -> R2)
; ============================================================================
load_file_to_memory:
    ; Save R2 (dest address) to fixed memory location instead of stack
    ; NOTE: Use 0x00E0, NOT 0x0090 which conflicts with filename buffer at 0x0080
    li r0, kvar_load_temp      ; Use 0x00E0 as temp storage for dest
    st [r0], r2

    push r7             ; Save return address

    ; ARG_COPY: index=R1, buf=R2, len=R3
    ; We need to set registers corresponding to MMIO protocol.
    ; MMIO_ARG_COPY (0xFF34) reads R1, R2, R3.
    ; But we setup registers FIRST then write to MMIO address?
    ; NO. The VM reads registers WHEN we write to the MMIO address.
    ; wait. `vm.py`: `idx = self.regs[1]`.
    ; So yes, we set R1, R2, R3 then write to 0xFF34.

    mov r1, r1          ; Index (already in R1)
    li r2, kvar_filename_buf      ; Buffer for filename (after trap frame area)
    li r3, #32          ; Max Len (32 bytes for filename)

    li r0, #MMIO_ARG_COPY      ; MMIO Addr
    mov r4, #1
    st [r0], r4         ; Trigger copy

    ; Open File: Path at R1.
    ; We just copied to 0x00C0. So Path is at 0x00C0.
    li r1, kvar_filename_buf
    li r0, #MMIO_FILE_OPEN      ; OPEN
    st [r0], r1         ; Trigger (uses R1 path). Returns Handle in R0 (VM sets R0).

    ; Check Handle (0xFFFF = Fail)
    ; ... (skipping check for brevity, assume success/fail handled by loop termination)
    mov r7, r0          ; Save Handle in R7

    ; Skip executable header (22 bytes)
    ; FILE_SEEK: handle=R1, pos_lo=R2, pos_hi=R3
    mov r1, r7
    li r2, #22          ; Skip 22 bytes
    mov r3, #0          ; High word = 0
    li r0, #MMIO_FILE_SEEK      ; SEEK
    st [r0], r1

    ; Read Content Loop
    ; Restore dest address from fixed memory
    li r0, kvar_load_temp
    ld r5, [r0]         ; R5 = Dest Address

read_loop_1:
    ; Read to R5, Max 256 bytes per chunk
    ; FILE_READ: handle=R1, buf=R2, len=R3
    mov r1, r7          ; Handle
    mov r2, r5          ; Buffer
    li r3, #0x0100      ; Len (256)

    li r4, #MMIO_FILE_READ      ; READ
    st [r4], r1         ; Trigger READ (R0 will contain bytes read)

    ; R0 = Bytes Read
    mov r4, #0
    sub r4, r0, r4
    jz read_finished

    ; Advance ptr
    add r5, r5, r0
    jmp read_loop_1

read_finished:
    ; Close
    li r0, #MMIO_FILE_CLOSE
    mov r1, r7
    st [r0], r1

    pop r7              ; Restore return address
    ret

; ============================================================================
; Syscall dispatcher with full context preservation
; ============================================================================
do_syscall:
    ; VM already saved user R0-R7 to trap frame at 0x0060
    ; We can freely use R0-R7 for kernel operations
    ; Syscall handlers will load args from trap frame and write results there

    ; Load syscall number from saved R1
    li r0, #USER_REGS_ADDR + 2
    ld r1, [r0]

    ; Dispatch using only R0 (safe to clobber)
    mov r0, #0
    sub r0, r1, r0
    jz sys_exit

    mov r0, #1
    sub r0, r1, r0
    jz sys_putchar

    mov r0, #2
    sub r0, r1, r0
    jz sys_getchar

    mov r0, #3
    sub r0, r1, r0
    jz sys_print_int

    mov r0, #4
    sub r0, r1, r0
    jz sys_newline

    mov r0, #5
    sub r0, r1, r0
    jz sys_print_hex

    mov r0, #6
    sub r0, r1, r0
    jz sys_print_str

    mov r0, #7
    sub r0, r1, r0
    jz sys_input_ready

    mov r0, #8
    sub r0, r1, r0
    jz sys_random

    mov r0, #9
    sub r0, r1, r0
    jz sys_timer_lo

    mov r0, #10
    sub r0, r1, r0
    jz sys_timer_hi

    mov r0, #11
    sub r0, r1, r0
    jz sys_flush

    mov r0, #12
    sub r0, r1, r0
    jz sys_clear_screen

    mov r0, #13
    sub r0, r1, r0
    jz sys_screen_flush

    mov r0, #14
    sub r0, r1, r0
    jz sys_screen_putc

    mov r0, #15
    sub r0, r1, r0
    jz sys_screen_setxy

    mov r0, #16
    sub r0, r1, r0
    jz sys_screen_getc

    mov r0, #17
    sub r0, r1, r0
    jz sys_kb_available

    mov r0, #18
    sub r0, r1, r0
    jz sys_kb_read

    mov r0, #19
    sub r0, r1, r0
    jz sys_mouse_getxy

    mov r0, #20
    sub r0, r1, r0
    jz sys_mouse_buttons

    ; Unknown syscall - set R0=-1 in trap frame and return
    li r0, #USER_REGS_ADDR
    mov r1, #0xFFFF
    st [r0], r1
    jmp restore_and_return

; ============================================================================
; Context restoration - restore all registers from trap frame and return to user
; ============================================================================
restore_and_return:
    ; Restore R0-R7 from trap frame at 0x0060 before returning to user mode
    ; Must restore in reverse order to avoid clobbering our working registers

    ; Restore R7 first
    li r0, #USER_REGS_ADDR + 14
    ld r7, [r0]

    ; Restore R6
    li r0, #USER_REGS_ADDR + 12
    ld r6, [r0]

    ; Restore R5
    li r0, #USER_REGS_ADDR + 10
    ld r5, [r0]

    ; Restore R4
    li r0, #USER_REGS_ADDR + 8
    ld r4, [r0]

    ; Restore R3
    li r0, #USER_REGS_ADDR + 6
    ld r3, [r0]

    ; Restore R2
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]

    ; Restore R1
    li r0, #USER_REGS_ADDR + 2
    ld r1, [r0]

    ; Restore R0 last (it's been our working register)
    li r0, #USER_REGS_ADDR
    ld r0, [r0]

    ; Now all registers are restored, return to user mode
    retk

; ----------------------------------------------------------------------------
; Syscall implementations
; ----------------------------------------------------------------------------

sys_exit:
    ; Terminates CURRENT Process
    ; Mark process as dead and switch to next alive process

    ; Get current PID
    li r0, kvar_pid
    ld r1, [r0]         ; R1 = current_pid

    ; Calculate PCB address (0x0040 + pid*32)
    mov r2, #32
    mul r2, r1, r2
    li r3, proc_table_base
    add r2, r2, r3      ; R2 = PCB base

    ; Set state to 0 (dead) at offset +22
    li r3, #22
    add r3, r2, r3      ; R3 = address of state field
    mov r4, #0
    st [r3], r4         ; Mark as dead

    ; Decrement alive process count
    li r0, kvar_alive_count
    ld r1, [r0]
    dec r1
    st [r0], r1

    ; Switch to next process (scheduler will skip dead ones)
    jmp scheduler

sys_putchar:
    ; Load arg from trap frame: R2=char
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]
    li r0, #MMIO_PRINT_CHAR
    st [r0], r2
    ; Write 0 to trap frame R0
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_getchar:
    li r0, #MMIO_INPUT_CHAR
    mov r1, #0
    st [r0], r1         ; Trigger read
    ld r1, [r0]         ; Read result
    ; Write result to trap frame R0
    li r0, #USER_REGS_ADDR
    st [r0], r1
    jmp restore_and_return

sys_print_int:
    ; Load arg from trap frame: R2=value
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]
    li r0, #MMIO_PRINT_INT
    st [r0], r2
    ; Write 0 to trap frame R0
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_newline:
    li r0, #MMIO_NEWLINE
    st [r0], r1 ; data ignored
    ; Write 0 to trap frame R0
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_print_hex:
    ; Load arg from trap frame: R2=value
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]
    li r0, #MMIO_PRINT_HEX
    st [r0], r2
    ; Write 0 to trap frame R0
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_print_str:
    ; Load arg from trap frame: R2=string address
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]

    ; Translate to Physical Address (Active User Base = 0x0900)
    li r1, #0x0900
    add r2, r2, r1

    ; MMIO_PRINT_STR reads from R1.
    mov r1, r2
    li r0, #MMIO_PRINT_STR
    st [r0], r1 ; Trigger
    ; Write 0 to trap frame R0
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_input_ready:
    li r1, #MMIO_INPUT_READY
    ld r1, [r1]
    ; Write result to trap frame R0
    li r0, #USER_REGS_ADDR
    st [r0], r1
    jmp restore_and_return

sys_random:
    li r1, #MMIO_RANDOM
    ld r1, [r1]
    ; Write result to trap frame R0
    li r0, #USER_REGS_ADDR
    st [r0], r1
    jmp restore_and_return

sys_timer_lo:
    li r1, #MMIO_TIMER_LO
    ld r1, [r1]
    ; Write result to trap frame R0
    li r0, #USER_REGS_ADDR
    st [r0], r1
    jmp restore_and_return

sys_timer_hi:
    li r1, #MMIO_TIMER_HI
    ld r1, [r1]
    ; Write result to trap frame R0
    li r0, #USER_REGS_ADDR
    st [r0], r1
    jmp restore_and_return

sys_flush:
    li r0, #MMIO_FLUSH
    st [r0], r1
    ; Write 0 to trap frame R0
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_clear_screen:
    li r0, #MMIO_SCREEN_CLEAR
    st [r0], r1
    ; Write 0 to trap frame R0
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_screen_flush:
    li r0, #MMIO_SCREEN_FLUSH      ; MMIO_SCREEN_FLUSH
    st [r0], r1
    ; Write 0 to trap frame R0
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_screen_putc:
    ; Load args from trap frame: R2=char, R3=x, R4=y, R5=color
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]
    li r0, #USER_REGS_ADDR + 6
    ld r3, [r0]
    li r0, #USER_REGS_ADDR + 8
    ld r4, [r0]
    li r0, #USER_REGS_ADDR + 10
    ld r5, [r0]

    ; Set cursor position
    mov r1, r3          ; R1 = x
    mov r2, r4          ; R2 = y
    li r0, #MMIO_SCREEN_SETXY
    st [r0], r1

    ; Reload char (R2 was clobbered)
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]

    ; Put character
    mov r1, r2          ; R1 = char
    mov r2, r5          ; R2 = color
    li r0, #MMIO_SCREEN_PUTC
    st [r0], r1

    ; Write 0 to trap frame R0 as return value
    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_screen_setxy:
    ; Load args from trap frame: R2=x, R3=y
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]
    li r0, #USER_REGS_ADDR + 6
    ld r3, [r0]

    mov r1, r2
    mov r2, r3
    li r0, #MMIO_SCREEN_SETXY
    st [r0], r1

    li r0, #USER_REGS_ADDR
    mov r1, #0
    st [r0], r1
    jmp restore_and_return

sys_screen_getc:
    ; Load args from trap frame: R2=x, R3=y
    li r0, #USER_REGS_ADDR + 4
    ld r2, [r0]
    li r0, #USER_REGS_ADDR + 6
    ld r3, [r0]

    mov r1, r2
    mov r2, r3
    li r0, #MMIO_SCREEN_GETC
    ld r0, [r0]

    ; Write result to trap frame R0
    li r1, #USER_REGS_ADDR
    st [r1], r0
    jmp restore_and_return

sys_kb_available:
    li r0, #MMIO_KB_AVAILABLE
    ld r1, [r0]
    ; Write result to trap frame R0
    li r0, #USER_REGS_ADDR
    st [r0], r1
    jmp restore_and_return

sys_kb_read:
    li r0, #MMIO_KB_READ
    ld r1, [r0]
    ; Write result to trap frame R0
    li r0, #USER_REGS_ADDR
    st [r0], r1
    jmp restore_and_return

sys_mouse_getxy:
    li r0, #MMIO_MOUSE_X
    ld r1, [r0]         ; R1 = x
    li r0, #MMIO_MOUSE_Y
    ld r2, [r0]         ; R2 = y
    ; Write x to trap frame R0, y to trap frame R1
    li r0, #USER_REGS_ADDR
    st [r0], r1
    li r0, #USER_REGS_ADDR + 2
    st [r0], r2
    jmp restore_and_return

sys_mouse_buttons:
    li r0, #MMIO_MOUSE_BUTTONS
    ld r1, [r0]
    ; Write result to trap frame R0
    li r0, #USER_REGS_ADDR
    st [r0], r1
    jmp restore_and_return

; ============================================================================
; Helper Functions
; ============================================================================
print_string:
    ; Print null-terminated string at address in R1
    ; Preserves all registers
    li r0, #MMIO_PRINT_STR      ; MMIO_PRINT_STR
    st [r0], r1
    ret

; ============================================================================
; Data Section - Placed after code
; ============================================================================

boot_msg:
    .string "Fr Kernel 1B\n"

no_prog_msg:
    .string "No user program(s) specified\n"

mem_violation_msg:
    .string "Segmentation Fault\n"

mmio_violation_msg:
    .string "Segmentation Fault\n"

load_fail_msg:
    .string "Kernel Panic: Load Failed\n"

invalid_saved_pc_msg:
    .string "Trap Return: Invalid PC\n"

; ============================================================================
; Kernel Variables & Data Structures
; ============================================================================
kvar_booted:        .word 0     ; 0x0018
kvar_prog_loaded:   .word 0     ; 0x001A
kvar_pid:           .word 0     ; 0x0020
kvar_proc_count:    .word 0     ; 0x0022
kvar_alive_count:   .word 0     ; 0x0024
kvar_init_loop:     .word 0     ; 0x0026
kvar_load_temp:     .word 0     ; 0x0028

; Filename buffer (old 0x0080) - Size 128 bytes
kvar_filename_buf:
    .space 128

; Process Table
proc_table_base:
    .space 512   ; 16 processes * 32 bytes

