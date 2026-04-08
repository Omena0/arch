; Kernel Boot and Dispatcher
; Entry point for all traps and syscalls

; .base, .entry, .kernel directives are in the main kernel.asm file

; ============================================================================
; KERNEL ENTRY POINT - Called on every trap and syscall
; ============================================================================

kernel_boot:
    ; VM already saved 32-bit registers at 4-byte intervals (0x0060, 0x0064, 0x0068, ...)
    ; Kernel memory layout:
    ;   0x0020-0x003F: Kernel variables
    ;   0x0040-0x005F: Trap info (cause, addr, PC, value - 16-bit each)
    ;   0x0060-0x007F: Saved user registers (32-bit each, 4-byte intervals)
    ;   0x0080+: Kernel code and data
    
    jmp kernel_dispatcher

; ============================================================================
; KERNEL DISPATCHER - Routes to init or syscall handler
; ============================================================================

kernel_dispatcher:
    ; Check if kernel is initialized
    li r0, #kvar_booted
    ld r5, [r0]
    mov r4, #0
    sub r4, r5, r4
    jz kernel_init

    ; Check trap cause
    li r0, #TRAP_CAUSE
    ld r5, [r0]
    
    ; Check for TRAP_SYSCALL (0x0007) - syscall via MMIO
    mov r4, #TRAP_SYSCALL
    sub r4, r5, r4
    jz do_syscall

    ; Check for TRAP_MMIO_WRITE (0x0002) - unprivileged MMIO access (other than syscalls)
    mov r4, #TRAP_MMIO_WRITE
    sub r4, r5, r4
    jz handle_trap

    ; Check for TRAP_MMIO_READ (0x0001)
    mov r4, #TRAP_MMIO_READ
    sub r4, r5, r4
    jz handle_trap

    ; Check for TRAP_TIMER (0x0005)
    mov r4, #TRAP_TIMER
    sub r4, r5, r4
    jz scheduler_entry

    ; Handle other VM traps or unknown - just return to user
    jmp restore_user_context

scheduler_entry:
    ; Clear trap cause
    li r0, #TRAP_CAUSE
    mov r5, #0
    st [r0], r5
    jmp scheduler

handle_trap:
    ; Kernel trap - for now just return to user
    jmp restore_user_context

; ============================================================================
; LOAD USER PROGRAM FROM FILE
; ============================================================================

load_user_program:
    ; Check if we have arguments
    li r0, #MMIO_ARG_COUNT
    ld r1, [r0]             ; R1 = arg count
    mov r0, #0
    sub r0, r1, r0
    jz lup_done              ; No arguments, skip file loading

    ; Copy the filename (first argument) to buffer
    mov r1, #0              ; Argument index 0
    li r2, #kvar_filename_buf  ; Destination buffer
    mov r3, #32             ; Max length
    li r0, #MMIO_ARG_COPY
    st [r0], r3             ; Trigger copy with maxlen, reads R1,R2,R3
    
    ; Open the file
    li r0, #kvar_filename_buf  ; Filename address in R1
    mov r1, r0
    li r0, #MMIO_FILE_OPEN
    st [r0], r1             ; Write to FILE_OPEN, handle returned in R0
    
    ; Check if file open succeeded (R0 != 0xFFFF)
    li r2, #0xFFFF
    sub r2, r0, r2
    jz lup_done              ; If error, skip file loading
    
    ; R1 = file handle for FILE_READ/CLOSE
    mov r1, r0
    
    ; Read file into memory at 0x4000 (user code absolute address)
    ; When in USER mode with process_mem_base=0x4000, PC=0x0000 reads from 0x0000+0x4000=0x4000
    li r2, #0x4000          ; R2 = destination address (absolute 0x4000)
    li r3, #0xC000          ; R3 = max read size (49KB to 0xFFFF)
    ; FILE_READ uses R1=handle, R2=buffer, R3=len and returns bytes in R0
    li r0, #MMIO_FILE_READ
    st [r0], r3             ; Trigger read
    
    ; Close the file (R1 still has handle)
    li r0, #MMIO_FILE_CLOSE
    st [r0], r1             ; Close file
    
lup_done:
    ret

; ============================================================================
; KERNEL INITIALIZATION - Called once on first trap
; ============================================================================

kernel_init:
    ; Load user program from file (if provided as argument)
    call load_user_program
    
    ; Mark as initialized
    li r0, #kvar_booted
    li r1, #1
    st [r0], r1

    ; Clear trap cause
    li r0, #TRAP_CAUSE
    li r1, #0
    st [r0], r1

    ; Initialize process count
    li r0, #kvar_proc_count
    li r1, #1
    st [r0], r1

    ; Initialize PID 0
    li r0, #kvar_pid
    li r1, #0
    st [r0], r1

    ; Initialize alive count
    li r0, #kvar_alive_count
    li r1, #1
    st [r0], r1

    ; Setup memory bounds for process 0
    li r0, #MMIO_SET_PROC_BASE
    li r1, #0x4000
    st [r0], r1
    li r0, #MMIO_SET_PROC_LIMIT
    li r1, #0xFFFF
    st [r0], r1

    ; Enable timer
    li r0, #MMIO_TIMER_INTERVAL
    li r1, #0
    st [r0], r1

    ; Jump to user space (entry at 0x0000, which with process_mem_base=0x4000 reads from absolute 0x4000)
    li r0, #TRAP_PC
    li r1, #0x0000
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; RESTORE USER CONTEXT - Return to user process
; ============================================================================

restore_user_context:
    ; Restore R0-R7 from trap frame (0x0060-0x007F) at 4-byte intervals
    ; Restore in reverse order like a typical pop sequence
    li r0, #0x007C
    ld r7, [r0]
    li r0, #0x0078
    ld r6, [r0]
    li r0, #0x0074
    ld r5, [r0]
    li r0, #0x0070
    ld r4, [r0]
    li r0, #0x006C
    ld r3, [r0]
    li r0, #0x0068
    ld r2, [r0]
    li r0, #0x0064
    ld r1, [r0]
    li r0, #0x0060
    ld r0, [r0]

    retk
