; Syscall Implementations

; ============================================================================
; SYSCALL DISPATCHER
; ============================================================================

do_syscall:
    ; For MMIO-based syscalls, advance PC past the syscall instruction
    ; TRAP_PC already points to the MMIO write, need to add 4 (one micro-op)
    li r0, #TRAP_PC
    ld r1, [r0]
    li r2, #4
    add r1, r1, r2
    st [r0], r1
    
    ; Load syscall number from saved R1 in trap frame
    li r0, #USER_R1_ADDR
    ld r1, [r0]

    ; Dispatch
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
    jz sys_time_lo

    mov r0, #5
    sub r0, r1, r0
    jz sys_time_hi

    mov r0, #6
    sub r0, r1, r0
    jz sys_random

    mov r0, #7
    sub r0, r1, r0
    jz sys_fork

    mov r0, #8
    sub r0, r1, r0
    jz sys_wait

    mov r0, #9
    sub r0, r1, r0
    jz sys_newline

    mov r0, #10
    sub r0, r1, r0
    jz sys_print_hex

    mov r0, #11
    sub r0, r1, r0
    jz sys_print_str

    mov r0, #12
    sub r0, r1, r0
    jz sys_yield

    ; Default: return -1
    li r0, #USER_R0_ADDR
    li r1, #0xFFFF
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_EXIT(code) - Terminate current process
; ============================================================================

sys_exit:
    ; Get exit code from R2
    li r0, #USER_R2_ADDR
    ld r1, [r0]

    ; Exit via MMIO
    li r0, #MMIO_EXIT
    st [r0], r1

    halt

; ============================================================================
; SYS_PUTCHAR(ch) - Write character
; ============================================================================

sys_putchar:
    ; Get char from R2
    li r0, #USER_R2_ADDR
    ld r2, [r0]

    ; Write to MMIO
    li r0, #MMIO_PRINT_CHAR
    st [r0], r2

    ; Return 0 in R0
    li r0, #USER_R0_ADDR
    li r1, #0
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_GETCHAR() - Read character
; ============================================================================

sys_getchar:
    ; Read from MMIO
    li r0, #MMIO_INPUT_CHAR
    li r1, #0
    st [r0], r1
    ld r1, [r0]

    ; Store in R0
    li r0, #USER_R0_ADDR
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_PRINT_INT(value) - Print integer
; ============================================================================

sys_print_int:
    ; Get value from R2
    li r0, #USER_R2_ADDR
    ld r2, [r0]

    ; Write to MMIO
    li r0, #MMIO_PRINT_INT
    st [r0], r2

    ; Return 0
    li r0, #USER_R0_ADDR
    li r1, #0
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_TIME_LO() - Get timer low word
; ============================================================================

sys_time_lo:
    li r0, #MMIO_TIMER_LO
    ld r1, [r0]

    li r0, #USER_R0_ADDR
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_TIME_HI() - Get timer high word
; ============================================================================

sys_time_hi:
    li r0, #MMIO_TIMER_HI
    ld r1, [r0]

    li r0, #USER_R0_ADDR
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_RANDOM() - Get random value
; ============================================================================

sys_random:
    li r0, #MMIO_RANDOM
    ld r1, [r0]

    li r0, #USER_R0_ADDR
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_NEWLINE() - Print newline
; ============================================================================

sys_newline:
    li r0, #MMIO_NEWLINE
    li r1, #0
    st [r0], r1

    ; Return 0
    li r0, #USER_R0_ADDR
    li r1, #0
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_PRINT_HEX(value) - Print hex value
; ============================================================================

sys_print_hex:
    ; Get value from R2
    li r0, #USER_R2_ADDR
    ld r2, [r0]

    ; Write to MMIO
    li r0, #MMIO_PRINT_HEX
    st [r0], r2

    ; Return 0
    li r0, #USER_R0_ADDR
    li r1, #0
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_PRINT_STR(addr) - Print string
; ============================================================================

sys_print_str:
    ; Get address from R2
    li r0, #USER_R2_ADDR
    ld r2, [r0]

    ; Write to MMIO
    li r0, #MMIO_PRINT_STR
    st [r0], r2

    ; Return 0
    li r0, #USER_R0_ADDR
    li r1, #0
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_YIELD() - Yield to scheduler
; ============================================================================

sys_yield:
    ; Save current context
    call save_context

    ; Clear trap cause
    li r0, #TRAP_CAUSE
    li r1, #0
    st [r0], r1

    ; Pick next process
    call pick_next_process

    ; Restore next process
    jmp restore_context

; ============================================================================
; ============================================================================
; SYS_FORK() - Create child process
; ============================================================================

sys_fork:
    ; Get current process count
    li r0, #kvar_proc_count
    ld r1, [r0]

    ; Check if we can add more processes (max MAX_PROCESSES)
    li r2, #MAX_PROCESSES
    sub r3, r1, r2
    jz fork_fail

    ; New PID = current count
    mov r3, r1

    ; Increment process count
    inc r1
    st [r0], r1

    ; Get current PID for copying context
    li r0, #kvar_pid
    ld r4, [r0]

    ; Calculate parent PCB address
    mov r0, #PCB_SIZE
    mul r0, r4, r0
    li r1, #proc_table_base
    add r0, r0, r1

    ; Calculate child PCB address
    mov r1, #PCB_SIZE
    mul r1, r3, r1
    li r2, #proc_table_base
    add r1, r1, r2

    ; Copy parent context to child (copy 9 words = 8 regs + PC)
    mov r4, #9
fork_copy_loop:
    ld r5, [r0]
    st [r1], r5
    inc r0
    inc r0
    inc r1
    inc r1
    dec r4
    jnz fork_copy_loop

    ; Return child PID in R0
    li r0, #USER_REGS_ADDR
    st [r0], r3

    jmp restore_user_context

fork_fail:
    li r0, #USER_REGS_ADDR
    li r1, #0xFFFF
    st [r0], r1

    jmp restore_user_context

; ============================================================================
; SYS_WAIT(pid) - Wait for child process
; ============================================================================

sys_wait:
    ; For now, just yield to allow child to run
    ; In a more complete implementation, this would:
    ; 1. Check if child exists
    ; 2. Block until child exits
    ; 3. Return child status

    call save_context
    call pick_next_process
    jmp restore_context
