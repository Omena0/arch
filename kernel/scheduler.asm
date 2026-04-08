; Scheduler and Process Management

; ============================================================================
; SCHEDULER - Round-robin process scheduler
; ============================================================================

scheduler:
    ; Get current PID for context save
    li r1, #kvar_pid
    ld r0, [r1]

    ; Save context of current process
    call save_context

    ; Pick next process
    call pick_next_process

    ; Restore context
    jmp restore_context

; ============================================================================
; SAVE CONTEXT - Current process to PCB
; Input: None (uses current_pid and trap frame)
; ============================================================================

save_context:
    ; Get PID
    li r1, #kvar_pid
    ld r0, [r1]

    ; Calculate PCB address = 0x0200 + (pid * 32)
    mov r1, #32
    mul r1, r0, r1
    li r2, #proc_table_base
    add r1, r1, r2

    ; Copy registers from trap frame (0x0060) to PCB (offset 0)
    li r2, #USER_REGS_ADDR
    mov r3, #8

save_regs_loop:
    ld r4, [r2]
    st [r1], r4
    inc r2
    inc r2
    inc r2
    inc r2      ; Increment r2 by 4 for next 32-bit register
    inc r1
    inc r1
    inc r1
    inc r1      ; Increment r1 by 4 for next PCB register slot
    dec r3
    jnz save_regs_loop

    ; Save PC from trap frame (TRAP_PC = 0x0014)
    li r2, #TRAP_PC
    ld r4, [r2]
    st [r1], r4

    ret

; ============================================================================
; PICK NEXT PROCESS - Round robin scheduler
; ============================================================================

pick_next_process:
    ; Get current PID
    li r1, #kvar_pid
    ld r0, [r1]

    ; Get process count
    li r1, #kvar_proc_count
    ld r4, [r1]

    ; Move to next PID
    inc r0
    mov r2, #0
    sub r2, r0, r4
    jz pick_wrap

    jmp pick_set

pick_wrap:
    mov r0, #0

pick_set:
    ; Set as current PID
    li r1, #kvar_pid
    st [r1], r0

    ret

; ============================================================================
; RESTORE CONTEXT - Copy PCB back to registers and trap frame
; Input: kvar_pid set to target process
; ============================================================================

restore_context:
    ; Get target PID
    li r1, #kvar_pid
    ld r0, [r1]

    ; Calculate PCB address
    mov r1, #32
    mul r1, r0, r1
    li r2, #proc_table_base
    add r1, r1, r2

    ; Load registers from PCB to trap frame
    li r2, #USER_REGS_ADDR
    mov r3, #8

restore_regs_loop:
    ld r4, [r1]
    st [r2], r4
    inc r1
    inc r1
    inc r1
    inc r1      ; Increment r1 by 4 for next PCB register slot
    inc r2
    inc r2
    inc r2
    inc r2      ; Increment r2 by 4 for next register save location
    dec r3
    jnz restore_regs_loop

    ; Load PC from PCB to trap frame
    ld r4, [r1]
    li r2, #TRAP_PC
    st [r2], r4

    ; Setup memory bounds
    li r0, #MMIO_SET_PROC_BASE
    li r1, #0x4000
    st [r0], r1
    li r0, #MMIO_SET_PROC_LIMIT
    li r1, #0xFFFF
    st [r0], r1

    jmp restore_user_context
