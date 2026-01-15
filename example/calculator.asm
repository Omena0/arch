
; 16-bit calculator - same as before (64-bit is too complex for this VM)
main:
    li r6, #0x1800
    
    ; Read input
    leab r3, buffer
read_loop:
    call getc
    mov r1, #10
    sub r1, r0, r1
    jz done_reading
    st [r3], r0
    inc r3
    jmp read_loop
done_reading:
    mov r0, #0
    st [r3], r0
    
    ; Parse expression
    leab r3, buffer
    call parse_expr
    
    ; Print result
    mov r2, r0
    call print_int
    call newline
    call exit0

; Parse expr = term (('+' | '-') term)*
parse_expr:
    push r7
    push r1
    push r2
    push r4
    
    call parse_term
    mov r4, r0
    
expr_loop:
    ld r0, [r3]
    mov r1, #255
    and r0, r0, r1
    
    mov r1, #'+'
    sub r1, r0, r1
    jz expr_add
    
    mov r1, #'-'
    sub r1, r0, r1
    jz expr_sub
    
    jmp expr_done
    
expr_add:
    inc r3
    push r4
    call parse_term
    pop r4
    add r4, r4, r0
    jmp expr_loop
    
expr_sub:
    inc r3
    push r4
    call parse_term
    pop r4
    sub r4, r4, r0
    jmp expr_loop
    
expr_done:
    mov r0, r4
    pop r4
    pop r2
    pop r1
    pop r7
    ret

; Parse term = factor (('*' | '/') factor)*
parse_term:
    push r7
    push r1
    push r2
    push r4
    
    call parse_factor
    mov r4, r0
    
term_loop:
    ld r0, [r3]
    mov r1, #255
    and r0, r0, r1
    
    mov r1, #'*'
    sub r1, r0, r1
    jz check_power
    
    mov r1, #'/'
    sub r1, r0, r1
    jz term_div
    
    jmp term_done

check_power:
    inc r3
    ld r0, [r3]
    dec r3
    mov r1, #255
    and r0, r0, r1
    mov r1, #'*'
    sub r1, r0, r1
    jz term_done
    
    inc r3
    push r4
    call parse_factor
    pop r4
    mul r4, r4, r0
    jmp term_loop
    
term_div:
    inc r3
    push r4
    call parse_factor
    pop r4
    div r4, r4, r0
    jmp term_loop
    
term_done:
    mov r0, r4
    pop r4
    pop r2
    pop r1
    pop r7
    ret

; Parse factor = power ('**' power)*
parse_factor:
    push r7
    push r1
    push r2
    push r4
    
    call parse_power
    mov r4, r0
    
factor_loop:
    ld r0, [r3]
    mov r1, #255
    and r0, r0, r1
    
    mov r1, #'*'
    sub r1, r0, r1
    jnz factor_done
    
    inc r3
    ld r0, [r3]
    mov r1, #255
    and r0, r0, r1
    mov r1, #'*'
    sub r1, r0, r1
    jnz not_power
    
    inc r3
    push r4
    call parse_power
    pop r4
    
    ; Compute r4 ** r0
    push r3
    mov r1, r4
    mov r2, r0
    call power_func
    mov r4, r0
    pop r3
    jmp factor_loop
    
not_power:
    dec r3
    jmp factor_done
    
factor_done:
    mov r0, r4
    pop r4
    pop r2
    pop r1
    pop r7
    ret

; Parse power = number | '(' expr ')'
parse_power:
    push r7
    push r1
    push r2
    
    ld r0, [r3]
    mov r1, #255
    and r0, r0, r1
    
    mov r1, #'('
    sub r1, r0, r1
    jz parse_paren
    
    ; Parse number
    mov r1, #0
    
num_loop:
    ld r0, [r3]
    mov r2, #255
    and r0, r0, r2
    
    mov r2, #'0'
    sub r0, r0, r2
    jn num_done
    
    mov r2, #9
    sub r2, r2, r0
    jn num_done
    
    mov r2, #10
    mul r1, r1, r2
    add r1, r1, r0
    inc r3
    jmp num_loop
    
num_done:
    mov r0, r1
    pop r2
    pop r1
    pop r7
    ret

parse_paren:
    inc r3
    call parse_expr
    push r0
    
    ld r0, [r3]
    mov r1, #255
    and r0, r0, r1
    mov r1, #')'
    sub r1, r0, r1
    jz close_paren
close_paren:
    inc r3
    pop r0
    pop r2
    pop r1
    pop r7
    ret

; Helper: compute R1 ** R2 (16-bit only)
power_func:
    push r7
    push r1
    push r2
    push r3
    
    mov r3, #1
    
    mov r0, #0
    sub r0, r2, r0
    jz power_done_one
    
power_loop:
    mov r0, #0
    sub r0, r2, r0
    jz power_done
    
    mul r3, r3, r1
    dec r2
    jmp power_loop
    
power_done_one:
    mov r0, #1
    pop r3
    pop r2
    pop r1
    pop r7
    ret
    
power_done:
    mov r0, r3
    pop r3
    pop r2
    pop r1
    pop r7
    ret

.include "stdlib.asm"

buffer: .space 128
