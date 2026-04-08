
#include "stdlib.asm"

; Decimal calculator using 32-bit fixed-point numbers.
; Representation: value * 10000 (4 decimal places).

#define SCALE 10000
#define SCALE_D1 1000
#define SCALE_D2 100
#define SCALE_D3 10

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
    call print_scaled
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
    
term_mul:
    inc r3
    push r4
    call parse_factor
    pop r4

    ; (a * b) / SCALE using decomposition to reduce overflow:
    ; a = q*SCALE + rem
    ; result = q*b + (rem*b)/SCALE
    li r1, #SCALE
    div r2, r4, r1      ; q
    mul r1, r2, r1
    sub r1, r4, r1      ; rem

    mul r4, r2, r0      ; q*b
    mul r2, r1, r0      ; rem*b
    li r1, #SCALE
    div r2, r2, r1
    add r4, r4, r2
    jmp term_loop
    
term_div:
    inc r3
    push r4
    call parse_factor
    pop r4

    mov r1, #0
    sub r1, r0, r1
    jz term_div_zero

    ; (a * SCALE) / b using decomposition to reduce overflow:
    ; a = q*b + rem
    ; result = q*SCALE + (rem*SCALE)/b
    div r2, r4, r0
    mul r1, r2, r0
    sub r1, r4, r1      ; rem

    li r4, #SCALE
    mul r2, r2, r4
    mul r1, r1, r4
    div r1, r1, r0
    add r4, r2, r1
    jmp term_loop

term_div_zero:
    mov r4, #0
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
; Number supports optional fractional part (e.g., 12.34).
parse_power:
    push r7
    push r1
    push r2
    push r4
    push r5
    
    ld r0, [r3]
    mov r1, #255
    and r0, r0, r1
    
    mov r1, #'('
    sub r1, r0, r1
    jz parse_paren
    
    ; Parse integer part
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
    ; Scale integer part
    li r2, #SCALE
    mul r1, r1, r2

    ; Optional fractional part
    ld r0, [r3]
    mov r2, #255
    and r0, r0, r2
    mov r2, #'.'
    sub r2, r0, r2
    jnz power_num_done

    inc r3
    li r4, #SCALE_D1

frac_loop:
    mov r0, #0
    sub r0, r4, r0
    jz power_num_done

    ld r0, [r3]
    mov r2, #255
    and r0, r0, r2

    mov r2, #'0'
    sub r0, r0, r2
    jn power_num_done

    mov r2, #9
    sub r2, r2, r0
    jn power_num_done

    mul r5, r0, r4
    add r1, r1, r5

    mov r5, #10
    div r4, r4, r5
    inc r3
    jmp frac_loop

power_num_done:
    mov r0, r1
    pop r5
    pop r4
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
    pop r5
    pop r4
    pop r2
    pop r1
    pop r7
    ret

; Helper: compute R1 ** R2 where both are fixed-point.
; Exponent uses integer part only.
power_func:
    push r7
    push r1
    push r2
    push r3
    push r4
    push r5
    
    li r4, #SCALE
    div r2, r2, r4      ; exponent integer part
    mov r3, r4          ; result = 1.0
    
    mov r0, #0
    sub r0, r2, r0
    jz power_done
    
power_loop:
    mov r0, #0
    sub r0, r2, r0
    jz power_done

    ; result = (result * base) / SCALE using decomposition:
    ; result = q*SCALE + rem
    ; (result*base)/SCALE = q*base + (rem*base)/SCALE
    div r5, r3, r4      ; q
    mul r0, r5, r4
    sub r0, r3, r0      ; rem

    mul r3, r5, r1      ; q*base
    mul r5, r0, r1      ; rem*base
    div r5, r5, r4
    add r3, r3, r5

    dec r2
    jmp power_loop

power_done:
    mov r0, r3
    pop r5
    pop r4
    pop r3
    pop r2
    pop r1
    pop r7
    ret

; Print fixed-point number in R2.
; Prints integer part only when fraction is 0.
print_scaled:
    push r7
    push r0
    push r1
    push r3
    push r4
    push r5

    mov r3, r2

    mov r0, #0
    sub r0, r3, r0
    jn scaled_negative
    jmp scaled_abs_ready

scaled_negative:
    mov r2, #'-'
    mov r1, #1
    syscall
    mov r0, #0
    sub r3, r0, r3

scaled_abs_ready:
    li r4, #SCALE
    div r1, r3, r4
    mov r2, r1
    mov r1, #3
    syscall

    li r4, #SCALE
    mul r1, r2, r4
    sub r4, r3, r1      ; fraction

    mov r0, #0
    sub r0, r4, r0
    jz scaled_done

    ; Keep only significant fractional places (up to 4),
    ; but preserve leading zeros when printing (e.g., 0.01).
    mov r0, r4          ; temp fraction
    mov r5, #4          ; digits to print

frac_trim_loop:
    mov r1, #1
    sub r1, r5, r1
    jz frac_trim_done   ; keep at least one digit

    mov r1, #10
    div r2, r0, r1      ; q = temp / 10
    mul r3, r2, r1
    sub r3, r0, r3      ; rem = temp - q*10

    mov r1, #0
    sub r1, r3, r1
    jnz frac_trim_done  ; stop when last digit is non-zero

    mov r0, r2          ; temp = q
    dec r5
    jmp frac_trim_loop

frac_trim_done:
    mov r2, #'.'
    mov r1, #1
    syscall

    mov r3, r4          ; remainder
    li r0, #SCALE_D1    ; divisor starts at 1000

frac_print_loop:
    div r2, r3, r0      ; digit = remainder / divisor
    mul r1, r2, r0
    sub r3, r3, r1      ; remainder -= digit * divisor

    push r0
    mov r1, #'0'
    add r2, r1, r2
    mov r1, #1
    syscall
    pop r0

    dec r5
    mov r1, #0
    sub r1, r5, r1
    jz scaled_done

    mov r1, #10
    div r0, r0, r1      ; next divisor
    jmp frac_print_loop

scaled_done:
    pop r5
    pop r4
    pop r3
    pop r1
    pop r0
    pop r7
    ret

buffer: .space 128
