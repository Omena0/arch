; Fr Standard Library
; ========================
; Common functions for user programs
;
; Include with: .include "stdlib.asm"
;
; Calling Convention:
;   R0-R3: Arguments and return values
;   R4-R5: Caller-saved temporaries (CLOBBERED by all jumps/calls!)
;   R6:    Stack pointer
;   R7:    Link register (return address)
;
; WARNING: R4 and R5 are used internally by 16-bit jump/call instructions.
; Any jmp, jz, jnz, jn, or call will clobber R4 and R5!
; Functions should avoid storing important values in R4/R5 across jumps.
;
; Loading string addresses:
;   Use 'leab' (load effective address - byte) for data labels like strings.
;   Example: leab r2, my_string
;
; Syscall Numbers:
;   0 = exit(code)          - R2 = exit code
;   1 = putchar(char)       - R2 = character
;   2 = getchar()           - R0 = character
;   3 = print_int(val)      - R2 = value (decimal)
;   4 = newline()           - Print newline
;   5 = print_hex(val)      - R2 = value (hex)
;   6 = print_str(addr)     - R2 = string address
;   7 = input_ready()       - R0 = 1 if input ready
;   8 = random()            - R0 = random value
;   9 = timer_lo()          - R0 = timer low word
;  10 = timer_hi()          - R0 = timer high word
;  11 = flush()             - Flush stdout
;  12 = clear_screen()      - Clear screen
;  13 = screen_flush()      - Update screen display
;  14 = screen_putc()       - R2=char, R3=x, R4=y, R5=color
;  15 = screen_setxy()      - R2=x, R3=y
;  16 = screen_getc()       - R2=x, R3=y -> R0=char|color
;  17 = kb_available()      - R0 = 1 if key ready
;  18 = kb_read()           - R0 = key event
;  19 = mouse_getxy()       - R0=x, R1=y
;  20 = mouse_buttons()     - R0 = button state

; ============================================================================
; I/O Functions
; ============================================================================
; putc - Print a single character
; Input: R2 = character to print
; Clobbers: R1
putc:
    push r7
    mov r1, #1
    syscall
    pop r7
    ret

; puts - Print a null-terminated string
; Input: R2 = pointer to string (byte address from leab)
; Clobbers: R0, R1, R3
; Note: Uses R3 for string pointer (R4/R5 clobbered by jumps)
puts:
    push r7
    mov r3, r2              ; Save string pointer in R3
puts_loop:
    mov r0, r3              ; Load address
    ld r2, [r0]             ; Load word (contains 2 bytes, we want low byte)
    ; Mask to low byte using XOR trick: value & 0xFF
    ; Since we don't have a good AND with immediate, use shift right then left to clear high byte
    ; Actually, let's just use immediate 0xFF in R1 and AND
    ; Wait, we need R1 for the syscall... let's be careful
    ; R0 = string address (needed for ld)
    ; R1 = syscall number (will set before syscall)
    ; R2 = value loaded
    ; R3 = string pointer (loop counter)
    ; Just check if R2 == 0 by subtracting 0
    mov r1, #0
    sub r1, r2, r1          ; R1 = R2 - 0 = R2, but actually check if R2 is 0
    ; To get just low byte and test if zero:
    ; Shift R2 left by 8, then right by 8 to clear high byte
    mov r0, #8
    shl r2, r2, r0          ; R2 = R2 << 8 (discard high byte)
    shr r2, r2, r0          ; R2 = R2 >> 8 (now only low byte)
    ; Now test if R2 is zero
    mov r1, #0
    sub r1, r2, r1          ; Test if zero
    jnz puts_print          ; If not zero, print it
    ; Zero found, we're done
    pop r7
    ret
puts_print:
    ; R2 has the character to print
    mov r1, #1              ; syscall putchar
    syscall
    inc r3                  ; Next character (byte)
    jmp puts_loop

; putln - Print string followed by newline
; Input: R2 = pointer to string
; Clobbers: R0, R1, R3, R4, R5
putln:
    push r7                 ; Save our return address FIRST
    call puts               ; call puts (clobbers R7 with puts' ret addr)
    mov r1, #4              ; syscall newline
    syscall
    pop r7                  ; Restore OUR return address
    ret

; newline - Print a newline character
; Clobbers: R1
newline:
    push r7
    mov r1, #4
    syscall
    pop r7
    ret

; print_int - Print integer in decimal
; Input: R2 = integer value
; Clobbers: R1
print_int:
    push r7
    mov r1, #3
    syscall
    pop r7
    ret
; print_hex - Print integer in hexadecimal
; Input: R2 = integer value
; Clobbers: R1
print_hex:
    push r7
    mov r1, #5
    syscall
    pop r7
    ret

; getc - Read a single character (blocking)
; Output: R0 = character read
; Clobbers: R1
getc:
    push r7
    mov r1, #2
    syscall
    pop r7
    ret

; input_ready - Check if input is available
; Output: R0 = 1 if input available, 0 otherwise
; Clobbers: R1
input_ready:
    push r7
    mov r1, #7
    syscall
    pop r7
    ret

; flush - Flush output buffer
; Clobbers: R1
flush:
    push r7
    mov r1, #11
    syscall
    pop r7
    ret

; ============================================================================
; Program Control
; ============================================================================

; exit - Exit program with code
; Input: R2 = exit code
; Does not return
exit:
    mov r1, #0
    syscall
    halt

; exit0 - Exit program with code 0
; Does not return
exit0:
    mov r1, #0
    mov r2, #0
    syscall
    halt

; ============================================================================
; Random Number Generation
; ============================================================================

; rand - Get random number
; Output: R0 = random value (0-65535)
; Clobbers: R1
rand:
    push r7
    mov r1, #8
    syscall
    pop r7
    ret

; rand_range - Get random number in range [0, max)
; Input: R2 = max (exclusive)
; Output: R0 = random value in range
; Clobbers: R1, R3
rand_range:
    push r7
    mov r3, r2              ; Save max in R3 (R4/R5 clobbered)
    mov r1, #8              ; syscall random
    syscall
    ; R0 = R0 % R3 (modulo)
    ; Simple modulo: subtract until < max
rand_range_mod:
    sub r1, r0, r3          ; R1 = R0 - max
    jn rand_range_done      ; If negative, we're done
    mov r0, r1              ; R0 = R0 - max
    jmp rand_range_mod
rand_range_done:
    pop r7
    ret

; ============================================================================
; Timer Functions
; ============================================================================

; timer_lo - Get low 16 bits of timer
; Output: R0 = timer low word
; Clobbers: R1
timer_lo:
    push r7
    mov r1, #9
    syscall
    pop r7
    ret

; timer_hi - Get high 16 bits of timer
; Output: R0 = timer high word
; Clobbers: R1
timer_hi:
    push r7
    mov r1, #10
    syscall
    pop r7
    ret

; ============================================================================
; String Functions
; ============================================================================

; strlen - Get string length
; Input: R2 = pointer to null-terminated string
; Output: R0 = length (not counting null)
; Clobbers: R1, R2, R3
; NOTE: We use R2 for the counter (output), R3 for string pointer
strlen:
    mov r3, r2              ; Save string pointer in R3
    mov r2, #0              ; Length counter (will move to R0 at end)
strlen_loop:
    mov r0, r3              ; Address for load
    ld r1, [r0]             ; R1 = word at address
    ; Mask to low byte using shift
    mov r0, #8
    shl r1, r1, r0          ; R1 <<= 8
    shr r1, r1, r0          ; R1 >>= 8 (now only low byte)
    ; Check if zero
    mov r0, #0
    sub r0, r1, r0          ; R0 = R1 - 0, sets Z flag
    jz strlen_done
    inc r2                  ; Length++
    inc r3                  ; Next char
    jmp strlen_loop
strlen_done:
    mov r0, r2              ; Return length in R0
    ret

; strcmp - Compare two strings
; Input: R2 = pointer to string 1, R3 = pointer to string 2
; Output: R0 = 0 if equal, <0 if s1<s2, >0 if s1>s2
; Clobbers: R4, R5
strcmp:
    mov r4, r2              ; s1 pointer
    mov r5, r3              ; s2 pointer
strcmp_loop:
    ; Load characters
    mov r0, r4
    ld r0, [r0]             ; R0 = *s1
    mov r1, r5
    ld r1, [r1]             ; R1 = *s2
    
    ; Compare
    sub r2, r0, r1          ; R2 = *s1 - *s2
    jnz strcmp_diff         ; If different, return difference
    
    ; If both are null, strings are equal
    mov r2, #0
    sub r2, r0, r2
    jz strcmp_equal
    
    ; Next characters
    inc r4
    inc r5
    jmp strcmp_loop

strcmp_diff:
    mov r0, r2              ; Return difference
    ret
    
strcmp_equal:
    mov r0, #0              ; Return 0 (equal)
    ret

; strcpy - Copy string
; Input: R2 = destination, R3 = source
; Output: R0 = destination
; Clobbers: R4, R5
strcpy:
    mov r0, r2              ; Save destination for return
    mov r4, r2              ; dst pointer
    mov r5, r3              ; src pointer
strcpy_loop:
    ; Load source character
    mov r1, r5
    ld r1, [r1]             ; R1 = *src
    
    ; Store to destination
    mov r2, r4
    st [r2], r1             ; *dst = R1
    
    ; Check for null
    mov r2, #0
    sub r2, r1, r2
    jz strcpy_done
    
    ; Next characters
    inc r4
    inc r5
    jmp strcpy_loop
strcpy_done:
    ret

; strcat - Concatenate strings
; Input: R2 = destination, R3 = source to append
; Output: R0 = destination
; Clobbers: R1, R3
strcat:
    push r7                 ; Save return (we call functions)
    push r2                 ; Save destination
    push r3                 ; Save source
    
    ; Find end of destination
    call strlen             ; R0 = strlen(dest)
    pop r3                  ; Restore source
    pop r2                  ; Restore destination
    add r2, r2, r0          ; dest += strlen(dest)
    
    ; Copy source to end of destination
    call strcpy
    pop r7
    ret

; ============================================================================
; Memory Functions
; ============================================================================

; memset - Fill memory with value
; Input: R2 = destination, R3 = value (byte), R4 = count
; Output: R0 = destination
; Clobbers: R5
memset:
    mov r0, r2              ; Save destination for return
memset_loop:
    ; Check count
    mov r5, #0
    sub r5, r4, r5
    jz memset_done
    
    ; Store value
    st [r2], r3
    
    ; Next
    inc r2
    dec r4
    jmp memset_loop
memset_done:
    mov r0, r2              ; Return original destination
    ret

; memcpy - Copy memory
; Input: R2 = destination, R3 = source, R4 = count
; Output: R0 = destination
; Clobbers: R5
memcpy:
    mov r0, r2              ; Save destination for return
memcpy_loop:
    ; Check count
    mov r5, #0
    sub r5, r4, r5
    jz memcpy_done
    
    ; Copy byte
    ld r5, [r3]             ; R5 = *src
    st [r2], r5             ; *dst = R5
    
    ; Next
    inc r2
    inc r3
    dec r4
    jmp memcpy_loop
memcpy_done:
    ret

; ============================================================================
; Math Functions
; ============================================================================

; abs - Absolute value
; Input: R2 = value
; Output: R0 = |value|
abs:
    mov r0, r2
    ; Check if negative (check high bit)
    mov r1, #0
    sub r1, r0, r1          ; Sets N flag if R0 < 0
    jn abs_negate
    ret
abs_negate:
    ; Negate: R0 = 0 - R0
    mov r1, r0
    mov r0, #0
    sub r0, r0, r1
    ret

; min - Minimum of two values
; Input: R2 = a, R3 = b
; Output: R0 = min(a, b)
min:
    sub r0, r2, r3          ; R0 = a - b
    jn min_a                ; If a < b, return a
    mov r0, r3              ; Return b
    ret
min_a:
    mov r0, r2              ; Return a
    ret

; max - Maximum of two values
; Input: R2 = a, R3 = b
; Output: R0 = max(a, b)
max:
    sub r0, r2, r3          ; R0 = a - b
    jn max_b                ; If a < b, return b
    mov r0, r2              ; Return a
    ret
max_b:
    mov r0, r3              ; Return b
    ret

; mul - Multiply two values (16-bit result)
; Input: R2 = a, R3 = b
; Output: R0 = a * b (low 16 bits)
; Clobbers: R4, R5
mul:
    mov r0, #0              ; Result
    mov r4, r2              ; Multiplicand
    mov r5, r3              ; Multiplier
mul_loop:
    ; Check if multiplier is zero
    mov r1, #0
    sub r1, r5, r1
    jz mul_done
    
    ; Check LSB of multiplier (use AND with R1 containing 1)
    mov r1, #1
    and r1, r5, r1          ; R1 = R5 & 1
    jz mul_skip
    add r0, r0, r4          ; result += multiplicand
mul_skip:
    mov r1, #1              ; shift amount
    shl r4, r4, r1          ; multiplicand <<= 1
    shr r5, r5, r1          ; multiplier >>= 1
    jmp mul_loop
mul_done:
    ret

; div - Divide two values
; Input: R2 = dividend, R3 = divisor
; Output: R0 = quotient, R1 = remainder
; Clobbers: R4, R5
div:
    mov r0, #0              ; Quotient
    mov r1, r2              ; Remainder starts as dividend
div_loop:
    ; Check if remainder < divisor
    sub r4, r1, r3
    jn div_done
    ; remainder -= divisor
    mov r1, r4
    inc r0                  ; quotient++
    jmp div_loop
div_done:
    ret

; ============================================================================
; Stack Helper Macros (implemented as functions)
; ============================================================================

; Note: push/pop are built-in instructions, but here are helpers
; for pushing/popping multiple registers

; push_all - Push all caller-saved registers (R0-R5)
; Clobbers: nothing (but modifies R6)
push_all:
    push r0
    push r1
    push r2
    push r3
    push r4
    push r5
    ret

; pop_all - Pop all caller-saved registers (R5-R0)
; Restores: R0-R5
pop_all:
    pop r5
    pop r4
    pop r3
    pop r2
    pop r1
    pop r0
    ret

; ============================================================================
; Utility Functions
; ============================================================================

; delay - Simple delay loop
; Input: R2 = iterations
; Clobbers: R2
delay:
    mov r0, #0
    sub r0, r2, r0
    jz delay_done
    dec r2
    jmp delay
delay_done:
    ret

; is_digit - Check if character is a digit
; Input: R2 = character
; Output: R0 = 1 if digit, 0 otherwise
is_digit:
    mov r0, #0              ; Assume not a digit
    ; Check >= '0' (0x30)
    mov r1, #0x30
    sub r1, r2, r1
    jn is_digit_done        ; < '0'
    ; Check <= '9' (0x39)
    mov r1, #0x3A
    sub r1, r2, r1
    jn is_digit_yes         ; < 0x3A means <= '9'
    jmp is_digit_done
is_digit_yes:
    mov r0, #1
is_digit_done:
    ret

; is_alpha - Check if character is alphabetic
; Input: R2 = character
; Output: R0 = 1 if alpha, 0 otherwise
is_alpha:
    mov r0, #0
    ; Check uppercase A-Z (0x41-0x5A)
    mov r1, #0x41
    sub r1, r2, r1
    jn is_alpha_check_lower
    mov r1, #0x5B
    sub r1, r2, r1
    jn is_alpha_yes
    
is_alpha_check_lower:
    ; Check lowercase a-z (0x61-0x7A)
    mov r1, #0x61
    sub r1, r2, r1
    jn is_alpha_done
    mov r1, #0x7B
    sub r1, r2, r1
    jn is_alpha_yes
    jmp is_alpha_done
    
is_alpha_yes:
    mov r0, #1
is_alpha_done:
    ret

; to_upper - Convert character to uppercase
; Input: R2 = character
; Output: R0 = uppercase character
to_upper:
    mov r0, r2
    ; Check if lowercase (0x61-0x7A)
    mov r1, #0x61
    sub r1, r2, r1
    jn to_upper_done        ; < 'a'
    mov r1, #0x7B
    sub r1, r2, r1
    jn to_upper_convert     ; < 0x7B means <= 'z'
    jmp to_upper_done
to_upper_convert:
    ; Subtract 0x20 to convert to uppercase
    mov r1, #0x20
    sub r0, r2, r1
to_upper_done:
    ret

; to_lower - Convert character to lowercase
; Input: R2 = character
; Output: R0 = lowercase character
to_lower:
    mov r0, r2
    ; Check if uppercase (0x41-0x5A)
    mov r1, #0x41
    sub r1, r2, r1
    jn to_lower_done        ; < 'A'
    mov r1, #0x5B
    sub r1, r2, r1
    jn to_lower_convert     ; < 0x5B means <= 'Z'
    jmp to_lower_done
to_lower_convert:
    ; Add 0x20 to convert to lowercase
    mov r1, #0x20
    add r0, r2, r1
to_lower_done:
    ret

; atoi - Convert string to integer
; Input: R2 = pointer to string
; Output: R0 = integer value
; Clobbers: R1, R3
atoi:
    push r7                 ; Save return address (we call mul)
    mov r0, #0              ; Result
    mov r3, r2              ; String pointer (use R3, not R4)
    
    ; Note: We'll handle negative sign later for simplicity
    ; For now, just parse positive integers

atoi_loop:
    ; Load character - need to set up R0 for addressing, then restore result
    push r0                 ; Save result
    mov r0, r3              ; Address
    ld r1, [r0]             ; R1 = character
    pop r0                  ; Restore result
    
    ; Mask to low byte (high byte might have garbage)
    push r0
    mov r0, #8
    shl r1, r1, r0          ; R1 <<= 8
    shr r1, r1, r0          ; R1 >>= 8 (now only low byte)
    pop r0
    
    ; Check for null terminator
    mov r2, #0
    sub r2, r1, r2
    jz atoi_done
    
    ; Check if digit: '0' = 0x30, '9' = 0x39
    mov r2, #0x30
    sub r2, r1, r2          ; R2 = char - '0' (digit value if valid)
    jn atoi_done            ; char < '0', not a digit
    
    ; Check char <= '9'
    push r2                 ; Save digit value
    mov r2, #10
    sub r2, r1, r2          ; Actually we need to check if digit >= 10
    ; Wait, let me reconsider...
    ; R1 = character
    ; R2 = R1 - '0' = digit value
    ; We need to check if R2 < 10
    pop r2                  ; Restore digit value (R1 - '0')
    push r1                 ; Save character
    mov r1, #10
    sub r1, r2, r1          ; R1 = digit - 10
    pop r1                  ; Restore character
    jn atoi_digit           ; digit < 10, valid
    jmp atoi_done           ; digit >= 10, not valid
    
atoi_digit:
    ; result = result * 10 + digit
    ; R0 = current result
    ; R2 = digit value
    push r2                 ; Save digit
    mov r2, r0              ; First arg = result
    mov r3, #10             ; Second arg = 10 (but this clobbers string pointer!)
    ; Actually we need a different approach...
    pop r2                  ; Restore digit
    ; Let's use hardware mul instruction instead
    ; result = result * 10 + digit
    ; Actually the ALU has MUL! Let me just use that directly
    push r3                 ; Save string pointer
    push r2                 ; Save digit
    ; R0 = result, multiply by 10
    mov r2, #10
    mul r0, r0, r2          ; R0 = R0 * 10 (using ALU mul)
    pop r2                  ; Restore digit
    add r0, r0, r2          ; result += digit
    pop r3                  ; Restore string pointer
    
    inc r3                  ; Next character
    jmp atoi_loop

atoi_done:
    pop r7                  ; Restore return address
    ret
; ============================================================================
; Screen Functions
; ============================================================================

; screen_flush - Update the screen display
; Clobbers: R1
screen_flush:
    push r7
    mov r1, #13             ; syscall screen_flush
    syscall
    pop r7
    ret

; screen_putc - Put a character at a specific position
; Input: R0 = character, R1 = x, R2 = y, R3 = color
; Clobbers: R1, R2, R3, R4, R5
screen_putc:
    push r7
    ; Map to syscall params: R2=char, R3=x, R4=y, R5=color
    mov r5, r3              ; R5 = color
    mov r4, r2              ; R4 = y
    mov r3, r1              ; R3 = x
    mov r2, r0              ; R2 = char
    mov r1, #14             ; syscall screen_putc
    syscall
    pop r7
    ret

; screen_setxy - Set cursor position
; Input: R0 = x, R1 = y
; Clobbers: R1, R2
screen_setxy:
    push r7
    mov r3, r1              ; R3 = y
    mov r2, r0              ; R2 = x
    mov r1, #15             ; syscall screen_setxy
    syscall
    pop r7
    ret

; screen_getc - Get character at position
; Input: R0 = x, R1 = y
; Output: R0 = character | (color << 8)
; Clobbers: R1, R2, R3
screen_getc:
    push r7
    mov r3, r1              ; R3 = y
    mov r2, r0              ; R2 = x
    mov r1, #16             ; syscall screen_getc
    syscall
    ; Result is in R0
    pop r7
    ret

; screen_print - Print string at position with color
; Input: R0 = x, R1 = y, R2 = string address, R3 = color
; Clobbers: R0, R1, R2, R3, R4, R5
screen_print:
    push r7
    push r0                 ; Save x
    push r1                 ; Save y
    push r2                 ; Save string address
    push r3                 ; Save color
    
    ; String loop (use R6 for temp storage to avoid R4/R5)
    mov r6, r2              ; R6 = string pointer
    
screen_print_loop:
    ; Load character
    mov r0, r6
    ld r2, [r0]             ; R2 = word with character
    
    ; Get low byte only
    mov r0, #8
    shl r2, r2, r0
    shr r2, r2, r0          ; R2 = low byte
    
    ; Check for null
    mov r0, #0
    sub r0, r2, r0
    jz screen_print_done
    
    ; Get position and color from stack
    pop r3                  ; color
    pop r1                  ; y (original)
    pop r0                  ; x (original)
    push r0                 ; Save x back
    push r1                 ; Save y back
    push r3                 ; Save color back
    
    ; R2 = char, need to set up for screen_putc syscall
    ; screen_putc syscall: R2=char, R3=x, R4=y, R5=color
    mov r5, r3              ; color
    mov r4, r1              ; y
    mov r3, r0              ; x
    ; R2 already has char
    mov r1, #14             ; syscall screen_putc
    syscall
    
    ; Increment x position
    pop r3                  ; color
    pop r1                  ; y
    pop r0                  ; x
    inc r0                  ; x++
    push r0
    push r1
    push r3
    
    inc r6                  ; Next character
    jmp screen_print_loop

screen_print_done:
    ; Clean up stack
    pop r3                  ; color
    pop r2                  ; string
    pop r1                  ; y
    pop r0                  ; x
    pop r7
    ret

; screen_clear - Clear screen with a color
; Input: R0 = color (background in high nibble, foreground in low)
; Clobbers: R0, R1, R2, R3, R4, R5
screen_clear:
    push r7
    push r0                 ; Save color
    
    mov r4, #0              ; y = 0
screen_clear_y:
    mov r3, #0              ; x = 0
screen_clear_x:
    ; screen_putc: R2=char, R3=x, R4=y, R5=color
    mov r2, #32             ; space character
    pop r5                  ; Get color
    push r5                 ; Put it back
    ; R3 = x, R4 = y already set
    mov r1, #14             ; syscall screen_putc
    syscall
    
    inc r3                  ; x++
    mov r0, #80
    sub r0, r3, r0          ; x - 80
    jn screen_clear_x       ; if x < 80, continue
    
    inc r4                  ; y++
    mov r0, #25
    sub r0, r4, r0          ; y - 25
    jn screen_clear_y       ; if y < 25, continue
    
    pop r0                  ; Clean up color from stack
    pop r7
    ret

; ============================================================================
; Keyboard Functions
; ============================================================================

; kb_available - Check if keyboard input is available
; Output: R0 = 1 if key available, 0 otherwise
; Clobbers: R1
kb_available:
    push r7
    mov r1, #17             ; syscall kb_available
    syscall
    ; Result in R0
    pop r7
    ret

; kb_read - Read a key event
; Output: R0 = key event (bits 0-7: ASCII, bit 8: release flag)
; Clobbers: R1
kb_read:
    push r7
    mov r1, #18             ; syscall kb_read
    syscall
    ; Result in R0
    pop r7
    ret

; kb_getchar - Wait for and read a character (blocking)
; Output: R0 = ASCII character
; Clobbers: R1
kb_getchar:
    push r7
kb_getchar_wait:
    mov r1, #17             ; syscall kb_available
    syscall
    mov r1, #0
    sub r1, r0, r1
    jz kb_getchar_wait      ; Loop while no key available
    
    ; Key available, read it
    mov r1, #18             ; syscall kb_read
    syscall
    
    ; Mask to get just ASCII (bits 0-7)
    mov r1, #0xFF
    and r0, r0, r1
    
    pop r7
    ret

; ============================================================================
; Mouse Functions
; ============================================================================

; mouse_getxy - Get mouse position
; Output: R0 = x, R1 = y
; Clobbers: R1
mouse_getxy:
    push r7
    mov r1, #19             ; syscall mouse_getxy
    syscall
    ; R0 = x, R1 = y
    pop r7
    ret

; mouse_buttons - Get mouse button state
; Output: R0 = button state (bit 0=left, 1=right, 2=middle)
; Clobbers: R1
mouse_buttons:
    push r7
    mov r1, #20             ; syscall mouse_buttons
    syscall
    ; Result in R0
    pop r7
    ret

; mouse_left - Check if left mouse button is pressed
; Output: R0 = 1 if pressed, 0 otherwise
; Clobbers: R1
mouse_left:
    push r7
    mov r1, #20             ; syscall mouse_buttons
    syscall
    ; R0 has button state, test bit 0
    mov r1, #1
    and r0, r0, r1
    pop r7
    ret

; mouse_right - Check if right mouse button is pressed
; Output: R0 = 1 if pressed, 0 otherwise
; Clobbers: R1
mouse_right:
    push r7
    mov r1, #20             ; syscall mouse_buttons
    syscall
    ; R0 has button state, test bit 1
    mov r1, #2
    and r0, r0, r1
    ; Shift right to get 0 or 1
    mov r1, #1
    shr r0, r0, r1
    pop r7
    ret