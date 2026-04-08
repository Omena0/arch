; ============================================================================
; KERNEL CONFIGURATION - Centralized constants and memory layout
; ============================================================================

; ============================================================================
; TRAP INFORMATION
; ============================================================================

#define TRAP_CAUSE     0x0010  ; Trap cause register
#define TRAP_ADDR      0x0014  ; Trap address
#define TRAP_PC        0x0018  ; Trap program counter
#define TRAP_VALUE     0x001C  ; Trap value

; Trap cause codes
#define TRAP_MMIO_READ   0x0001  ; Unprivileged MMIO read
#define TRAP_MMIO_WRITE  0x0002  ; Unprivileged MMIO write (includes syscalls)
#define TRAP_INVALID_OP  0x0003  ; Invalid operation  
#define TRAP_DIV_ZERO    0x0004  ; Division by zero
#define TRAP_TIMER       0x0005  ; Timer interrupt
#define TRAP_MEM_VIOLATION 0x0006 ; Memory protection violation
#define TRAP_SYSCALL     0x0007  ; User syscall via MMIO gateway

; User Register Save Area
#define USER_REGS_ADDR 0x0060  ; Base address for saved user registers (4-byte intervals for 32-bit values)
#define USER_R0_ADDR   0x0060
#define USER_R1_ADDR   0x0064
#define USER_R2_ADDR   0x0068
#define USER_R3_ADDR   0x006C
#define USER_R4_ADDR   0x0070
#define USER_R5_ADDR   0x0074
#define USER_R6_ADDR   0x0078
#define USER_R7_ADDR   0x007C

; Kernel Variables
#define kvar_booted        0x0020  ; Kernel initialized flag (1 byte)
#define kvar_pid           0x0022  ; Current process ID (1 byte)
#define kvar_proc_count    0x0024  ; Number of processes (1 byte)
#define kvar_alive_count   0x0026  ; Count of alive processes (1 byte)
#define kvar_init_loop     0x002A  ; Temp variable for loops
#define kvar_filename_buf  0x00C0  ; Filename buffer (32 bytes)
#define kvar_load_temp     0x00E0  ; Load temporary storage

; Process Control Block table
#define proc_table_base  0x0200  ; Start of PCB table
#define PCB_SIZE         32      ; 16 words per process: 8 regs + PC + reserved
#define MAX_PROCESSES    16      ; Maximum number of processes

; Memory Layout
#define KERNEL_BASE      0x0000  ; Kernel code/data base
#define KERNEL_SIZE      0x0100  ; Kernel region (256 bytes)
#define USER_CODE_BASE   0x4000  ; User code starts here
#define USER_STACK_BASE  0xFFFF  ; User stack top

; Timer configuration
#define TIMER_INTERVAL   5000    ; Timer interrupt interval (cycles)

; ============================================================================
; MMIO ADDRESSES - Memory-Mapped I/O
; ============================================================================

; Character I/O
#define MMIO_PRINT_CHAR  0xFF00  ; Write character to stdout
#define MMIO_PRINT_INT   0xFF02  ; Write integer (decimal)
#define MMIO_PRINT_HEX   0xFF04  ; Write integer (hex)
#define MMIO_PRINT_STR   0xFF06  ; Write null-terminated string
#define MMIO_INPUT_CHAR  0xFF08  ; Read character (blocking)
#define MMIO_INPUT_READY 0xFF0A  ; Check if input available
#define MMIO_INPUT_LINE  0xFF0C  ; Read line with max length
#define MMIO_NEWLINE     0xFF0E  ; Write newline

; Timer
#define MMIO_TIMER_LO    0xFF10  ; Read: low 16 bits of cycle counter
#define MMIO_TIMER_HI    0xFF12  ; Read: high 16 bits of cycle counter
#define MMIO_TIMER_INTERVAL  0xFF36  ; Set timer interrupt interval

; Misc
#define MMIO_RANDOM      0xFF14  ; Read: random 16-bit value
#define MMIO_EXIT        0xFF18  ; Exit with code

; File I/O (kernel only)
#define MMIO_FILE_OPEN   0xFF20  ; Open file (path in R1), returns handle in R0
#define MMIO_FILE_READ   0xFF22  ; Read from handle (R1=handle, R2=buf, R3=len), returns bytes in R0
#define MMIO_FILE_CLOSE  0xFF24  ; Close file handle (R1=handle)
#define MMIO_FILE_SIZE   0xFF26  ; Get file size (R1=handle), returns size in R0
#define MMIO_FILE_SEEK   0xFF28  ; Seek in file

; Program Arguments
#define MMIO_ARG_COUNT   0xFF30  ; Read: number of arguments
#define MMIO_ARG_LEN     0xFF32  ; Read: length of argument (R1=index)
#define MMIO_ARG_COPY    0xFF34  ; Copy argument to buffer (R1=index, R2=buf, R3=maxlen)

; Memory Setup
#define MMIO_SET_PROC_BASE   0xFF3C  ; Set process base address
#define MMIO_SET_PROC_LIMIT  0xFF3E  ; Set process limit address

; Syscalls  
#define MMIO_SYSCALL     0xFF80  ; User program writes here to trigger syscall trap

; ============================================================================
; SYSCALL NUMBERS
; ============================================================================

#define SYS_EXIT         0
#define SYS_PUTCHAR      1
#define SYS_GETCHAR      2
#define SYS_PRINT_INT    3
#define SYS_TIME_LO      4
#define SYS_TIME_HI      5
#define SYS_RANDOM       6
#define SYS_FORK         7
#define SYS_WAIT         8
#define SYS_NEWLINE      9
#define SYS_PRINT_HEX   10
#define SYS_PRINT_STR   11
#define SYS_YIELD       12
#define SYS_OPEN_FILE  13
#define SYS_READ_FILE  14
#define SYS_CLOSE_FILE 15
