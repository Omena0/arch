; ============================================================================
; Fr Kernel - Real multi-process OS with scheduling and syscalls
; ============================================================================

.base 0x0100
.entry kernel_boot
.kernel 0x0800  ; Kernel occupies space from 0x0100 to 0x0800

#include "config.asm"
#include "boot.asm"
#include "scheduler.asm"
#include "syscalls.asm"
