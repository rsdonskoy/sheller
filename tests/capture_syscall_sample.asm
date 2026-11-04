; Synthetic hello sample for the syscall route: three direct
; syscalls (synthetic numbers shared with the C++ policy table) covering the
; minimal handler set - NtWriteFile("hello"), NtDelayExecution (no-op) and
; NtTerminateProcess(0x1234). The entry is patched into a spin by the
; capture path before the loader runs, so none of this executes in the real
; process; in the emulator the handler back-ends provide the results.
;
; entry_deny exercises the default-deny path: an unregistered number must
; come back with STATUS_ACCESS_DENIED in rax (stored to g_result and handed
; to NtTerminateProcess as the exit code so tests can assert the write-back).
; entry_spin never issues a syscall and always exhausts the budget.
; entry_multi issues NtWriteFile three times with different buffers before
; terminating, which is the shape a host sink that throws on one write needs:
; only that write can be shown to be the one that went missing.
; entry_delay is the burn-loop corpus: outer 16 x inner 100000h counter
; decrements with no guest writes, then terminate. The run only reaches the
; terminate syscall when the fast-forward skips the inner loop and the cached
; exit covers the outer re-entries; a regression exhausts the default 1M
; instruction budget inside the delay.

.code
entry proc
    sub rsp, 38h
    ; NtWriteFile(handle=0, event=0, apc=0, apcctx=0, iosb, buffer, 5, 0, 0)
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    lea rax, g_iosb
    mov [rsp+28h], rax
    lea rax, g_hello
    mov [rsp+30h], rax
    mov qword ptr [rsp+38h], 5
    mov qword ptr [rsp+40h], 0
    mov qword ptr [rsp+48h], 0
    mov eax, 1000h
    syscall
    ; NtDelayExecution(alertable=0, delay)
    xor r10d, r10d
    lea rdx, g_delay
    mov eax, 1001h
    syscall
    ; NtTerminateProcess(handle=-1, exit code 1234h)
    mov r10, -1
    mov edx, 1234h
    mov eax, 1002h
    syscall
    add rsp, 38h
    ret
entry endp

entry_deny proc
    sub rsp, 28h
    mov eax, 0DEADh  ; unregistered: default deny must set rax
    syscall
    mov g_result, rax
    add rsp, 28h
    ; NtTerminateProcess with the stored low dword as the exit code
    mov r10, -1
    mov edx, dword ptr [g_result]
    mov eax, 1002h
    syscall
    ret
entry_deny endp

entry_spin proc
    sub rsp, 28h
spin:
    jmp spin
entry_spin endp

entry_delay proc
    sub rsp, 28h
    mov r11d, 10h
delay_outer:
    mov ecx, 100000h
delay_inner:
    lea ecx, [rcx-1]
    test ecx, ecx
    jne delay_inner
    dec r11d
    jne delay_outer
    ; the loop leaves rcx at zero; the engine's terminate handler reads rcx
    ; as the process handle, and zero is the "process terminating" pending
    ; path - set the explicit current-process handle
    mov rcx, -1
    mov r10, -1
    mov edx, 1234h
    mov eax, 1002h
    syscall
    add rsp, 28h
    ret
entry_delay endp

; entry_multi writes three separate buffers, then terminates. The point of the
; distinct contents and lengths is that a host sink which throws on one of them
; can be shown to have lost exactly that write: the recording sink sees
; "one" then "three" with "two" gone, and an ordering claim is only testable if
; the pieces are distinguishable. Same stack slots as entry (the syscall
; convention puts args 5.. on the stack), same synthetic numbers.
entry_multi proc
    sub rsp, 38h
    ; NtWriteFile(handle=0, event=0, apc=0, apcctx=0, iosb, buffer, 3, 0, 0)
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    lea rax, g_iosb
    mov [rsp+28h], rax
    lea rax, g_one
    mov [rsp+30h], rax
    mov qword ptr [rsp+38h], 3
    mov qword ptr [rsp+40h], 0
    mov qword ptr [rsp+48h], 0
    mov eax, 1000h
    syscall
    ; NtWriteFile(..., g_two, 3, ...)
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    lea rax, g_iosb
    mov [rsp+28h], rax
    lea rax, g_two
    mov [rsp+30h], rax
    mov qword ptr [rsp+38h], 3
    mov qword ptr [rsp+40h], 0
    mov qword ptr [rsp+48h], 0
    mov eax, 1000h
    syscall
    ; NtWriteFile(..., g_three, 5, ...)
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    lea rax, g_iosb
    mov [rsp+28h], rax
    lea rax, g_three
    mov [rsp+30h], rax
    mov qword ptr [rsp+38h], 5
    mov qword ptr [rsp+40h], 0
    mov qword ptr [rsp+48h], 0
    mov eax, 1000h
    syscall
    ; NtTerminateProcess(handle=-1, exit code 1234h)
    mov r10, -1
    mov edx, 1234h
    mov eax, 1002h
    syscall
    add rsp, 38h
    ret
entry_multi endp

.data
g_hello db "hello"
g_one db "one"
g_two db "two"
g_three db "three"
g_iosb dq 0, 0
g_delay dq 0
g_result dq 0
end
