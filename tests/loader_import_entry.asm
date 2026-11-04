; entry code for the import e2e: VirtualAlloc via IAT, prove the
; page is writable, then ExitProcess(1122h) via IAT
.code
entry proc
    sub rsp, 28h
    xor ecx, ecx                                   ; lpAddress = NULL
    mov edx, 1000h                                 ; dwSize
    mov r8d, 3000h                                 ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 4                                     ; PAGE_READWRITE
    call qword ptr [rip + IAT0]                    ; VirtualAlloc
    test rax, rax
    mov ecx, 0DEADh                                ; failure exit code
    jz done
    mov byte ptr [rax], 42h                        ; prove the page is writable
    cmp byte ptr [rax], 42h
    mov ecx, 1122h                                 ; success exit code
done:
    mov r10, -1                                    ; NtTerminateProcess handle
    mov edx, ecx                                   ; exit code
    mov eax, 1002h                                 ; NtTerminateProcess
    syscall
    jmp $
entry endp
end
