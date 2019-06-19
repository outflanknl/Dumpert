.code

; Reference: https://j00ru.vexillium.org/syscalls/nt/64/

; Windows 7 SP1 / Server 2008 R2 specific syscalls

ZwOpenProcess7SP1 proc
		mov r10, rcx
		mov eax, 23h
		syscall
		ret
ZwOpenProcess7SP1 endp

ZwClose7SP1 proc
		mov r10, rcx
		mov eax, 0Ch
		syscall
		ret
ZwClose7SP1 endp

ZwWriteVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 37h
		syscall
		ret
ZwWriteVirtualMemory7SP1 endp

ZwProtectVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 4Dh
		syscall
		ret
ZwProtectVirtualMemory7SP1 endp

ZwQuerySystemInformation7SP1 proc
		mov r10, rcx
		mov eax, 33h
		syscall
		ret
ZwQuerySystemInformation7SP1 endp

NtAllocateVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 15h
		syscall
		ret
NtAllocateVirtualMemory7SP1 endp

NtFreeVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 1Bh
		syscall
		ret
NtFreeVirtualMemory7SP1 endp

NtCreateFile7SP1 proc
		mov r10, rcx
		mov eax, 52h
		syscall
		ret
NtCreateFile7SP1 endp

; Windows 8 / Server 2012 specific syscalls

ZwOpenProcess80 proc
		mov r10, rcx
		mov eax, 24h
		syscall
		ret
ZwOpenProcess80 endp

ZwClose80 proc
		mov r10, rcx
		mov eax, 0Dh
		syscall
		ret
ZwClose80 endp

ZwWriteVirtualMemory80 proc
		mov r10, rcx
		mov eax, 38h
		syscall
		ret
ZwWriteVirtualMemory80 endp

ZwProtectVirtualMemory80 proc
		mov r10, rcx
		mov eax, 4Eh
		syscall
		ret
ZwProtectVirtualMemory80 endp

ZwQuerySystemInformation80 proc
		mov r10, rcx
		mov eax, 34h
		syscall
		ret
ZwQuerySystemInformation80 endp

NtAllocateVirtualMemory80 proc
		mov r10, rcx
		mov eax, 16h
		syscall
		ret
NtAllocateVirtualMemory80 endp

NtFreeVirtualMemory80 proc
		mov r10, rcx
		mov eax, 1Ch
		syscall
		ret
NtFreeVirtualMemory80 endp

NtCreateFile80 proc
		mov r10, rcx
		mov eax, 53h
		syscall
		ret
NtCreateFile80 endp

; Windows 8.1 / Server 2012 R2 specific syscalls

ZwOpenProcess81 proc
		mov r10, rcx
		mov eax, 25h
		syscall
		ret
ZwOpenProcess81 endp

ZwClose81 proc
		mov r10, rcx
		mov eax, 0Eh
		syscall
		ret
ZwClose81 endp

ZwWriteVirtualMemory81 proc
		mov r10, rcx
		mov eax, 39h
		syscall
		ret
ZwWriteVirtualMemory81 endp

ZwProtectVirtualMemory81 proc
		mov r10, rcx
		mov eax, 4Fh
		syscall
		ret
ZwProtectVirtualMemory81 endp

ZwQuerySystemInformation81 proc
		mov r10, rcx
		mov eax, 35h
		syscall
		ret
ZwQuerySystemInformation81 endp

NtAllocateVirtualMemory81 proc
		mov r10, rcx
		mov eax, 17h
		syscall
		ret
NtAllocateVirtualMemory81 endp

NtFreeVirtualMemory81 proc
		mov r10, rcx
		mov eax, 1Dh
		syscall
		ret
NtFreeVirtualMemory81 endp

NtCreateFile81 proc
		mov r10, rcx
		mov eax, 54h
		syscall
		ret
NtCreateFile81 endp

; Windows 10 / Server 2016 specific syscalls
 
ZwOpenProcess10 proc
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
ZwOpenProcess10 endp

ZwClose10 proc
		mov r10, rcx
		mov eax, 0Fh
		syscall
		ret
ZwClose10 endp

ZwWriteVirtualMemory10 proc
		mov r10, rcx
		mov eax, 3Ah
		syscall
		ret
ZwWriteVirtualMemory10 endp

ZwProtectVirtualMemory10 proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret
ZwProtectVirtualMemory10 endp

ZwQuerySystemInformation10 proc
		mov r10, rcx
		mov eax, 36h
		syscall
		ret
ZwQuerySystemInformation10 endp

NtAllocateVirtualMemory10 proc
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
NtAllocateVirtualMemory10 endp

NtFreeVirtualMemory10 proc
		mov r10, rcx
		mov eax, 1Eh
		syscall
		ret
NtFreeVirtualMemory10 endp

NtCreateFile10 proc
		mov r10, rcx
		mov eax, 55h
		syscall
		ret
NtCreateFile10 endp

end
