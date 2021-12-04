.CODE

;----------------  SYSCALL  -------------------
x_syscall PROC

; save regs rsi, rdi, rbx, r12 in stack
;
sub rsp, 48h

mov [rsp],       rsi
mov [rsp + 8],   rdi
mov [rsp + 10h], rbx
mov [rsp + 18h], r12
mov [rsp + 20h], r13

; get args from func
;
mov eax,  ecx ; syscall number
mov esi,  edx ; params
mov rdi,  r8  ; syscall address
mov r12,  r9  ; param package

cmp rsi, 0    ; if no params, make call
je  make_call

; get args from param table (x64 call)
;
mov rcx, [r12]
add r12, 8
dec rsi
jz  make_call

mov rdx, [r12]
add r12, 8
dec rsi
jz  make_call

mov r8, [r12]
add r12, 8
dec rsi
jz  make_call

mov r9, [r12]
add r12, 8
dec rsi
jz  make_call

lea rbx, [rsi * 8]
sub rsp, rbx
mov rbx, 0 

add_arg:
	mov r13, [r12]
	mov [rsp + rbx], r13
	add rbx, 8
	add r12, 8
	dec rsi
	jnz add_arg

make_call:

sub rsp, 20h

db 4Ch, 8Dh, 1Dh, 27h, 00h, 00h, 00h  ; lea r11, [rip+0x27] ; 39 bytes
call r11

add rsp, 20h
add rsp, rbx

mov r13, [rsp + 20h]
mov r12, [rsp + 18h]
mov rbx, [rsp + 10h]
mov rdi, [rsp + 8]
mov rsi, [rsp]

add rsp, 48h

ret

mov r10, rcx
jmp rdi			; syscall

x_syscall ENDP

END