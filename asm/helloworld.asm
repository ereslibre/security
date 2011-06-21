section	.data
msg	db	"Hello, world !", 0x0a

section	.text
global	_start
_start:

; write(1, "Hello, world !", 15);
mov eax, 4	; write is syscall #4
mov ebx, 1	; stdout
mov ecx, msg	; our message
mov edx, 15	; message length
int 0x80	; do it !

; exit(0)
mov eax, 1	; exit is syscall #1
mov ebx, 0	; status code
int 0x80	; do it !


