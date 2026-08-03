ExitProcess proto
.data
sum qword 0
.code
main proc

	mov rax, 1fffffffffffffffh
	push rax
	push rcx
	push rdx
	push r8
	push r9
	mov rcx,  1fffffffffffffffh

	mov rax, 1fffffffffffffffh
	call     rax

	pop r9
	pop r8
	pop rdx
	pop rcx
	ret
main endp
end