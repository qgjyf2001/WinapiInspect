.code 
traceFunction proc
push        rsp
push        rax
push        rcx
push        rdx
push        rbx
push        rbp
push        rsi
push        rdi
push        r8
push        r9
push        r10
push        r11
push        r12
push        r13
push        r14
push        r15
pushfq
mov rcx, [rsp + 136]
push rcx
call reportFunctionCall
mov [rsp + 144], rax
pop rax
popfq
pop        r15
pop        r14
pop        r13
pop        r12
pop        r11
pop        r10
pop        r9
pop        r8
pop        rdi
pop        rsi
pop        rbp
pop        rbx
pop        rdx
pop        rcx
pop        rax
pop        rsp
ret
traceFunction endp

extern reportFunctionCall:proc  
end
