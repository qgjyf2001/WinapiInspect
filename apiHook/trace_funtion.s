.model flat, c
.code 
traceFunction proc
pushad
mov eax, [esp + 32]
push eax
call reportFunctionCall
mov [esp + 36], eax
pop eax
popad
ret
traceFunction endp

extern reportFunctionCall:proc  
end