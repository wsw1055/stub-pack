.386
.model flat, stdcall
option casemap:none

include windows.inc
includelib user32.lib

COMPRESS_ALGORITHM_XPRESS_HUFF  equ 4

InitPackEnv proto env:ptr PackEnv
GetKernel32Base proto
GetModuleBase proto
StubEntry proto
MyProcAddress proto hModule:dword, szName:dword
MyStrcmp proto  szSrc:dword, szDst:dword
MyCopyMemory proto Dest:dword, Src:dword, Len:dword
FixImportTable proto env:ptr PackEnv, imageBase:dword, buffer:dword
FixRelTable proto env:ptr PackEnv, imageBase:dword, buffer:dword
FixTlsTable proto imageBase:dword, buffer:dword

.code

PackEnv struct 
    OldEntryPoint        dd ?
    VirtualAllocPtr       dd ?
    VirtualFreePtr       dd ?
    VirtualProtectPtr    dd ?
    LoadLibraryAPtr     dd ?
    GetProcAddressPtr dd ?
    CreateDecompressorPtr  dd ?
    DecompressPtr dd ?
    CloseDecompressorPtr dd ?
PackEnv ends

PackerInfo struct  
    version dd ? 
    oldEntryPoint dd ?
    oldDataSize dd  ?
    newDataSize dd ?
PackerInfo ends

start:
    pushad
    pushfd
    
    invoke StubEntry
    mov dword ptr [esp+20h], eax
    
    popfd
    popad
    jmp eax

StubEntry proc
    LOCAL @Env:PackEnv
    LOCAL @Decompressor:HANDLE
    LOCAL @PackerInfo:ptr PackerInfo
    LOCAL @ImageBase:DWORD 
    LOCAL @Buffer:dword
    LOCAL @Size:dword
    LOCAL @OldProto:dword
    
    invoke InitPackEnv, addr @Env
    
    invoke GetModuleBase
    mov @ImageBase, eax
    
    mov  eax, @ImageBase
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, @ImageBase
    assume eax:ptr IMAGE_NT_HEADERS
    lea ebx, [eax].OptionalHeader
    movzx eax, [eax].FileHeader.SizeOfOptionalHeader
    add ebx,eax 
   
    assume ebx:ptr IMAGE_SECTION_HEADER
    add ebx, sizeof IMAGE_SECTION_HEADER
    mov eax, [ebx].VirtualAddress
    add eax, @ImageBase
    mov @PackerInfo, eax
    
    lea eax,  @Decompressor
    push eax
    push NULL
    push COMPRESS_ALGORITHM_XPRESS_HUFF
    call @Env.CreateDecompressorPtr
    
    mov esi, @PackerInfo
    assume esi:ptr PackerInfo
    
    push PAGE_READWRITE
    push MEM_COMMIT
    mov eax, [esi].oldDataSize
    push eax
    push NULL
    call @Env.VirtualAllocPtr
    mov @Buffer, eax
    
    lea eax, @Size
    push eax
    push [esi].oldDataSize
    push @Buffer
    push [esi].newDataSize
    lea eax, [esi + sizeof PackerInfo]
    push eax
    push @Decompressor
    call @Env.DecompressPtr
    
    lea eax, @OldProto
    push eax
    push PAGE_EXECUTE_READWRITE
    push 1000h
    push @ImageBase
    call @Env.VirtualProtectPtr
    
    invoke MyCopyMemory,@ImageBase, @Buffer, 1000h
    
    lea eax, @OldProto
    push eax
    push @OldProto
    push 1000h
    push @ImageBase
    call @Env.VirtualProtectPtr
    
    mov  eax, @Buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov esi, [eax].e_lfanew
    add esi, @Buffer
    assume esi:ptr IMAGE_NT_HEADERS
    lea ebx, [esi].OptionalHeader
    movzx eax, [esi].FileHeader.SizeOfOptionalHeader
    add ebx,eax 
    assume ebx:ptr IMAGE_SECTION_HEADER
    
    xor cx, cx
    .while cx < [esi].FileHeader.NumberOfSections
        push ecx
        push [ebx].SizeOfRawData
        
        mov eax, [ebx].PointerToRawData
        add eax, @Buffer
        push eax
        
        mov eax, [ebx].VirtualAddress
        add eax, @ImageBase
        push eax
        call MyCopyMemory
        
        lea eax, @OldProto
        push eax
        push PAGE_EXECUTE_READWRITE
        push [ebx].Misc.VirtualSize
        mov eax, [ebx].VirtualAddress
        add eax, @ImageBase
        push eax
        call @Env.VirtualProtectPtr
        
        add ebx, sizeof IMAGE_SECTION_HEADER
        pop ecx    
        inc cx
    .endw
    
    invoke FixImportTable, addr @Env, @ImageBase, @Buffer
    invoke FixRelTable, addr @Env, @ImageBase, @Buffer
    invoke FixTlsTable, @ImageBase, @Buffer
    
    mov  eax, @Buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov esi, [eax].e_lfanew
    add esi, @Buffer
    assume esi:ptr IMAGE_NT_HEADERS
    lea ebx, [esi].OptionalHeader
    movzx eax, [esi].FileHeader.SizeOfOptionalHeader
    add ebx,eax 
    assume ebx:ptr IMAGE_SECTION_HEADER

    xor cx, cx
    .while cx < [esi].FileHeader.NumberOfSections
        push ecx
        
        lea eax, @OldProto
        push eax
        
        mov eax, [ebx].Characteristics
        mov ecx, PAGE_EXECUTE_READWRITE
        test eax, IMAGE_SCN_MEM_EXECUTE
        .if !ZERO?
            test eax, IMAGE_SCN_MEM_WRITE
            .if !ZERO?
                mov ecx, PAGE_EXECUTE_READWRITE
            .else
                mov ecx, PAGE_EXECUTE_READ
            .endif
        .else
            test eax, IMAGE_SCN_MEM_WRITE
            .if !ZERO?
                mov ecx, PAGE_READWRITE
            .else
                mov ecx, PAGE_READONLY
            .endif
        .endif
        push ecx
        
        push [ebx].Misc.VirtualSize
        mov eax, [ebx].VirtualAddress
        add eax, @ImageBase
        push eax
        call @Env.VirtualProtectPtr
        
        add ebx, sizeof IMAGE_SECTION_HEADER
        pop ecx    
        inc cx
    .endw
    
    push @Decompressor
    call @Env.CloseDecompressorPtr
    
    push MEM_RELEASE
    push 0
    push @Buffer
    call @Env.VirtualFreePtr
    
    mov esi, @PackerInfo
    assume esi:ptr PackerInfo
    mov eax, [esi].oldEntryPoint
    add eax, @ImageBase
    
    ret
StubEntry endp

FixImportTable proc uses esi edi ebx env:ptr PackEnv, imageBase:dword, buffer:dword
    LOCAL @hModule:DWORD
    
    mov eax, buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, buffer
    assume eax:ptr IMAGE_NT_HEADERS
    
    mov eax, [eax].OptionalHeader.DataDirectory[1*8].VirtualAddress
    .if eax == 0
        ret
    .endif
    add eax, imageBase
    mov esi, eax
    assume esi:ptr IMAGE_IMPORT_DESCRIPTOR
    
    .while TRUE
        .if [esi].Name1 == 0
            .break
        .endif
        
        mov eax, [esi].Name1
        add eax, imageBase
        push eax
        mov ecx, env
        assume ecx:ptr PackEnv
        call [ecx].LoadLibraryAPtr
        mov @hModule, eax
        
        .if @hModule != 0
            mov eax, [esi].OriginalFirstThunk
            .if eax == 0
                mov eax, [esi].FirstThunk
            .endif
            add eax, imageBase
            mov edi, eax
            assume edi:ptr IMAGE_THUNK_DATA
            
            mov ebx, [esi].FirstThunk
            add ebx, imageBase
            
            .while dword ptr [edi] != 0
                mov eax, dword ptr [edi]
                .if eax & 80000000h
                    and eax, 0FFFFh
                    push eax
                    push @hModule
                    mov ecx, env
                    call [ecx].GetProcAddressPtr
                .else
                    add eax, imageBase
                    add eax, 2
                    push eax
                    push @hModule
                    mov ecx, env
                    call [ecx].GetProcAddressPtr
                .endif
                
                mov dword ptr [ebx], eax
                
                add edi, 4
                add ebx, 4
            .endw
        .endif
        
        add esi, sizeof IMAGE_IMPORT_DESCRIPTOR
    .endw
    
    ret
FixImportTable endp

FixRelTable proc uses esi edi ebx env:ptr PackEnv, imageBase:dword, buffer:dword
    LOCAL @Delta:DWORD
    LOCAL @OldProto:DWORD
    LOCAL @TmpProto:DWORD
    
    mov eax, buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, buffer
    assume eax:ptr IMAGE_NT_HEADERS
    
    mov eax, [eax].OptionalHeader.ImageBase
    mov ecx, imageBase
    sub ecx, eax
    mov @Delta, ecx
    
    .if @Delta == 0
        ret
    .endif
    
    mov eax, buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, buffer
    assume eax:ptr IMAGE_NT_HEADERS
    
    mov eax, [eax].OptionalHeader.DataDirectory[5*8].VirtualAddress
    .if eax == 0
        ret
    .endif
    add eax, imageBase
    mov esi, eax
    assume esi:ptr IMAGE_BASE_RELOCATION
    
    .while TRUE
        mov eax, [esi].SizeOfBlock
        .if eax == 0
            .break
        .endif
        
        sub eax, 8
        shr eax, 1
        mov ecx, eax
        
        lea eax, @OldProto
        push eax
        push PAGE_EXECUTE_READWRITE
        push 1000h
        mov eax, [esi].VirtualAddress
        add eax, imageBase
        push eax
        mov edx, env
        assume edx:ptr PackEnv
        call [edx].VirtualProtectPtr
        
        lea edi, [esi + 8]
        mov ebx, 0
        
        .while ebx < ecx
            movzx eax, word ptr [edi]
            and eax, 0F000h
            .if eax == 3000h
                movzx eax, word ptr [edi]
                and eax, 0FFFh
                add eax, [esi].VirtualAddress
                add eax, imageBase
                mov edx, dword ptr [eax]
                add edx, @Delta
                mov dword ptr [eax], edx
            .endif
            add edi, 2
            inc ebx
        .endw
        
        lea eax, @TmpProto
        push eax
        push @OldProto
        push 1000h
        mov eax, [esi].VirtualAddress
        add eax, imageBase
        push eax
        mov edx, env
        assume edx:ptr PackEnv
        call [edx].VirtualProtectPtr
        
        mov eax, [esi].SizeOfBlock
        add esi, eax
    .endw
    
    ret
FixRelTable endp

FixTlsTable proc uses esi edi ebx imageBase:dword, buffer:dword
    mov eax, buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, buffer
    assume eax:ptr IMAGE_NT_HEADERS
    
    mov eax, [eax].OptionalHeader.DataDirectory[9*8].VirtualAddress
    .if eax == 0
        ret
    .endif
    add eax, imageBase
    mov esi, eax
    assume esi:ptr IMAGE_TLS_DIRECTORY
    
    mov eax, [esi].AddressOfCallBacks
    .if eax == 0
        ret
    .endif
    add eax, imageBase
    mov edi, eax
    
    .while dword ptr [edi] != 0
        mov eax, dword ptr [edi]
        add eax, imageBase
        
        push NULL
        push 1
        push imageBase
        call eax
        
        add edi, 4
    .endw
    
    ret
FixTlsTable endp

InitPackEnv proc env:ptr PackEnv
    LOCAL hKernel32:HANDLE
    LOCAL hCabinet:HANDLE
     
    mov esi, env
    assume esi:ptr PackEnv
    
    invoke GetKernel32Base
    mov hKernel32, eax
    
    call next
next:
    pop ebx
    sub  ebx, offset next
    
    lea eax, dword ptr [ebx + szGetProcAddress]
    invoke MyProcAddress, hKernel32, eax
    mov edi, eax
    mov [esi].GetProcAddressPtr, edi
    
    lea eax, [ebx + offset szLoadLibraryA]
    push eax
    push hKernel32
    call edi
    mov [esi].LoadLibraryAPtr, eax
    
    lea eax, [ebx + offset szVirtualAlloc]
    push eax
    push hKernel32
    call edi
    mov [esi].VirtualAllocPtr, eax
    
    lea eax, [ebx + offset szVirtualFree]
    push eax
    push hKernel32
    call edi
    mov [esi].VirtualFreePtr, eax
    
    lea eax, [ebx + offset szVirtualProtect]
    push eax
    push hKernel32
    call edi
    mov [esi].VirtualProtectPtr, eax

    lea eax, [ebx + offset szCabinet]
    push eax
    call [esi].LoadLibraryAPtr
    mov hCabinet, eax
 
    lea eax, [ebx + offset szCreateDecompressor]
    push eax
    push hCabinet
    call edi
    mov [esi].CreateDecompressorPtr, eax
    
    lea eax, [ebx + offset szDecompress]
    push eax
    push hCabinet
    call edi
    mov [esi].DecompressPtr, eax
    
    lea eax, [ebx + offset szCloseDecompressor]
    push eax
    push hCabinet
    call edi
    mov [esi].CloseDecompressorPtr, eax
    
    ret
    
szGetProcAddress db "GetProcAddress", 0
szLoadLibraryA db "LoadLibraryA", 0
szVirtualAlloc db "VirtualAlloc", 0
szVirtualFree db "VirtualFree", 0
szVirtualProtect db "VirtualProtect", 0
szCabinet  db "Cabinet.dll", 0
szCreateDecompressor db "CreateDecompressor", 0
szDecompress db "Decompress", 0
szCloseDecompressor db "CloseDecompressor", 0
szCopyMemory db "CopyMemory"
InitPackEnv endp

MyProcAddress proc uses esi edi ebx hModule:dword, szName:dword
    mov eax, hModule
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add  eax, hModule
    assume eax:ptr IMAGE_NT_HEADERS
    
    lea eax, [eax].OptionalHeader.DataDirectory
    assume eax:ptr IMAGE_DATA_DIRECTORY
    mov edi, [eax].VirtualAddress
    
    add edi, hModule
    assume edi:ptr IMAGE_EXPORT_DIRECTORY
    
    mov esi, [edi].AddressOfNames
    add esi, hModule
    
    assume eax :nothing
       
    xor ebx, ebx
    .while TRUE 
        .if ebx >= [edi].nName
            .break
        .endif
        
        mov eax, dword ptr [esi + ebx* 4]
        add eax, hModule
        invoke MyStrcmp,eax, szName
        .if eax == 0
            mov eax, [edi].AddressOfNameOrdinals
            add eax, hModule
            movzx eax, word ptr [eax + ebx * 2]
            
            mov ebx, [edi].AddressOfFunctions
            add  ebx, hModule
            mov eax, dword ptr [ebx  + eax * 4]
            add eax, hModule
            ret
        .endif
        
        inc ebx
    .endw

    xor eax, eax
    ret
MyProcAddress endp

MyStrcmp proc  uses esi edi ebx szSrc:dword, szDst:dword
    mov esi, szSrc
    mov edi, szDst
    
loop1: 
    movzx eax, byte ptr [esi]
    movzx ebx, byte ptr [edi]
    cmp eax, ebx
    jnz  label1
    inc esi
    inc edi
    cmp eax, 0
    jnz loop1
    
 label1:
    sub eax, ebx
    ret
MyStrcmp endp

GetModuleBase proc
    assume fs:nothing
    mov eax, fs:[30h]
    mov eax, [eax+0ch]
    mov eax, [eax+0ch]
    mov eax, [eax+18h]
    ret
GetModuleBase endp

GetKernel32Base proc
    assume fs:nothing
    mov eax, fs:[30h]
    mov eax, [eax+0ch]
    mov eax, [eax+0ch]
    mov eax, [eax]
    mov eax, [eax]
    mov eax, [eax+18h]
    ret
GetKernel32Base endp

MyCopyMemory proc uses esi edi Dest:dword, Src:dword, Len:dword
    xor  ecx, ecx
    mov esi, Src
    mov edi, Dest
    .while ecx < Len
        mov al, byte ptr [esi]
        mov byte ptr [edi], al
        inc esi
        inc edi
        inc ecx
    .endw
    
    ret
MyCopyMemory endp

end start
