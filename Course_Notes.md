# PE文件分析与压缩壳实现 学习笔记

---

## 第一部分：PE文件基础

### 第1课：PE文件结构概述

#### 1.1 什么是PE文件
PE（Portable Executable）是Windows平台的可执行文件格式，包括：
- .exe：可执行程序
- .dll：动态链接库
- .sys：系统驱动
- .ocx：ActiveX控件
- .scr：屏幕保护程序

#### 1.2 PE文件结构总览

```
┌─────────────────────────┐
│  DOS头 (DOS Header)      │
├─────────────────────────┤
│  DOS存根程序 (DOS Stub)  │
├─────────────────────────┤
│  NT头 (NT Header)        │
│  ├─ 文件头 (File Header)  │
│  └─ 可选头 (Optional Header)│
├─────────────────────────┤
│  节表 (Section Headers)  │
├─────────────────────────┤
│  节数据 (Section Data)   │
│  ├─ .text (代码节)       │
│  ├─ .data (数据节)       │
│  ├─ .rdata (只读数据)    │
│  └─ 其他节...            │
└─────────────────────────┘
```

#### 1.3 文件偏移与虚拟地址
- **文件偏移**：数据在文件中的实际位置
- **虚拟地址（VA）**：程序加载到内存后的地址
- **相对虚拟地址（RVA）**：相对于ImageBase的偏移
- **RAW**：节在文件中的位置

#### 1.4 stub-pack项目中的PE解析
在[Packer.h](file:///workspace/Packer.h#L129-L202)中，`ParsePe()`函数实现了PE文件的解析。

---

### 第2课：DOS头与NT头详解

#### 2.1 DOS头（IMAGE_DOS_HEADER）

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;        // 魔数，值为0x5A4D ("MZ")
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;       // NT头的文件偏移
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

**关键字段**：
- `e_magic`：必须为0x5A4D（"MZ"），用于标识有效的DOS程序
- `e_lfanew`：指向NT头的文件偏移，重要！

#### 2.2 DOS存根
- 是一个简单的16位DOS程序
- 当在DOS环境运行时，会显示"This program cannot be run in DOS mode"
- 在Windows环境下直接被跳过

#### 2.3 NT头（IMAGE_NT_HEADERS）

```c
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;                     // PE签名，0x00004550 ("PE\0\0")
    IMAGE_FILE_HEADER FileHeader;        // 文件头
    IMAGE_OPTIONAL_HEADER32 OptionalHeader; // 可选头（32位）
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

#### 2.4 文件头（IMAGE_FILE_HEADER）

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;               // 目标机器类型
    WORD  NumberOfSections;      // 节的数量
    DWORD TimeDateStamp;         // 时间戳
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;  // 可选头大小
    WORD  Characteristics;       // 文件特征
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

**关键字段**：
- `Machine`：0x14C表示x86，0x8664表示x64
- `NumberOfSections`：节的数量
- `Characteristics`：文件属性，如是否为可执行文件

#### 2.5 stub-pack中的应用
在[Packer.h](file:///workspace/Packer.h#L175-L199)中，我们可以看到如何获取和验证这些头部：

```cpp
m_dosHeader = (PIMAGE_DOS_HEADER)imageBase;
if (m_dosHeader->e_magic != 'ZM') {
    printf("Invalid PE File\n");
    return -1;
}

m_ntHeader = (PIMAGE_NT_HEADERS)(imageBase + m_dosHeader->e_lfanew);
if (m_ntHeader->Signature != 0x00004550) {
    printf("Invalid PE File\n");
    return -1;
}
```

---

### 第3课：节表与节属性

#### 3.1 节表结构（IMAGE_SECTION_HEADER）

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[IMAGE_SIZEOF_SHORT_NAME]; // 节名
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;              // 内存中的大小
    } Misc;
    DWORD VirtualAddress;               // 内存中的RVA
    DWORD SizeOfRawData;                // 文件中的大小
    DWORD PointerToRawData;             // 文件中的偏移
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;              // 节属性
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

#### 3.2 常见的节

| 节名 | 描述 | 典型属性 |
|-----|------|---------|
| .text | 代码节 | 可读可执行 |
| .data | 数据节 | 可读可写 |
| .rdata | 只读数据 | 只读 |
| .bss | 未初始化数据 | 不占用文件空间 |
| .idata | 导入表 | 只读 |
| .edata | 导出表 | 只读 |
| .reloc | 重定位表 | 只读 |
| .rsrc | 资源 | 只读 |

#### 3.3 节属性（Characteristics）

```c
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000
```

#### 3.4 stub-pack中的节表处理
在[Packer.h](file:///workspace/Packer.h#L204-L249)的`RebuildPe()`函数中，我们看到了如何创建新节：

```cpp
IMAGE_SECTION_HEADER oldSection = { 0 };
strcpy_s((char*)oldSection.Name, sizeof(oldSection.Name), ".old");
oldSection.Misc.VirtualSize = m_optionalHeader->SizeOfImage - GetSectionAlignment(m_optionalHeader->SizeOfHeaders);
oldSection.VirtualAddress = m_sectionHeader[0].VirtualAddress;
oldSection.SizeOfRawData = 0;
oldSection.PointerToRawData = 0;
oldSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

IMAGE_SECTION_HEADER packSection = { 0 };
strcpy_s((char*)packSection.Name, sizeof(oldSection.Name), ".pack");
// ... 设置其他字段
```

#### 3.5 对齐计算

**节对齐（Section Alignment）**：节在内存中的对齐单位

```cpp
DWORD GetSectionAlignment(DWORD size) {
    DWORD alignment = m_optionalHeader->SectionAlignment;
    DWORD alignmentSize = size / alignment * alignment;
    alignmentSize += (size % alignment != 0) ? alignment : 0;
    return alignmentSize;
}
```

**文件对齐（File Alignment）**：节在文件中的对齐单位

```cpp
DWORD GetFileAlignment(DWORD size) {
    DWORD alignment = m_optionalHeader->FileAlignment;
    DWORD alignmentSize = size / alignment * alignment;
    alignmentSize += (size % alignment != 0) ? alignment : 0;
    return alignmentSize;
}
```

---

### 第4课：数据目录详解

#### 4.1 数据目录结构

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;  // RVA
    DWORD Size;            // 大小
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

#### 4.2 数据目录索引

```c
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // 导出表
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // 导入表
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // 资源
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // 异常
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // 安全证书
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // 重定位表
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // 调试
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // 版权
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // 全局指针
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG     10  // 加载配置
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT    11  // 绑定导入
#define IMAGE_DIRECTORY_ENTRY_IAT             12  // IAT
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT    13  // 延迟导入
#define IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME     14  // CLR运行时
#define IMAGE_DIRECTORY_ENTRY_RESERVED        15  // 保留
```

#### 4.3 stub-pack中的数据目录处理
在[Packer.h](file:///workspace/Packer.h#L243)中，我们看到stub-pack清空了所有数据目录：

```cpp
memset(optionHeader->DataDirectory, 0, sizeof(optionHeader->DataDirectory));
```

这是因为在运行时，stub代码会重新修复这些表。

---

## 第二部分：PE文件高级特性

### 第5课：导入表与导出表

#### 5.1 导入表（Import Table）

导入表记录了程序依赖的动态链接库及其函数。

**导入表结构**：

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;  // INT（Import Name Table）的RVA
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;                    // DLL名称的RVA
    DWORD FirstThunk;              // IAT（Import Address Table）的RVA
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;
```

**INT与IAT**：
- **INT**（Import Name Table）：存储函数名称或序号
- **IAT**（Import Address Table）：存储函数地址（加载时填充）

#### 5.2 stub-pack中的导入表修复
在[StubCode.Asm](file:///workspace/StubCode.Asm#L230-L301)中，`FixImportTable`函数实现了导入表的修复：

```asm
FixImportTable proc uses esi edi ebx env:ptr PackEnv, imageBase:dword, buffer:dword
    ; 获取导入表的RVA
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
    
    ; 遍历每个导入描述符
    .while TRUE
        .if [esi].Name1 == 0
            .break
        .endif
        
        ; 加载DLL
        mov eax, [esi].Name1
        add eax, imageBase
        push eax
        mov ecx, env
        assume ecx:ptr PackEnv
        call [ecx].LoadLibraryAPtr
        mov @hModule, eax
        
        ; 处理函数导入
        .if @hModule != 0
            ; ... 获取函数地址并填充IAT
        .endif
        
        add esi, sizeof IMAGE_IMPORT_DESCRIPTOR
    .endw
    
    ret
FixImportTable endp
```

#### 5.3 导出表（Export Table）

导出表记录了DLL提供的导出函数。

**导出表结构**：

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // 导出函数地址数组的RVA
    DWORD   AddressOfNames;         // 函数名称数组的RVA
    DWORD   AddressOfNameOrdinals;  // 序号数组的RVA
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

---

### 第6课：重定位表

#### 6.1 为什么需要重定位？

当程序加载到内存的基址与预期的ImageBase不同时，就需要修复绝对地址引用，这就是重定位的作用。

#### 6.2 重定位表结构

```c
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
    // WORD  TypeOffset[1];  // 类型和偏移数组
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
```

**重定位类型**：
- 0：绝对（忽略）
- 1：高16位（用于16位代码）
- 2：低16位（用于16位代码）
- 3：高16位加低16位（用于32位代码）

#### 6.3 重定位计算

```
Delta = 实际基址 - ImageBase
需要重定位的地址 += Delta
```

#### 6.4 stub-pack中的重定位修复
在[StubCode.Asm](file:///workspace/StubCode.Asm#L302-L393)中，`FixRelTable`函数实现了重定位修复：

```asm
FixRelTable proc uses esi edi ebx env:ptr PackEnv, imageBase:dword, buffer:dword
    LOCAL @Delta:DWORD
    
    ; 计算Delta
    mov eax, buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, buffer
    assume eax:ptr IMAGE_NT_HEADERS
    
    mov eax, [eax].OptionalHeader.ImageBase
    mov ecx, imageBase
    sub ecx, eax
    mov @Delta, ecx
    
    ; 遍历重定位块
    .while TRUE
        mov eax, [esi].SizeOfBlock
        .if eax == 0
            .break
        .endif
        
        ; 处理每个重定位项
        .while ebx < ecx
            movzx eax, word ptr [edi]
            and eax, 0F000h
            .if eax == 3000h  ; 32位重定位
                ; 计算需要重定位的地址并修复
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
        
        add esi, eax
    .endw
    
    ret
FixRelTable endp
```

---

### 第7课：TLS表

#### 7.1 什么是TLS？

TLS（Thread Local Storage，线程局部存储）用于存储每个线程的独立数据。

#### 7.2 TLS表结构

```c
typedef struct _IMAGE_TLS_DIRECTORY {
    DWORD StartAddressOfRawData;
    DWORD EndAddressOfRawData;
    DWORD AddressOfIndex;
    DWORD AddressOfCallBacks;  // TLS回调函数数组的RVA
    DWORD SizeOfZeroFill;
    DWORD Characteristics;
} IMAGE_TLS_DIRECTORY, *PIMAGE_TLS_DIRECTORY;
```

#### 7.3 TLS回调函数

TLS回调函数在线程创建和退出时被调用，是壳程序常用的反调试手段。

**回调函数原型**：

```c
typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK)(
    PVOID DllHandle,
    DWORD Reason,
    PVOID Reserved
);
```

**Reason参数**：
- DLL_PROCESS_ATTACH：进程附加
- DLL_THREAD_ATTACH：线程附加
- DLL_THREAD_DETACH：线程分离
- DLL_PROCESS_DETACH：进程分离

#### 7.4 stub-pack中的TLS修复
在[StubCode.Asm](file:///workspace/StubCode.Asm#L394-L430)中，`FixTlsTable`函数实现了TLS修复：

```asm
FixTlsTable proc uses esi edi ebx imageBase:dword, buffer:dword
    mov eax, buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, buffer
    assume eax:ptr IMAGE_NT_HEADERS
    
    ; 获取TLS表
    mov eax, [eax].OptionalHeader.DataDirectory[9*8].VirtualAddress
    .if eax == 0
        ret
    .endif
    add eax, imageBase
    mov esi, eax
    assume esi:ptr IMAGE_TLS_DIRECTORY
    
    ; 获取回调函数数组
    mov eax, [esi].AddressOfCallBacks
    .if eax == 0
        ret
    .endif
    add eax, imageBase
    mov edi, eax
    
    ; 调用每个回调函数
    .while dword ptr [edi] != 0
        mov eax, dword ptr [edi]
        add eax, imageBase
        
        push NULL
        push 1  ; DLL_PROCESS_ATTACH
        push imageBase
        call eax
        
        add edi, 4
    .endw
    
    ret
FixTlsTable endp
```

---

### 第8课：PE文件加载流程

#### 8.1 Windows加载器工作流程

1. **验证文件**：检查PE签名、魔数等
2. **读取头部**：读取DOS头、NT头
3. **创建进程**：创建进程和主线程
4. **映射内存**：根据可选头信息将文件映射到内存
5. **加载依赖DLL**：递归加载所需的DLL
6. **修复导入表**：填充IAT
7. **处理重定位**：如果基址冲突，进行重定位
8. **初始化TLS**：设置线程局部存储
9. **调用入口点**：跳转到程序入口执行

#### 8.2 壳程序对加载流程的改变

加壳程序会改变正常的加载流程：

1. **壳程序先运行**：修改入口点指向stub代码
2. **stub解压**：stub代码在内存中解压原始程序
3. **修复各表**：stub代码手动修复导入表、重定位表、TLS表等
4. **跳转到原入口**：执行原始程序

---

## 第三部分：压缩壳原理

### 第9课：加壳技术概述

#### 9.1 什么是壳？

"壳"（Shell）是附加在程序上的一段代码，负责保护程序，在程序运行时先于程序执行，完成特定功能后将控制权交还给程序。

#### 9.2 壳的分类

**按功能分类**：
- **压缩壳**：减小程序体积，如UPX、PECompact
- **加密壳**：保护代码不被分析，如Themida、VMProtect
- **虚拟机壳**：将代码转换为虚拟指令，如VMProtect
- **反调试壳**：增加调试难度，如ASProtect

**按加壳时机分类**：
- **静态加壳**：程序运行前就完成加壳
- **动态加壳**：程序运行时动态加壳

#### 9.3 壳的基本原理

```
原始程序 → 压缩/加密 → 加壳程序
加壳程序运行 → 解压/解密 → 原始程序运行
```

#### 9.4 为什么要加壳？

- **减小体积**：压缩程序，方便分发
- **保护版权**：防止逆向工程
- **防止静态分析**：保护核心算法
- **防止恶意修改**：校验代码完整性
- **添加附加功能**：如授权验证、反调试

#### 9.5 stub-pack项目类型

stub-pack是一个典型的**压缩壳**，使用Windows内置压缩算法压缩原始程序，然后添加自解压stub代码。

---

### 第10课：压缩算法基础

#### 10.1 常见压缩算法

| 算法 | 压缩率 | 速度 | 特点 |
|-----|-------|------|------|
| LZ77/LZ78 | 中等 | 快 | 字典压缩，广泛使用 |
| LZW | 中等 | 快 | LZ78变种，GIF使用 |
| Huffman编码 | 中高 | 快 | 熵编码，常与其他算法结合 |
| DEFLATE | 高 | 中快 | LZ77+Huffman，ZIP使用 |
| XPress | 中 | 很快 | 微软开发，性能优异 |
| LZMA | 很高 | 慢 | 7-Zip使用，高压缩率 |

#### 10.2 Windows压缩API

Windows提供了压缩API（compressapi.h），支持多种算法：

```c
#define COMPRESS_ALGORITHM_INVALID    0
#define COMPRESS_ALGORITHM_MSZIP      1
#define COMPRESS_ALGORITHM_XPRESS     2
#define COMPRESS_ALGORITHM_XPRESS_HUFF 4
#define COMPRESS_ALGORITHM_LZMS       5
```

#### 10.3 stub-pack中的压缩实现
在[Packer.h](file:///workspace/Packer.h#L73-L127)中，`CompressorData()`函数实现了数据压缩：

```cpp
int CompressorData() {
    BOOL Success;
    
    // 1. 创建压缩器
    Success = CreateCompressor(
        COMPRESS_ALGORITHM_XPRESS_HUFF,
        NULL,                          
        &m_compressor);
    if (!Success) {
        printf("Cannot create a compressor %d.\n", GetLastError());
        return -1;
    }
    
    // 2. 获取压缩后大小
    Success = Compress(
        m_compressor,
        m_mapAddress,
        m_inputFileSize,
        NULL,
        0,
        &m_compressedBufferSize);
    if (!Success && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("Cannot compress data ErrCode:%d.\n", GetLastError());
        return -1;
    }
    
    // 3. 分配压缩缓冲区
    m_compressedBuffer = (PBYTE)malloc(m_compressedBufferSize);
    if (!m_compressedBuffer) {
        printf("Cannot allocate memory for compressed buffer.\n");
        return -1;
    }
    
    // 4. 执行压缩
    Success = Compress(
        m_compressor,
        m_mapAddress,
        m_inputFileSize,
        m_compressedBuffer,
        m_compressedBufferSize,
        &m_compressedDataSize);
    if (!Success) {
        printf("Cannot compress data: %d\n", GetLastError());
        return -1;
    }
    
    printf("Input file size: %d; Compressed Size: %d\n", m_inputFileSize, m_compressedDataSize);
    return 0;
}
```

---

### 第11课：自解压原理

#### 11.1 自解压程序架构

```
┌─────────────────────────┐
│  压缩程序头部            │
├─────────────────────────┤
│  stub代码（自解压程序）  │
├─────────────────────────┤
│  压缩后的原始数据        │
└─────────────────────────┘
```

#### 11.2 stub代码的职责

1. **初始化环境**：获取必要的系统函数
2. **定位数据**：找到压缩后的数据位置
3. **分配内存**：为解压数据分配空间
4. **执行解压**：使用解压器解压数据
5. **修复PE结构**：修复导入表、重定位表、TLS表等
6. **设置内存保护**：根据节属性设置内存保护
7. **转移控制权**：跳转到原始程序的入口点

#### 11.3 关键信息存储

在stub-pack中，使用`PackerInfo`结构存储关键信息：

```c
struct PackerInfo {
    DWORD version;
    DWORD oldEntryPoint;  // 原始程序入口点
    DWORD oldDataSize;    // 原始数据大小
    DWORD newDataSize;    // 压缩后大小
};
```

---

### 第12课：stub代码设计

#### 12.1 stub代码的设计原则

- **小体积**：stub代码本身要尽可能小
- **独立性**：尽量减少对外部函数的依赖
- **自包含**：包含必要的辅助函数
- **位置无关**：支持在任意地址运行（或重定位）
- **安全清理**：运行后清理踪迹，减少被分析的可能

#### 12.2 获取系统函数

stub代码需要动态获取必要的系统函数：

- `LoadLibraryA`：加载DLL
- `GetProcAddress`：获取函数地址
- `VirtualAlloc`：分配内存
- `VirtualFree`：释放内存
- `VirtualProtect`：修改内存保护
- `CreateDecompressor`：创建解压器
- `Decompress`：解压数据
- `CloseDecompressor`：关闭解压器

#### 12.3 stub-pack中的环境初始化
在[StubCode.Asm](file:///workspace/StubCode.Asm#L431-L512)中，`InitPackEnv`函数实现了环境初始化：

```asm
InitPackEnv proc env:ptr PackEnv
    LOCAL hKernel32:HANDLE
    LOCAL hCabinet:HANDLE
    
    mov esi, env
    assume esi:ptr PackEnv
    
    ; 获取Kernel32基址
    invoke GetKernel32Base
    mov hKernel32, eax
    
    ; 获取GetProcAddress
    lea eax, dword ptr [ebx + szGetProcAddress]
    invoke MyProcAddress, hKernel32, eax
    mov edi, eax
    mov [esi].GetProcAddressPtr, edi
    
    ; 获取其他函数
    lea eax, [ebx + offset szLoadLibraryA]
    push eax
    push hKernel32
    call edi
    mov [esi].LoadLibraryAPtr, eax
    
    ; ... 获取VirtualAlloc, VirtualFree, VirtualProtect
    
    ; 加载Cabinet.dll
    lea eax, [ebx + offset szCabinet]
    push eax
    call [esi].LoadLibraryAPtr
    mov hCabinet, eax
    
    ; 获取压缩相关函数
    lea eax, [ebx + offset szCreateDecompressor]
    push eax
    push hCabinet
    call edi
    mov [esi].CreateDecompressorPtr, eax
    
    ; ... 获取Decompress, CloseDecompressor
    
    ret
InitPackEnv endp
```

#### 12.4 自定义GetProcAddress

为了不依赖导入表，stub代码实现了自己的`MyProcAddress`函数：

```asm
MyProcAddress proc uses esi edi ebx hModule:dword, szName:dword
    ; 获取导出表
    mov eax, hModule
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, hModule
    assume eax:ptr IMAGE_NT_HEADERS
    
    lea eax, [eax].OptionalHeader.DataDirectory
    assume eax:ptr IMAGE_DATA_DIRECTORY
    mov edi, [eax].VirtualAddress
    
    add edi, hModule
    assume edi:ptr IMAGE_EXPORT_DIRECTORY
    
    ; 遍历导出名称
    mov esi, [edi].AddressOfNames
    add esi, hModule
    
    xor ebx, ebx
    .while TRUE
        .if ebx >= [edi].nName
            .break
        .endif
        
        ; 比较函数名
        mov eax, dword ptr [esi + ebx * 4]
        add eax, hModule
        invoke MyStrcmp, eax, szName
        .if eax == 0
            ; 找到函数，获取其地址
            mov eax, [edi].AddressOfNameOrdinals
            add eax, hModule
            movzx eax, word ptr [eax + ebx * 2]
            
            mov ebx, [edi].AddressOfFunctions
            add ebx, hModule
            mov eax, dword ptr [ebx + eax * 4]
            add eax, hModule
            ret
        .endif
        
        inc ebx
    .endw
    
    xor eax, eax
    ret
MyProcAddress endp
```

---

## 第四部分：压缩壳实现（基于stub-pack项目）

### 第13课：项目架构解析

#### 13.1 stub-pack项目结构

```
stub-pack/
├── Packer.cpp        # 主程序入口，处理命令行参数
├── Packer.h          # 核心打包逻辑实现（包含Packer类）
├── StubCode.Asm      # 汇编实现的自解压代码
└── README.md         # 项目说明文件
```

#### 13.2 项目工作流程

**打包阶段**：
1. 读取输入PE文件
2. 解析PE文件结构
3. 压缩整个PE文件
4. 重建PE文件结构
5. 创建新的PE文件
6. 写入压缩数据和stub代码

**运行阶段**：
1. stub代码先运行
2. 初始化环境
3. 解压原始PE文件到内存
4. 修复导入表、重定位表、TLS表
5. 恢复内存保护属性
6. 跳转到原始程序入口

#### 13.3 核心类：Packer

```cpp
class Packer {
private:
    // 输入输出文件
    std::string m_inputFile;
    std::string m_outputFile;
    
    // 文件映射相关
    HANDLE m_file;
    DWORD m_inputFileSize;
    HANDLE m_mapFile;
    LPVOID m_mapAddress;
    
    // 原始PE头
    PIMAGE_DOS_HEADER m_dosHeader;
    PIMAGE_NT_HEADERS m_ntHeader;
    PIMAGE_FILE_HEADER m_fileHeader;
    PIMAGE_OPTIONAL_HEADER32 m_optionalHeader;
    PIMAGE_SECTION_HEADER m_sectionHeader;
    
    // 新PE头
    IMAGE_DOS_HEADER m_newDosHeader;
    IMAGE_NT_HEADERS m_newNtHeader;
    std::vector<IMAGE_SECTION_HEADER> m_newSectionHeader;
    
    // 压缩相关
    COMPRESSOR_HANDLE m_compressor;
    DWORD m_compressedBufferSize;
    PVOID m_compressedBuffer;
    DWORD m_compressedDataSize;

public:
    // 构造/析构函数
    Packer(const std::string& inputFile, const std::string& outputFile);
    ~Packer();
    
    // 核心方法
    int pack();
    int ParsePe();
    int CompressorData();
    int RebuildPe();
    int CreateNewFile();
    DWORD GetSectionAlignment(DWORD size);
    DWORD GetFileAlignment(DWORD size);
};
```

---

### 第14课：PE文件解析与重建

#### 14.1 PE文件解析步骤

1. **打开文件**：使用CreateFile打开输入文件
2. **获取文件大小**：使用GetFileSizeEx获取文件大小
3. **创建文件映射**：使用CreateFileMapping创建内存映射
4. **映射视图**：使用MapViewOfFile获取内存指针
5. **解析头部**：获取DOS头、NT头、节表等

#### 14.2 代码实现（ParsePe）

```cpp
int ParsePe() {
    // 1. 打开文件
    m_file = CreateFile(m_inputFile.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (m_file == INVALID_HANDLE_VALUE) {
        printf("CreateFile ErrCode:%d\n", GetLastError());
        return -1;
    }
    
    // 2. 获取文件大小
    LARGE_INTEGER fileSize;
    GetFileSizeEx(m_file, &fileSize);
    m_inputFileSize = fileSize.LowPart;
    
    // 3. 创建文件映射
    m_mapFile = CreateFileMapping(
        m_file,
        NULL,                 
        PAGE_READWRITE,
        0,                    
        0,                    
        NULL);                
    if (m_mapFile == NULL) {
        printf("CreateFileMapping ErrCode:%d\n", GetLastError());
        return -1;
    }
    
    // 4. 映射视图
    m_mapAddress = (LPVOID)MapViewOfFile(m_mapFile,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        0);
    if (m_mapAddress == NULL) {
        printf("MapViewOfFile ErrCode:%d\n", GetLastError());
        return -1;
    }
    
    // 5. 解析头部
    char* imageBase = (char*)m_mapAddress;
    m_dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    if (m_dosHeader->e_magic != 'ZM') {
        printf("Invalid PE File\n");
        return -1;
    }
    
    m_ntHeader = (PIMAGE_NT_HEADERS)(imageBase + m_dosHeader->e_lfanew);
    if (m_ntHeader->Signature != 0x00004550) {
        printf("Invalid PE File\n");
        return -1;
    }
    
    m_fileHeader = &m_ntHeader->FileHeader;
    m_optionalHeader = &m_ntHeader->OptionalHeader;
    m_sectionHeader = (PIMAGE_SECTION_HEADER)((char*)m_fileHeader + 
        sizeof(IMAGE_FILE_HEADER) + m_fileHeader->SizeOfOptionalHeader);
    
    return 0;
}
```

#### 14.3 PE文件重建步骤

1. **复制并修改DOS头**：修改e_lfanew指向新的NT头位置
2. **复制并修改NT头**：修改节数量、SizeOfHeaders、入口点等
3. **创建新节表**：创建.old节和.pack节
4. **更新节属性**：设置节的虚拟地址、大小、属性等
5. **清空数据目录**：因为stub会在运行时修复

#### 14.4 代码实现（RebuildPe）

```cpp
int RebuildPe() {
    // 1. 复制DOS头并修改
    memcpy(&m_newDosHeader, m_dosHeader, sizeof(IMAGE_DOS_HEADER));
    m_newDosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER);
    
    // 2. 复制NT头
    memcpy(&m_newNtHeader, m_ntHeader, sizeof(IMAGE_NT_HEADERS));
    
    // 3. 修改节数量
    PIMAGE_FILE_HEADER fileHeader = &m_newNtHeader.FileHeader;
    fileHeader->NumberOfSections = 2;
    
    // 4. 创建.old节
    IMAGE_SECTION_HEADER oldSection = { 0 };
    strcpy_s((char*)oldSection.Name, sizeof(oldSection.Name), ".old");
    oldSection.Misc.VirtualSize = m_optionalHeader->SizeOfImage - GetSectionAlignment(m_optionalHeader->SizeOfHeaders);
    oldSection.VirtualAddress = m_sectionHeader[0].VirtualAddress;
    oldSection.SizeOfRawData = 0;
    oldSection.PointerToRawData = 0;
    oldSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    
    // 5. 创建.pack节
    IMAGE_SECTION_HEADER packSection = { 0 };
    strcpy_s((char*)packSection.Name, sizeof(oldSection.Name), ".pack");
    DWORD dataSize = sizeof(PackerInfo) + m_compressedDataSize + sizeof(g_stubCode);
    packSection.Misc.VirtualSize = GetSectionAlignment(dataSize);
    packSection.VirtualAddress = oldSection.VirtualAddress + oldSection.Misc.VirtualSize;
    packSection.SizeOfRawData = GetFileAlignment(dataSize);
    packSection.PointerToRawData = GetFileAlignment(sizeof(IMAGE_DOS_HEADER) + 
        sizeof(IMAGE_NT_HEADERS) + 2 * sizeof(IMAGE_SECTION_HEADER));
    packSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    
    // 6. 添加到新节表
    m_newSectionHeader.push_back(oldSection);
    m_newSectionHeader.push_back(packSection);
    
    // 7. 更新可选头
    PIMAGE_OPTIONAL_HEADER optionHeader = &m_newNtHeader.OptionalHeader;
    optionHeader->SizeOfHeaders = packSection.PointerToRawData;
    optionHeader->SizeOfImage = oldSection.Misc.VirtualSize + packSection.Misc.VirtualSize + GetSectionAlignment(optionHeader->SizeOfHeaders);
    
    // 8. 清空数据目录
    memset(optionHeader->DataDirectory, 0, sizeof(optionHeader->DataDirectory));
    
    // 9. 设置新的入口点
    optionHeader->AddressOfEntryPoint = m_newSectionHeader[1].VirtualAddress +
        sizeof(PackerInfo) + m_compressedDataSize;
    
    return 0;
}
```

---

### 第15课：数据压缩实现

#### 15.1 压缩流程

1. **创建压缩器**：使用CreateCompressor创建压缩器
2. **获取压缩后大小**：先调用一次Compress获取所需大小
3. **分配缓冲区**：分配足够的压缩缓冲区
4. **执行压缩**：再次调用Compress执行实际压缩
5. **记录压缩信息**：保存压缩后的数据和大小

#### 15.2 代码实现（CompressorData）

```cpp
int CompressorData() {
    BOOL Success;
    
    // 1. 创建压缩器
    Success = CreateCompressor(
        COMPRESS_ALGORITHM_XPRESS_HUFF,
        NULL,                          
        &m_compressor);
    if (!Success) {
        printf("Cannot create a compressor %d.\n", GetLastError());
        return -1;
    }
    printf("CreateCompressor m_compressor:%p.\n", m_compressor);
    
    // 2. 获取压缩后大小
    Success = Compress(
        m_compressor,
        m_mapAddress,
        m_inputFileSize,
        NULL,
        0,
        &m_compressedBufferSize);
    if (!Success && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("Cannot compress data ErrCode:%d.\n", GetLastError());
        return -1;
    }
    
    // 3. 分配压缩缓冲区
    m_compressedBuffer = (PBYTE)malloc(m_compressedBufferSize);
    if (!m_compressedBuffer) {
        printf("Cannot allocate memory for compressed buffer.\n");
        return -1;
    }
    
    // 4. 执行压缩
    ULONGLONG StartTime = GetTickCount64();
    Success = Compress(
        m_compressor,
        m_mapAddress,
        m_inputFileSize,
        m_compressedBuffer,
        m_compressedBufferSize,
        &m_compressedDataSize);
    if (!Success) {
        printf("Cannot compress data: %d\n", GetLastError());
        return -1;
    }
    ULONGLONG EndTime = GetTickCount64();
    double TimeDuration = (EndTime - StartTime) / 1000.0;
    
    printf("Input file size: %d; Compressed Size: %d\n", m_inputFileSize, m_compressedDataSize);
    printf("Compression Time (Exclude I/O): %.2f seconds\n", TimeDuration);
    printf("File Compressed.\n");
    
    return 0;
}
```

#### 15.3 压缩算法选择

stub-pack使用`COMPRESS_ALGORITHM_XPRESS_HUFF`，原因：
- 压缩速度快
- 解压速度快
- Windows原生支持，无需额外依赖
- 压缩率适中

---

### 第16课：自解压代码实现

#### 16.1 StubEntry函数流程

这是stub代码的主函数，协调整个解压过程：

1. **初始化打包环境**
2. **获取模块基地址**
3. **定位PackerInfo结构**
4. **创建解压器**
5. **分配内存并解压数据**
6. **修复内存保护属性**
7. **复制解压后的数据到正确位置**
8. **修复导入表、重定位表、TLS表**
9. **恢复原始入口点并执行**

#### 16.2 代码实现（StubEntry）

```asm
StubEntry proc
    LOCAL @Env:PackEnv
    LOCAL @Decompressor:HANDLE
    LOCAL @PackerInfo:ptr PackerInfo
    LOCAL @ImageBase:DWORD
    LOCAL @Buffer:dword
    LOCAL @Size:dword
    LOCAL @OldProto:dword
    
    ; 1. 初始化环境
    invoke InitPackEnv, addr @Env
    
    ; 2. 获取模块基地址
    invoke GetModuleBase
    mov @ImageBase, eax
    
    ; 3. 定位PackerInfo
    mov eax, @ImageBase
    assume eax:ptr IMAGE_DOS_HEADER
    mov eax, [eax].e_lfanew
    add eax, @ImageBase
    assume eax:ptr IMAGE_NT_HEADERS
    lea ebx, [eax].OptionalHeader
    movzx eax, [eax].FileHeader.SizeOfOptionalHeader
    add ebx, eax
    
    assume ebx:ptr IMAGE_SECTION_HEADER
    add ebx, sizeof IMAGE_SECTION_HEADER
    mov eax, [ebx].VirtualAddress
    add eax, @ImageBase
    mov @PackerInfo, eax
    
    ; 4. 创建解压器
    lea eax, @Decompressor
    push eax
    push NULL
    push COMPRESS_ALGORITHM_XPRESS_HUFF
    call @Env.CreateDecompressorPtr
    
    ; 5. 分配内存并解压
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
    
    ; 6. 修复内存保护，复制数据
    lea eax, @OldProto
    push eax
    push PAGE_EXECUTE_READWRITE
    push 1000h
    push @ImageBase
    call @Env.VirtualProtectPtr
    
    invoke MyCopyMemory, @ImageBase, @Buffer, 1000h
    
    ; 7. 复制节数据
    mov eax, @Buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov esi, [eax].e_lfanew
    add esi, @Buffer
    assume esi:ptr IMAGE_NT_HEADERS
    lea ebx, [esi].OptionalHeader
    movzx eax, [esi].FileHeader.SizeOfOptionalHeader
    add ebx, eax
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
        
        ; 设置内存保护
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
    
    ; 8. 修复各表
    invoke FixImportTable, addr @Env, @ImageBase, @Buffer
    invoke FixRelTable, addr @Env, @ImageBase, @Buffer
    invoke FixTlsTable, @ImageBase, @Buffer
    
    ; 9. 恢复节属性
    mov eax, @Buffer
    assume eax:ptr IMAGE_DOS_HEADER
    mov esi, [eax].e_lfanew
    add esi, @Buffer
    assume esi:ptr IMAGE_NT_HEADERS
    lea ebx, [esi].OptionalHeader
    movzx eax, [esi].FileHeader.SizeOfOptionalHeader
    add ebx, eax
    assume ebx:ptr IMAGE_SECTION_HEADER
    
    xor cx, cx
    .while cx < [esi].FileHeader.NumberOfSections
        push ecx
        
        lea eax, @OldProto
        push eax
        
        ; 根据节属性设置正确的内存保护
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
    
    ; 10. 清理资源
    push @Decompressor
    call @Env.CloseDecompressorPtr
    
    push MEM_RELEASE
    push 0
    push @Buffer
    call @Env.VirtualFreePtr
    
    ; 11. 返回原始入口点
    mov esi, @PackerInfo
    assume esi:ptr PackerInfo
    mov eax, [esi].oldEntryPoint
    add eax, @ImageBase
    
    ret
StubEntry endp
```

---

### 第17课：新文件创建

#### 17.1 创建新PE文件步骤

1. **创建输出文件**：使用CreateFile创建新文件
2. **写入DOS头**：写入修改后的DOS头
3. **写入NT头**：写入修改后的NT头
4. **写入节表**：写入新的节表
5. **定位到节数据位置**：设置文件指针到pack节的Raw位置
6. **写入PackerInfo**：写入关键信息结构
7. **写入压缩数据**：写入压缩后的原始PE数据
8. **写入stub代码**：写入自解压代码
9. **填充对齐**：写入零字节以达到文件对齐

#### 17.2 代码实现（CreateNewFile）

```cpp
int CreateNewFile() {
    // 1. 创建输出文件
    HANDLE handle = CreateFile(m_outputFile.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        printf("CreateFile ErrCode:%d\n", GetLastError());
        return -1;
    }
    printf("CreateFile handle:%p\n", handle);
    
    DWORD writeBytes = 0;
    
    // 2. 写入DOS头
    if (!WriteFile(handle, &m_newDosHeader, sizeof(m_newDosHeader), &writeBytes, NULL)
        || writeBytes != sizeof(m_newDosHeader)) {
        return -1;
    }
    
    // 3. 写入NT头
    if (!WriteFile(handle, &m_newNtHeader, sizeof(m_newNtHeader), &writeBytes, NULL)
        || writeBytes != sizeof(m_newNtHeader)) {
        return -1;
    }
    
    // 4. 写入节表
    if (!m_newSectionHeader.empty()) {
        if (!WriteFile(handle, &m_newSectionHeader[0],
            m_newSectionHeader.size() * sizeof(IMAGE_SECTION_HEADER), &writeBytes, NULL)
            || writeBytes != m_newSectionHeader.size() * sizeof(IMAGE_SECTION_HEADER)) {
            return -1;
        }
    }
    
    // 5. 定位到节数据位置
    SetFilePointer(handle, m_newNtHeader.OptionalHeader.SizeOfHeaders, 0, FILE_BEGIN);
    
    // 6. 写入PackerInfo
    PackerInfo info;
    info.version = 1;
    info.oldEntryPoint = m_optionalHeader->AddressOfEntryPoint;
    info.oldDataSize = m_inputFileSize;
    info.newDataSize = m_compressedDataSize;
    if (!WriteFile(handle, &info,
        sizeof(info), &writeBytes, NULL)
        || writeBytes != sizeof(info)) {
        return -1;
    }
    
    // 7. 写入压缩数据
    if (!WriteFile(handle, m_compressedBuffer,
        m_compressedDataSize, &writeBytes, NULL)
        || writeBytes != m_compressedDataSize) {
        return -1;
    }
    
    // 8. 写入stub代码
    if (!WriteFile(handle, g_stubCode,
        sizeof(g_stubCode), &writeBytes, NULL)
        || writeBytes != sizeof(g_stubCode)) {
        return -1;
    }
    
    // 9. 填充对齐
    DWORD size = sizeof(info) + m_compressedDataSize + sizeof(g_stubCode);
    DWORD zeroSize = GetFileAlignment(size) - size;
    char zero = 0;
    for (DWORD i = 0; i < zeroSize; i++) {
        WriteFile(handle, &zero, sizeof(zero), &writeBytes, NULL);
    }
    
    // 10. 关闭文件
    CloseHandle(handle);
    return 0;
}
```

---

### 第18课：项目实战与优化

#### 18.1 编译项目

**前置条件**：
- Visual Studio（支持MASM）
- Windows SDK

**编译步骤**：

1. 创建Visual Studio C++项目
2. 将[Packer.cpp](file:///workspace/Packer.cpp)、[Packer.h](file:///workspace/Packer.h)、[StubCode.Asm](file:///workspace/StubCode.Asm)添加到项目
3. 配置项目属性：
   - 配置为Release x86
   - 启用MASM编译
   - 链接Cabinet.lib
4. 编译生成

#### 18.2 使用项目

```bash
packer.exe input.exe output.exe
```

#### 18.3 测试加壳程序

1. 使用PEiD等工具检测加壳
2. 运行加壳程序，验证功能正常
3. 使用调试器观察stub代码的运行过程
4. 比较加壳前后的文件大小

#### 18.4 优化建议

**功能扩展**：
1. **支持64位PE文件**：扩展代码以支持x64架构
2. **多种压缩算法**：添加不同压缩算法的选项
3. **加密功能**：在压缩基础上添加加密
4. **添加反调试**：提高分析难度
5. **添加完整性检查**：防止程序被修改

**性能优化**：
1. **增量压缩**：只压缩代码和数据部分
2. **优化压缩参数**：调整压缩参数平衡体积和速度
3. **优化stub代码**：减小stub体积
4. **内存优化**：减少内存使用峰值

**安全加固**：
1. **代码混淆**：混淆stub代码
2. **反虚拟机**：添加VM检测
3. **多态变形**：每次生成不同的stub
4. **IAT加密**：加密导入地址表

#### 18.5 常见问题与解决

| 问题 | 可能原因 | 解决方案 |
|-----|---------|---------|
| 程序运行崩溃 | 重定位表修复有误 | 检查重定位修复代码 |
| 程序无法启动 | 导入表修复有误 | 检查导入表修复代码 |
| 特定程序加壳失败 | 特殊PE结构 | 添加对该结构的支持 |
| 杀毒软件报毒 | 加壳特征被识别 | 改变加壳特征，添加签名 |

---

## 附录

### A. 推荐工具

| 工具名 | 用途 |
|-------|------|
| PEiD | PE文件分析、查壳 |
| CFF Explorer | PE文件编辑、分析 |
| x64dbg/x32dbg | 动态调试 |
| IDA Pro | 静态分析、反汇编 |
| PE-bear | PE文件分析 |
| 010 Editor | 十六进制编辑器（有PE模板） |

### B. 推荐阅读

- 《Windows PE权威指南》
- 《加密与解密（第三版）》
- 《Professional Assembly Language》
- 《Windows Internals》系列
- MSDN PE文件格式文档

### C. 进阶学习方向

1. **逆向工程**：深入学习逆向分析技术
2. **恶意代码分析**：学习恶意代码分析方法
3. **漏洞分析与利用**：研究漏洞挖掘与利用
4. **加壳与脱壳**：深入研究各类加壳技术
5. **虚拟机保护**：研究基于虚拟机的保护技术

---

## 总结

通过本系列课程的学习，我们系统地掌握了：

1. **PE文件结构**：从DOS头到节表，从数据目录到加载流程
2. **压缩壳原理**：压缩算法、自解压技术、stub设计
3. **实战实现**：基于stub-pack项目，完整实现了一个压缩壳

这只是逆向工程和安全研究的入门，还有很多高级技术等待我们探索。希望本课程能为你打开这扇门，祝你学习愉快！