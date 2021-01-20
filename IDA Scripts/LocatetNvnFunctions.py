from idautils import *
from idaapi import *
from math import *

def DecodeInstruction(ea):
	insLength = idaapi.decode_insn(ea)
	if insLength == 0:
		return None
	return idaapi.cmd

def WalkStringsBack(ea):
    offset = 0
    last_valid_offset = 0
    while True:
        offset += 1
        c = Byte(ea - offset)
        if c == 0:
            continue
        elif c >= 65:
            last_valid_offset = offset
        else:
            break
    return ea - last_valid_offset

def BuildStringTable(base_ea):
    string_table = []
    offset = 0
    last = Byte(base_ea)
    cur_str = ''
    while True:
        c = Byte(base_ea + offset)
        if last == 0 and c == 0:
            break

        if c == 0:
            string_table.append(cur_str)
            cur_str = '' 
        else:
            cur_str += chr(c)
        
        last = c
        offset += 1
    return string_table

def LocateNvnFunctionTable(base_ea):
    DeviceGetProcAddress = 0x0
    func_tail = FindFuncEnd(base_ea)
    for i, head in enumerate(Heads(base_ea, func_tail)):
        ins = DecodeInstruction(head)
        if ins is None:
            continue
        if ins.itype == ARM_b:
            DeviceGetProcAddress = ins.Operands[0].addr
            break
    if DeviceGetProcAddress == 0x0:
        return 0x0
    
    page_base = 0x0
    GetProcAddressOffset = 0x0
    func_tail = FindFuncEnd(DeviceGetProcAddress)
    for i, head in enumerate(Heads(DeviceGetProcAddress, func_tail)):
        ins = DecodeInstruction(head)
        if ins is None:
            continue
        if ins.itype == ARM_adrp:
            page_base = ins.Operands[1].value
        
        if ins.itype == ARM_ldr:
            if page_base != 0x0:
                GetProcAddressOffset = ins.Operands[1].addr + page_base
                break
    if GetProcAddressOffset == 0x0:
        return 0x0
    
    GetProcAddress = Qword(Qword(GetProcAddressOffset))
    NVNFunctionVTable = 0x0
    need_update = False
    # Last ADRP is our vtable
    func_tail = FindFuncEnd(GetProcAddress)
    for i, head in enumerate(Heads(GetProcAddress, func_tail)):
        ins = DecodeInstruction(head)
        if ins is None:
            continue
        if ins.itype == ARM_adrp:
            page_base = ins.Operands[1].value
            need_update = True
        
        if ins.itype == ARM_ldr and need_update:
            if page_base != 0x0:
                need_update = False
                NVNFunctionVTable = ins.Operands[1].addr + page_base
    if NVNFunctionVTable == 0x0:
        return 0x0
    return Qword(NVNFunctionVTable)
    

def Main():
    base_ea = 0x0
    sc = Strings()
    for s in sc:
        if(str(s) == "CommandBufferBindTexture"):
            print('Found base str @ %016x'%s.ea)
            base_ea = s.ea
            break
    if base_ea == 0x0:
        print("Failed to location NVN functions!")
        return
    
    nvn_func_string_table_offset = WalkStringsBack(base_ea)
    print('NVN String Table @ %016x'%nvn_func_string_table_offset)
    nvn_func_string_table = BuildStringTable(nvn_func_string_table_offset)
    print("String table built, searching for function vtable...")

    text_off = getnseg(0).startEA
    nvnBootstrapLoaderInternal = 0x0
    for funcAddr in Functions(SegStart(text_off), SegEnd(text_off)):
        funcName = GetFunctionName(funcAddr)
        if funcName == 'nvnBootstrapLoaderInternal':
            nvnBootstrapLoaderInternal = funcAddr
            break
    if nvnBootstrapLoaderInternal == 0x0:
        print("Failed to locate nvnBootstrapLoaderInternal")
        return
    print('Found nvnBootstrapLoaderInternal @ %016x'%nvnBootstrapLoaderInternal)
    nvn_func_table = LocateNvnFunctionTable(nvnBootstrapLoaderInternal)
    if nvn_func_table == 0x0:
        print("Failed to locate nvn functions table!")
        return
    print('Found NVN Function table @ %016x'%nvn_func_table)

    for i in xrange(len(nvn_func_string_table)):
        offset = nvn_func_table + (i * 8)
        addr_offset = get_qword(offset)
        MakeName(offset, '')
        MakeName(addr_offset, "nvn" + nvn_func_string_table[i])
        print("nvn" + nvn_func_string_table[i], '%016x'%addr_offset)
    MakeName(nvn_func_table, 'NvnCommandList')
    print('Done!')
Main()
