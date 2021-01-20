from idautils import *
from idaapi import *
from math import *

def get_string(addr):
    out = ""
    while True:
        if Byte(addr) != 0:
            out += chr(Byte(addr))
        else:
            break
        addr += 1
    return out

def DecodeInstruction(ea):
	insLength = idaapi.decode_insn(ea)
	if insLength == 0:
		return None
	return idaapi.cmd

def GetFuncStart(ea):
    return GetFunctionAttr(ea, FUNCATTR_START)

def GetFuncEnd(ea):
    return PrevHead(GetFunctionAttr(here(), FUNCATTR_END))

def trace_register_to_call(ea):
    func_end = GetFuncEnd(ea)
    cur_ea = NextHead(ea)
    current_reg = 'X0'
    while cur_ea < func_end:
        if GetMnem(cur_ea) == 'MOV':
            dst = GetOpnd(cur_ea, 0)
            src = GetOpnd(cur_ea, 1)
            if src == current_reg:
                current_reg = dst
        if GetMnem(cur_ea) == 'BL':
            if current_reg == 'X1':
                return idc.GetOperandValue(cur_ea, 0)
        cur_ea = NextHead(cur_ea)
    return 0x0

def search_for_page_base(ea_base):
    page_base = 0x0
    ea = ea_base + 0
    func_start = GetFuncStart(ea_base)
    while ea > func_start:
        if GetMnem(ea) == 'ADRP':
            return idc.GetOperandValue(ea, 1)
        ea = PrevHead(ea)


def ArgumentToStr(ea):
    if GetMnem(ea) == 'ADD':
        # print("page_base", hex(search_for_page_base(ea)))
        off = idc.GetOperandValue(ea, 2)
        str_addr = off + search_for_page_base(ea)
        return get_string(str_addr)
    else:
        print('Unhandled instruction type %d'%ins.itype)
        return None

def Name_NVN_functions(nvnLoadCProcs):
    ea = GetFuncStart(nvnLoadCProcs)
    func_tail = GetFuncEnd(nvnLoadCProcs)
    
    str_tbl = []
    func_tbl = []
    page_base = 0x0

    while ea < func_tail:
        if GetMnem(ea) == 'ADRP':
            page_base = idc.GetOperandValue(ea, 1)
        elif GetMnem(ea) == 'ADD' and page_base != 0x0:
            addr = idc.GetOperandValue(ea, 2) + page_base
            str_tbl.append(get_string(addr))
        elif GetMnem(ea) == 'LDR':
            func_tbl.append(idc.GetOperandValue(ea, 1) + page_base)
        ea = NextHead(ea)
    assert len(str_tbl) == len(func_tbl)
    count = len(str_tbl)
    print('Found %d nvn funcs! Naming now...'%len(str_tbl))

    used_nvn_funcs = []
    for i in range(count):
        print('%016x -> f_%s'%(func_tbl[i], str_tbl[i]))
        MakeNameEx(func_tbl[i], 'f_' + str_tbl[i], 0)
        MakeNameEx(Qword(func_tbl[i]), 'o_' + str_tbl[i], 0)
        cnt = 0
        for xref in XrefsTo(func_tbl[i], 0):
            cnt+= 1
        if cnt > 2:
            used_nvn_funcs.append([func_tbl[i], 'f_' + str_tbl[i], (cnt / 2) - 1])
    print('-'*16)
    print('Used NVN Funcs: ')
    for f in used_nvn_funcs:
        print('%016x: %s - Used %d times'%(f[0], f[1], f[2]))


def LocateArg1(ea):
    func_start = GetFuncStart(ea)
    cur_ea = PrevHead(ea)
    target_reg = 'X0'
    if GetMnem(cur_ea) == 'MOV':
        if GetOpnd(cur_ea, 0) == 'X0':
            target_reg = GetOpnd(cur_ea, 1)
    while cur_ea > func_start:
        if GetMnem(cur_ea) == 'ADD':
            dst = GetOpnd(cur_ea, 0)
            if dst == target_reg:
                return idc.GetOperandValue(cur_ea, 2) + search_for_page_base(cur_ea)
        cur_ea = PrevHead(cur_ea)
    return 0x0

def Main():
    ea = getnseg(0).startEA # Text
    print(hex(ea))
    nvnBootstrapLoader = 0x0
    nvnBootstrapLoader_fallback = 0x0
    for ea in Segments():
        for funcea in Functions(ea, SegEnd(ea)):
            name = GetFunctionName(funcea)
            if name == 'nvnBootstrapLoader':
                nvnBootstrapLoader = funcea
                break
            if 'nvnbootstraploader' in name.lower():
                nvnBootstrapLoader_fallback = funcea
    if nvnBootstrapLoader == 0x0:
        print('Failed to locate nvnBootstrapLoader!')
        if nvnBootstrapLoader_fallback != 0x0:
            print('Using fallback...')
            nvnBootstrapLoader = nvnBootstrapLoader_fallback
        else:
            return
    print('Found nvnBootstrapLoader @ 0x%016x'%nvnBootstrapLoader)
    SetType(nvnBootstrapLoader, 'uint64_t __fastcall nvnBootstrapLoader(const char *nvnName)')

    nvnDeviceGetProcAddress = 0x0
    Jump(nvnBootstrapLoader)
    for xref in XrefsTo(nvnBootstrapLoader, 0):
        print('Scanning xref 0x%016x'%xref.frm)
        Jump(xref.frm)
        arg0 = LocateArg1(xref.frm)
        if arg0 == 0x0:
            continue
        nvn_str = get_string(arg0)
        print('Bootstrap call for %s'%nvn_str)
        if nvn_str == 'nvnDeviceGetProcAddress':
            nvnDeviceGetProcAddress = xref.frm
            print('nvnDeviceGetProcAddress @ 0x%016x'%nvnDeviceGetProcAddress)
            Jump(nvnDeviceGetProcAddress)
    if nvnDeviceGetProcAddress == 0x0:
        print('Failed to locate nvnDeviceGetProcAddress!')
        return
    nvnLoadCProcs = trace_register_to_call(nvnDeviceGetProcAddress)
    if nvnLoadCProcs == 0x0:
        print("Failed to locate nvnLoadCProcs! Trying fallback")
        return
    print('nvnLoadCProcs @ 0x%016x'%nvnLoadCProcs)
    Jump(nvnLoadCProcs)
    MakeNameEx(nvnLoadCProcs, 'nvnLoadCProcs', 0)
    SetType(nvnLoadCProcs, 'void __fastcall nvnLoadCProcs(void *device, void *get_proc)')
    Name_NVN_functions(nvnLoadCProcs)
    print('nvnLoadCProcs @ 0x%016x'%nvnLoadCProcs)
    print('Done!')
Main()
