from idautils import *
from idaapi import *
from math import *

def DecodeInstruction(ea):
	insLength = idaapi.decode_insn(ea)
	if insLength == 0:
		return None
	return idaapi.cmd

def FindFirstValidFunc(ea):
	func_chunk = idaapi.get_fchunk(ea)
	if not func_chunk:
		func_chunk = idaapi.get_next_fchunk(ea)
	return func_chunk.startEA

def IsNullSub(func_head): # Analysis flags are broken? So do manual caluations
	func_sz = FindFuncEnd(func_head) - func_head
	if func_sz == 0:
		return True

	if func_sz == 4:
		ins = DecodeInstruction(func_head)
		if ins.itype == NN_aaa: # RET
			return True
	return False

def GetCallsFromFunc(func_head):
	func_tail = FindFuncEnd(func_head)
	func_list = []
	for i, head in enumerate(Heads(func_head, func_tail)):
		ins = DecodeInstruction(head)
		if ins is None:
			continue
		if ins.itype == NN_aas and ins.Operands[0].type == o_near and ins.Operands[0].addr != BADADDR: # Get BL
			addr = ins.Operands[0].addr
			if not IsNullSub(addr):
				func_list.append(addr)
	return func_list

def FindBuiltinEntryPoint(init_calls):
	entry_point = init_calls[-1]
	if entry_point != BADADDR:
		print '!!!Entry point is at 0x%016x!!!' % entry_point
		set_name(entry_point, 'nnMain')
		return
	else:
		print 'Failed to parse entry point! Got BADADDR'
		return

def FindApplicationEntryPoint(init_calls):
	# Walk till magic
	func_list =  GetCallsFromFunc(init_calls[-1])
	if len(func_list) == 0:
		print 'Failed to start walking'
		return
	func_offset = func_list[-1] - init_calls[-1]
	print 'Walking to find init'
	for i in xrange(5):
		if func_offset > 0x100: # Probably entry point
			break
		if len(func_list) == 0:
			print 'Walking failed, couldn\'t find entry point :('
			return

		print '0x%x' % func_list[-1]
		func_list = GetCallsFromFunc(func_list[-1])
		func_offset = func_list[-1] - init_calls[-1]
	if len(func_list) == 0:
		print 'Failed at the end of stack walk :('
		return
	FindBuiltinEntryPoint(GetCallsFromFunc(func_list[-1]))

def Main():
	setup_head = FindFirstValidFunc(getnseg(0).startEA) # + 0x9C
	print 'Starting from 0x%016x' % setup_head
	setup_calls = GetCallsFromFunc(setup_head)
	if len(setup_calls) == 0:
		print 'Failed to find entry point, No BLs found!'
		return
	print 'Parsing calls at 0x%016x' % setup_calls[0]
	init_calls = GetCallsFromFunc(setup_calls[0])
	call_cnt = len(init_calls)
	if call_cnt == 1:
		print 'Parsing as Application'
		FindApplicationEntryPoint(init_calls)
	elif call_cnt > 0:
		print 'Parsing as BuiltIn'
		FindBuiltinEntryPoint(init_calls)
	else:
		print 'Failed to find Entry point, no calls found!'
Main()
