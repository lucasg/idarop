""" IDA ROP view plugin rop search engine and processing """

# Python libraries
import binascii
import sys
import logging
from struct import pack, unpack
from collections import namedtuple

# IDA libraries
import idaapi
import idc

if idaapi.IDA_SDK_VERSION <= 695:
    from idaapi import get_segm_qty, getnseg
if idaapi.IDA_SDK_VERSION >= 700:
    from ida_segment import get_segm_qty, getnseg
else:
    pass

###############################################################################
# Data Structure class

class SegmentEntry(namedtuple('Segment','name start end size r w x segclass')):
    """ Segment entry container for listing segments and characteristics  """

    __slots__ = ()

    def get_display_list(self):
        """ Return the display format list for the segment listing """
        return [ self.name ,
                 "%08X" % self.start,
                 "%08X" % self.end,
                 "%08X" % self.size,
                 (".", "R")[self.r],
                 (".", "W")[self.w],
                 (".", "X")[self.x],
                 self.segclass]

class Gadget(namedtuple('Gadget', 'address ret_address instructions opcodes size')):
    """ Gadget element container for rop listing and export to csv """

    __slots__ = ()

    def get_display_list(self, address_format):
        """ Return the display format list for the rop gadget listing """
        txt_instructions = " ; ".join(self.instructions)
        txt_opcodes = " ".join("%02x" % ord(op) for op in self.opcodes)
        return [ idc.SegName(self.address),
                 address_format % self.address, 
                 address_format % self.ret_address, 
                 txt_instructions,
                 txt_opcodes,
                 "%d" % len(self.opcodes), 
                 ("N", "Y")["sp" in txt_instructions]
                 ]



# ROP Search Engine
class IdaRopSearch():

    def __init__(self, sploiter):
        
        self.maxRopOffset = 40 # Maximum offset from the return instruction to look for gadgets. default: 40
        self.maxRopSize   = 6  # Maximum number of instructions to look for gadgets. default: 6
        self.maxRetnImm   = 64 # Maximum imm16 value in retn. default: 64
        self.maxJopImm    = 255 # Maximum jop [reg + IMM] value. default: 64
        self.maxRops      = 0  # Maximum number of ROP chains to find. default: 0 (unlimited)

        self.debug        = False

        self.regnames     = idaapi.ph_get_regnames()

        self.sploiter     = sploiter
        self.retns        = list()
        self.gadgets      = list()

        # Decoded instruction cache
        self.insn_cache = dict()

        # Extra bytes to read to ensure correct decoding of
        # RETN, RETN imm16, CALL /2, and JMP /4 instructions.
        self.dbg_read_extra = 6 # FF + ModR/M + SIB + disp32 

        self.insn_arithmetic_ops = ["inc","dec","neg", "add","sub","mul","imul","div","idiv","adc","sbb","lea"]
        self.insn_bit_ops = ["not","and","or","xor","shr","shl","sar","sal","shld","shrd","ror","rcr","rcl"]

    def get_o_reg_name(self, insn, n):

        reg_num = insn.Operands[n].reg
        reg_name = self.regnames[reg_num]

        # NOTE: IDA's x86/x86-64 regname array contains only register root names
        #       (e.g ax,cx,dx,etc.). However we can still figure out exact register
        #       size by looking at the operand 'dtyp' property.
        if reg_num < 8:

            # 32-bit register
            if insn.Operands[n].dtyp == idaapi.dt_dword:
                reg_name = 'e'+reg_name

            # 64-bit register
            elif insn.Operands[n].dtyp == idaapi.dt_qword:
                reg_name = 'r'+reg_name

            # 16-bit register otherwise

        return reg_name

    def search_retns(self):

        self.retns = list()

        # Iterate over segments in the module
        # BUG: Iterating over all loaded segments is more stable than looking up by address
        for n in self.segments:
            segment = getnseg(n)

            # Locate executable segments in a selected modules
            # NOTE: Each module may have multiple executable segments
            if segment and segment.perm & idaapi.SEGPERM_EXEC:
               
                #######################################################
                # Search for ROP gadgets
                self.search_rop_gadgets(segment, ret_preamble = 0xc3 ) # RETN 
                self.search_rop_gadgets(segment, ret_preamble = 0xcb ) # RETF
                self.search_rop_gadgets(segment, ret_preamble = 0xc2 ) # RETN imm16
                self.search_rop_gadgets(segment, ret_preamble = 0xca ) # RETN imm16
                self.search_rop_gadgets(segment, ret_preamble = 0xf2c3 ) # MPX RETN 
                self.search_rop_gadgets(segment, ret_preamble = 0xf2c2 ) # MPX RETN imm16

                #######################################################
                # Search for JOP gadgets
                self.search_job_gadgets(segment, jump_preamble = 0xff )
                self.search_job_gadgets(segment, jump_preamble = 0xf2ff ) # MPX
                
                #######################################################
                # Search for SYS gadgets
                self.search_sys_gadgets(segment)

        print("[IdaRopSearch] Found %d returns" % len(self.retns))


    def is_job_gadget(self, jop):
        """ jump oriented gadget predicate """

        ###################################################
        # JMP/CALL reg
        if jop[0] in ["\xe0","\xe1","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7",
                      "\xd0","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6","\xd7"]:
            return True

        ###################################################
        # JMP/CALL [reg] no SIB
        # NOTE: Do not include pure [disp] instruction.

        # JMP/CALL [reg] no *SP,*BP
        elif jop[0] in ["\x20","\x21","\x22","\x23","\x26","\x27", 
                        "\x10","\x11","\x12","\x13","\x16","\x17"]:
            return True

        # JMP/CALL [reg + imm8] no *SP
        elif jop[0] in ["\x60","\x61","\x62","\x63","\x65","\x66","\x67",
                        "\x50","\x51","\x52","\x53","\x55","\x56","\x57"]:
            jop_imm8 = jop[1]
            jop_imm8 = unpack("b", jop_imm8)[0] # signed

            if jop_imm8 <= self.maxJopImm:
                return True


        # JMP/CALL [reg + imm32] no *SP
        elif jop[0] in ["\xa0","\xa1","\xa2","\xa3","\xa5","\xa6","\xa7",
                        "\x90","\x91","\x92","\x93","\x95","\x96","\x97"]:
            jop_imm32 = jop[1:5]
            jop_imm32 = unpack("<i", jop_imm32)[0] # signed

            if jop_imm32 <= self.maxJopImm:
                return True

        ###################################################
        # JMP/CALL [reg] with SIB
        # NOTE: Do no include pure [disp] instructions in SIB ([*] - none)
        elif (jop[0] in ["\x24","\x64","\xa4"] and not jop[1] in ["\x25","\x65","\xad","\xe5"]) or \
             (jop[0] in ["\x14","\x54","\x94"] and not jop[1] in ["\x25","\x65","\xad","\xe5"]):

             # Check for displacement
            if jop[0] in ["\x64","\x54"]:
                jop_imm8 = jop[2]
                jop_imm8 = unpack("b", jop_imm8)[0] # signed

                if jop_imm8 <= self.maxJopImm:
                    return True


            elif jop[0] in ["\xa4","\x94"]:
                jop_imm32 = jop[2:6]
                jop_imm32 = unpack("<i", jop_imm32)[0] # signed

                if jop_imm32 <= self.maxJopImm:
                    return True


            else:
                return True

        return False

    def is_sys_gadget(self, sys_op):
        """ syscall oriented gadget predicate """

        if sys_op[0] in [
            b"\xcd\x80",                         # int 0x80
            b"\x0f\x34",                         # sysenter
            b"\x0f\x05",                         # syscall
            b"\x65\xff\x15\x10\x00\x00\x00",     # call DWORD PTR gs:0x10
            b"\xcd\x80\xc3",                     # int 0x80 ; ret
            b"\x0f\x34\xc3",                     # sysenter ; ret
            b"\x0f\x05\xc3",                     # syscall ; ret
            b"\x65\xff\x15\x10\x00\x00\x00\xc3", # call DWORD PTR gs:0x10 ; ret
        ]:
            return True

        return False

    def search_job_gadgets(self, segment, jump_preamble = 0xFF):
        """ Search for JMP/J(.*) jump gadgets """

        # Nothing to do if the option is not set
        if not self.searchJop:
            return

        # Search all instances of JMP reg (FF /4) and CALL reg (FF /2)
        ea = segment.startEA
        while True:

            ea = idaapi.find_binary(ea + 1, segment.endEA, "%X" % jump_preamble, 16, idaapi.SEARCH_DOWN)
            if ea == idaapi.BADADDR: 
                break

            # Read possible ModR/M, SIB, and IMM8/IMM32 bytes
            jop = idc.GetManyBytes(ea + 1, self.maxRopSize)

            if self.is_job_gadget(jop):
                self.retns.append((ea))

    def search_sys_gadgets(self, segment, jump_preamble = 0xFF):
        """ Search for SYS jump gadgets """

        # Nothing to do if the option is not set
        if not self.searchSys:
            return

        # Search all instances of JMP reg (FF /4) and CALL reg (FF /2)
        ea = segment.startEA
        while True:

            ea = idaapi.find_binary(ea + 1, segment.endEA, "%X" % jump_preamble, 16, idaapi.SEARCH_DOWN)
            if ea == idaapi.BADADDR: 
                break

            # Read possible ModR/M, SIB, and IMM8/IMM32 bytes
            sys_op = idc.GetManyBytes(ea + 1, self.maxRopSize)

            if self.is_sys_gadget(jop):
                self.retns.append((ea))

    def search_rop_gadgets(self, segment, ret_preamble = 0xc3):
        """ Search for rop gadgets """

        # Nothing to do if the option is not set
        if not self.searchRop:
            return
            
        ea = segment.startEA
        while True:

            ea = idaapi.find_binary(ea + 1, segment.endEA, "%X" % ret_preamble, 16, idaapi.SEARCH_DOWN)
            if ea == idaapi.BADADDR: 
                break

            if ret_preamble in [ 0xc2, 0xca, 0xf2c2]:

                 # Read imm16 value and filter large values
                retn_imm16 = idc.Word(ea + 1)
                if retn_imm16 <= self.maxRetnImm:
                    self.retns.append((ea))
            else:
                self.retns.append( (ea))

            

    def search_gadgets(self):

        count_total = len(self.retns)
        count_notify = 0
        count_curr  = 0

        # BUG: A separate flag is used to track user canceling the search,
        #      because multiple calls to idaapi.wasBreak() do not properly
        #      detect cancellations.
        breakFlag = False

        # Show wait dialog
        if not self.debug: 
            idaapi.show_wait_box("Searching gadgets: 00 %")

        try :

        
            for ea_end in self.retns:

                # Flush the gadgets cache for each new retn pointer
                self.gadgets_cache = dict()

                # Flush memory cache for each new retn pointer
                self.dbg_mem_cache = None

                # CACHE: It is faster to read as much memory in one blob than to make incremental reads backwards.
                #        Try to read and cache self.maxRopOffset bytes back. In cases where it is not possible,
                #        then simply try to read the largest chunk.
                
                # NOTE: Read a bit extra to cover correct decoding of RETN, RETN imm16, CALL /2, and JMP /4 instructions.
                # Bug on end of segments : self.dbg_read_extra must be 0
                dbg_read_extra = self.dbg_read_extra
                seg_start, seg_end = idc.SegStart(ea_end), idc.SegEnd(ea_end)
                if ea_end + dbg_read_extra > seg_end:
                    dbg_read_extra = 0

                for i in range(self.maxRopOffset):
                    self.dbg_mem_cache = idc.GetManyBytes(ea_end - self.maxRopOffset + i, self.maxRopOffset - i + self.dbg_read_extra)
                    if self.dbg_mem_cache != None:
                        break

                # Error while reading memory (Ida sometimes does not want to read uninit data)
                if self.dbg_mem_cache == None:
                    for backward_size in range(self.maxRopOffset, 0, -1):
                        self.dbg_mem_cache = idc.GetManyBytes(ea_end - backward_size, backward_size)
                        if self.dbg_mem_cache != None:
                            break

                # Big problem ahead
                if self.dbg_mem_cache == None:
                    logging.error("[Ida Search Error] could not read bytes [0x%x, 0x%x]" % (ea_end - self.maxRopOffset + i, ea_end - self.maxRopOffset + i + self.maxRopOffset - i + self.dbg_read_extra))
                
                # Search all possible gadgets up to maxoffset bytes back
                # NOTE: Try all byte combinations to capture longer/more instructions
                #       even with bad bytes in the middle.
                for i in range(1, len(self.dbg_mem_cache) - self.dbg_read_extra):

                    ea = ea_end - i

                    # Try to build a gadget at the pointer
                    gadget = self.build_gadget(ea, ea_end)
                    
                    # Successfully built the gadget
                    if gadget:

                        # Filter gadgets with too many instruction
                        if gadget.size > self.maxRopSize: 
                            break

                        # Append newly built gadget
                        self.gadgets.append(gadget)
                        self.gadgets_cache[ea] = gadget

                        # Exceeded maximum number of gadgets
                        if self.maxRops and len(self.gadgets) >= self.maxRops:
                            breakFlag = True
                            print("[Ida Rop] Maximum number of gadgets exceeded.")
                            break
                    else:
                        self.gadgets_cache[ea] = None

                    if breakFlag or idaapi.wasBreak():
                        breakFlag = True
                        break


                # Canceled
                # NOTE: Only works when started from GUI not script.
                if breakFlag or idaapi.wasBreak():
                    breakFlag = True
                    print ("[IdaRopSearch] Canceled.")
                    break

                # Progress report
                if not self.debug and count_curr >= count_notify:

                    # NOTE: Need to use %%%% to escape both Python and IDA's format strings
                    percent_progression = count_curr*100/count_total
                    progression_str = """Searching gadgets: {progression:02d} %""".format(progression = percent_progression)
                    idaapi.replace_wait_box(progression_str) 

                    count_notify += 0.10 * count_total

                count_curr += 1            

            print ("[IdaRopSearch] Found %d gadgets." % len(self.gadgets))
        except:
            logging.error ("[IdaRopSearch] Exception raised while search for gadgets : %s." % sys.exc_info())
            pass

        finally:

            if not self.debug:
                idaapi.hide_wait_box()


    # Attempt to build a gadget at the provided start address
    # by verifying it properly terminates at the expected RETN.
    def build_gadget(self, ea, ea_end):

        instructions  = list()
        chg_registers = set()
        use_registers = set()
        operations    = set()
        pivot         = 0
        start_ea = ea

        # Process each instruction in the gadget
        while ea <= ea_end:

            ###################################################################
            # Gadget Level Cache:
            #
            # Locate a gadget (failed or built) starting at this address.
            # If one is located, then we don't need to process any further
            # instructions and just get necessary data from the cached
            # gadget to never have to process the same address twice.
            if ea in self.gadgets_cache:

                # Check if the gadget was build successfully
                gadget_cache = self.gadgets_cache[ea]
                
                # Build the reset of the gadget from cache
                if gadget_cache:    

                    for insn in gadget_cache.instructions:
                        instructions.append(insn)

                    #pivot += gadget_cache.pivot
                    opcodes = idc.GetManyBytes(start_ea, ea_end - start_ea + 1)
                    
                    gadget = Gadget(
                        address = start_ea,
                        ret_address = ea_end,
                        instructions = instructions,
                        opcodes = opcodes,
                        size = len(opcodes), 
                        #pivot = pivot
                        )

                    return gadget

                # Previous attempt to build gadget at this address failed
                else:
                    return None

            # Process new instruction
            else:

                # Instruction length
                # NOTE: decode_insn also sets global idaapi.cmd
                #       which contains insn_t structure
                insn_size = idaapi.decode_insn(ea)

                # Check successful decoding of the instruction
                if insn_size:

                    # Decoded instruction is too big to be a RETN or RETN imm16
                    if ea + insn_size > ea_end + self.dbg_read_extra:
                        return None

                    ###############################################################
                    # Instruction Level Cache
                    #
                    # Most instructions are repetitive so we can just cache
                    # unique byte combinations to avoid costly decoding more
                    # than once
                    
                    # Read instruction from memory cache
                    dbg_mem_offset = ea - (ea_end - (len(self.dbg_mem_cache) - self.dbg_read_extra) )
                    dbg_mem = self.dbg_mem_cache[dbg_mem_offset:dbg_mem_offset + insn_size]

                    # Create instruction cache if it doesn't already exist
                    if not dbg_mem in self.insn_cache:

                        ###########################################################
                        # Decode instruction
                        ###########################################################

                        # Get global insn_t structure describing the instruction
                        # NOTE: copy() is expensive, so we keep this single-threaded
                        insn = idaapi.cmd                  

                        #######################################################
                        # Decode and Cache instruction characteristics
                        self.insn_cache[dbg_mem] = self.decode_instruction(insn, ea, ea_end)

                    ##################################################################
                    # Retrieve cached instruction and apply it to the gadget    

                    # Check that cached instruction contains valid data
                    if self.insn_cache[dbg_mem]:

                        # Retrieve basic instruction characteristics
                        insn_mnem = self.insn_cache[dbg_mem]["insn_mnem"]
                        insn_disas = self.insn_cache[dbg_mem]["insn_disas"]
                        instructions.append(insn_disas)

                        #######################################################
                        # Expected ending instruction of the gadget
                        if ea == ea_end:
                            opcodes = idc.GetManyBytes(start_ea, ea_end - start_ea + 1)
                            
                            gadget = Gadget(
                                address = start_ea,
                                ret_address = ea_end,
                                instructions = instructions,
                                opcodes = opcodes,
                                size = len(opcodes), 
                                #pivot = pivot
                                )
                            return gadget

                        #######################################################
                        # Filter out of place ROP/JOP/COP terminators
                        # NOTE: retn/jmp/call are allowed, but only in the last position

                        # Unexpected return instruction
                        elif insn_mnem == "retn":
                            return None

                        # Unexpected call/jmp instruction
                        elif insn_mnem in ["jmp","call"]:
                            return None

                        #######################################################
                        # Add instruction instruction characteristics to the gadget
                        else:

                            for reg in self.insn_cache[dbg_mem]["insn_chg_registers"]:
                                chg_registers.add(reg)

                            for reg in self.insn_cache[dbg_mem]["insn_use_registers"]:
                                use_registers.add(reg)

                            for op in self.insn_cache[dbg_mem]["insn_operations"]:
                                operations.add(op)

                            pivot += self.insn_cache[dbg_mem]["insn_pivot"]

                    # Previous attempt to decode the instruction invalidated the gadget
                    else:                        
                        return None
                        
                    ###############################################################
                    # Next instruction
                    # NOTE: This is outside cache
                    ea += insn_size

                ###################################################################
                # Failed decoding of the instruction
                # NOTE: Gadgets may have bad instructions in the middle which
                #       can be tolerated as long as we can find a useful instruction
                #       further out.
                else:

                    # HACK: IDA does not disassemble "\x00\x00" unless you enable
                    #       "Disassemble zero opcode instructions" in Processor Options.
                    #       Since this option is normally disabled, I will attempt
                    #       to get this instruction manually.

                    # Read two bytes from memory cache at current instruction candidate
                    dbg_mem_offset = ea - (ea_end - self.maxRopOffset)
                    dbg_mem = self.dbg_mem_cache[dbg_mem_offset:dbg_mem_offset + 2]

                    # Compare to two zero bytes
                    if dbg_mem[:2] == "\x00\x00":

                        if self.sploiter.addr64:
                            instructions.append("add [rax],al")
                        else:
                            instructions.append("add [eax],al")

                        use_registers.add("al")
                        operations.add("reg-to-mem")

                        ea += 2

                    # "MOV Sreg, r/m16" instructions will result in illegal instruction exception: c000001d
                    # or the memory couldn't be read exception: c0000005 which we don't want in our gadgets.
                    elif len(dbg_mem) and dbg_mem[0] == "\x8E":
                        return None

                    # Record a "bad byte" if allowed
                    elif dbg_mem and not self.ropNoBadBytes:
                        byte = dbg_mem[0]

                        instructions.append("db %sh" % binascii.hexlify(byte))

                        ea += 1

                    # Invalidate the gadget
                    else:
                        return None

        # Failed to build a gadget, because RETN instruction was not found
        else:    
            return None

    ###############################################################
    # Decode instruction

    def decode_instruction(self, insn, ea, ea_end):

        # Instruction specific characteristics
        insn_chg_registers = set()
        insn_use_registers = set()
        insn_operations = set()
        insn_pivot = 0

        # Instruction feature
        #
        # instruc_t.feature
        #
        # CF_STOP = 0x00001 #  Instruction doesn't pass execution to the next instruction
        # CF_CALL = 0x00002 #  CALL instruction (should make a procedure here)
        # CF_CHG1 = 0x00004 #  The instruction modifies the first operand
        # CF_CHG2 = 0x00008 #  The instruction modifies the second operand
        # CF_CHG3 = 0x00010 #  The instruction modifies the third operand
        # CF_CHG4 = 0x00020 #  The instruction modifies 4 operand
        # CF_CHG5 = 0x00040 #  The instruction modifies 5 operand
        # CF_CHG6 = 0x00080 #  The instruction modifies 6 operand
        # CF_USE1 = 0x00100 #  The instruction uses value of the first operand
        # CF_USE2 = 0x00200 #  The instruction uses value of the second operand
        # CF_USE3 = 0x00400 #  The instruction uses value of the third operand
        # CF_USE4 = 0x00800 #  The instruction uses value of the 4 operand
        # CF_USE5 = 0x01000 #  The instruction uses value of the 5 operand
        # CF_USE6 = 0x02000 #  The instruction uses value of the 6 operand
        # CF_JUMP = 0x04000 #  The instruction passes execution using indirect jump or call (thus needs additional analysis)
        # CF_SHFT = 0x08000 #  Bit-shift instruction (shl,shr...)
        # CF_HLL  = 0x10000 #  Instruction may be present in a high level language function.
        insn_feature = insn.get_canon_feature()

        # Instruction mnemonic name
        insn_mnem = insn.get_canon_mnem()

        #if insn_mnem in self.mnems: self.mnems[insn_mnem] += 1
        #else:                       self.mnems[insn_mnem]  = 1

        # Get instruction operand types
        #
        # op_t.type
        #                    Description                          Data field
        # o_void     =  0 #  No Operand                           ----------
        # o_reg      =  1 #  General Register (al,ax,es,ds...)    reg
        # o_mem      =  2 #  Direct Memory Reference  (DATA)      addr
        # o_phrase   =  3 #  Memory Ref [Base Reg + Index Reg]    phrase
        # o_displ    =  4 #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
        # o_imm      =  5 #  Immediate Value                      value
        # o_far      =  6 #  Immediate Far Address  (CODE)        addr
        # o_near     =  7 #  Immediate Near Address (CODE)        addr
        insn_op1 = insn.Operands[0].type
        insn_op2 = insn.Operands[1].type

        ###############################################################
        # Filter gadget
        ###############################################################

        # Do not filter ROP, JOP, COP, always decode them
        # NOTE: A separate check must be done to check if they are out of place.
        if not insn_mnem in ["retn","jmp","call"]:

            # Filter gadgets with instructions that don't forward execution to the next address
            if insn_feature & idaapi.CF_STOP:
                return None

            # Filter gadgets with instructions in a bad list
            elif insn_mnem in self.ropBadMnems:
                return None

            # Filter gadgets with jump instructions
            # Note: conditional jumps may still be useful if we can
            #       set flags prior to calling them.
            elif not self.ropAllowJcc and insn_mnem[0] == "j":
                return None

        ###############################################################
        # Get disassembly
        ###############################################################
        # NOTE: GENDSM_FORCE_CODE ensures correct decoding
        #       of split instructions.
        insn_disas = idc.GetDisasmEx(ea, idaapi.GENDSM_FORCE_CODE)                
        insn_disas = insn_disas.partition(';')[0]       # Remove comments from disassembly                       
        insn_disas = ' '.join(insn_disas.split())       # Remove extraneous space from disassembly

        ###############################################################
        # Analyze instruction
        ###############################################################

        # Standalone instruction
        if insn_op1 == idaapi.o_void:

            # TODO: Determine and test how these instructions affect the stack
            #       in 32-bit and 64-bit modes.
            if insn_mnem in ["pusha","pushad","popa","popad","pushf","pushfd","pushfq","popf","popfd","popfq"]:
                insn_operations.add("stack")

                if insn_mnem in ["popa","popad"]:
                    insn_pivot += 7*4
                elif insn_mnem in ["pusha","pushad"]:
                    insn_pivot -= 8*4
                elif insn_mnem in ["popf","popfd"]:
                    insn_pivot += 4
                elif insn_mnem in ["pushf","pushfd"]:
                    insn_pivot -= 4
                elif insn_mnem == "popfq":  # TODO: Needs testing
                    insn_pivot += 8
                elif insn_mnem == "pushfq": # TODO: Needs testing
                    insn_pivot -= 8

        # Single operand instruction
        elif insn_op2 == idaapi.o_void:

            # Single operand register
            if insn_op1 == idaapi.o_reg:
                insn_operations.add("one-reg")

                if insn_feature & idaapi.CF_CHG1:
                    reg_name = self.get_o_reg_name(insn, 0)
                    insn_chg_registers.add(reg_name)

                    # Check for stack operation
                    if reg_name[1:] == "sp":
                        insn_operations.add("stack")

                        if insn_mnem == "inc":
                            insn_pivot += 1

                        elif insn_mnem == "dec":
                            insn_pivot -= 1

                elif insn_feature & idaapi.CF_USE1:
                    reg_name = self.get_o_reg_name(insn, 0)
                    insn_use_registers.add(reg_name)

            # Single operand immediate
            elif insn_op1 == idaapi.o_imm:
                insn_operations.add("one-imm")

            # Single operand reference
            # TODO: determine the [reg + ...] value if present
            elif insn_op1 == idaapi.o_phrase or insn_op1 == idaapi.o_displ:
                insn_operations.add("one-mem")

            # PUSH/POP mnemonic with a any operand type
            if insn_mnem in ["push","pop"]:
                insn_operations.add("stack")

                # Adjust pivot based on operand size (32bit vs 64bit)
                if insn_mnem == "pop":
                    if   insn.Operands[0].dtyp == idaapi.dt_dword: insn_pivot += 4
                    elif insn.Operands[0].dtyp == idaapi.dt_qword: insn_pivot += 8
                elif insn_mnem == "push":                   
                    if   insn.Operands[0].dtyp == idaapi.dt_dword: insn_pivot -= 4
                    elif insn.Operands[0].dtyp == idaapi.dt_qword: insn_pivot -= 8

            # Check for arithmetic operation:
            if insn_mnem in self.insn_arithmetic_ops:
                insn_operations.add("math")

            # Check for bit-wise operations:
            if insn_mnem in self.insn_bit_ops:
                insn_operations.add("bit")

        # Two operand instruction
        else:

            # Check for arithmetic operations
            if insn_mnem in self.insn_arithmetic_ops:
                insn_operations.add("math")

            # Check for bit-wise operations
            if insn_mnem in self.insn_bit_ops:
                insn_operations.add("bit")

            # Two operand instruction with the first operand a register
            if insn_op1 == idaapi.o_reg:

                reg_name = self.get_o_reg_name(insn, 0)

                if insn_feature & idaapi.CF_CHG1:
                    insn_chg_registers.add(reg_name)

                    # Check for stack operation
                    if reg_name[1:] == "sp":
                        insn_operations.add("stack")

                        # Determine stack pivot distance
                        if insn_op2 == idaapi.o_imm:

                            # NOTE: adb and sbb may also be useful, but let the user
                            #       determine their use by locating the operations "stack"
                            if insn_mnem == "add":
                                insn_pivot += insn.Operands[1].value

                            elif insn_mnem == "sub":
                                insn_pivot -= insn.Operands[1].value

                    # Check for operations
                    if insn_op2 == idaapi.o_reg:
                        insn_operations.add("reg-to-reg")
                    elif insn_op2 == idaapi.o_imm:
                        insn_operations.add("imm-to-reg")

                    # TODO: determine the [reg + ...] value if present
                    elif insn_op2 == idaapi.o_phrase or insn_op2 == idaapi.o_displ:
                        insn_operations.add("mem-to-reg")

                if insn_feature & idaapi.CF_USE1:
                    insn_use_registers.add(reg_name)


            # Two operand instruction with the second operand a register
            if insn_op2 == idaapi.o_reg:

                reg_name = self.get_o_reg_name(insn, 1)

                if insn_feature & idaapi.CF_CHG2:
                    insn_chg_registers.add(reg_name)

                    # Check for stack operation
                    if reg_name[1:] == "sp":
                        insn_operations.add("stack")

                if insn_feature & idaapi.CF_USE2:
                    insn_use_registers.add(reg_name)

                # Check for operations
                # TODO: determine the [reg + ...] value if present
                if insn_op1 == idaapi.o_phrase or insn_op1 == idaapi.o_displ:
                    insn_operations.add("reg-to-mem")

        # Build instruction dictionary
        insn = dict()
        insn["insn_mnem"] = insn_mnem
        insn["insn_disas"] = insn_disas
        insn["insn_operations"] = insn_operations
        insn["insn_chg_registers"] = insn_chg_registers
        insn["insn_use_registers"] = insn_use_registers
        insn["insn_pivot"] = insn_pivot

        return insn


class IdaRopEngine():
    """ Ida ROP Engine class for process all kinds of data """

    def __init__(self):
        self.rop  = None

        if not idaapi.ph.id == idaapi.PLFM_386:
            logging.error ("[IdaRop] Only Intel 80x86 processors are supported.")
            sys.exit(1)

        # Check if processor supports 64-bit addressing
        if idaapi.ph.flag & idaapi.PR_USE64:
            self.addr64 = True
            self.addr_format = "%016X"
            self.pack_format_be = ">Q"
            self.pack_format_le = "<Q"
        else:
            self.addr64 = False
            self.addr_format = "%08X"
            self.pack_format_be = ">I"
            self.pack_format_le = "<I"

    def list_segments(self):
        """ Return the list of segments in the current binary and their characteristics """
        
        self.segments = list()
        self.segments_idx = list()


        for n in xrange(get_segm_qty()):
            seg = getnseg(n)

            if not seg: 
                continue

            # For some linux binaries
            # Ida does not recognize the segment
            # permissions (usually for plt)
            if seg.perm == 0:
                continue

            segentry = SegmentEntry(
                name = idaapi.get_segm_name(seg),
                start = seg.startEA,
                end = seg.endEA,
                size = seg.size(),
                r = (seg.perm & idaapi.SEGPERM_READ) >> 2,
                w = (seg.perm & idaapi.SEGPERM_WRITE) >> 1,
                x = (seg.perm & idaapi.SEGPERM_EXEC),
                segclass = idaapi.get_segm_class(seg)
            )

            self.segments.append(segentry) 
            self.segments_idx.append(n)

        return self.segments

    def clear_rop_list(self):
        """ Clear previous rop search results """
        self.rop.gadgets = list()

    def process_rop(self, form,  select_list = None):
        """ Look for rop gadgets using user-input search options """
        
        # Clear previous results
        self.clear_rop_list()
        
        # Get selected segments
        self.rop.segments = [self.segments_idx[i] for i in select_list]

        if len(self.rop.segments) > 0:

            # Filter bad characters
            buf                    = form.strBadChars.value
            buf = buf.replace(' ','')         # remove spaces
            buf = buf.replace('\\x','')       # remove '\x' prefixes
            buf = buf.replace('0x','')        # remove '0x' prefixes
            try:
                buf = binascii.unhexlify(buf) # convert to bytes
                self.ptrBadChars   = buf
            except Exception as e:
                idaapi.warning("Invalid input: %s" % e)
                self.ptrBadChars   = ""

            # Ascii_to_Unicode_transformation table
            # BUG: DropdownControl does not work on IDA 6.5
            self.unicodeTable      = form.radUnicode.value

            # ROP instruction filters
            self.rop.ropBadMnems   = [mnem.strip().lower() for mnem in form.strBadMnems.value.split(',')]
            self.rop.ropAllowJcc   = form.cRopAllowJcc.checked
            self.rop.ropNoBadBytes = form.cRopNoBadBytes.checked

            # Get ROP engine settings
            self.rop.maxRopSize    = form.intMaxRopSize.value
            self.rop.maxRopOffset  = form.intMaxRopOffset.value
            self.rop.maxRops       = form.intMaxRops.value
            self.rop.maxRetnImm    = form.intMaxRetnImm.value

            # Gadget search values
            self.rop.searchRop     = form.cRopSearch.checked
            self.rop.searchJop     = form.cJopSearch.checked
            self.rop.searchSys     = form.cSysSearch.checked 

            # Search for returns and ROP gadgets
            self.rop.search_retns()
            self.rop.search_gadgets()

            return True

        else:
            idaapi.warning("No segments selected.")
            return False

       