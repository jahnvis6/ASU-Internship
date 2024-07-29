import logging
from binascii import crc_hqx as crc16
import angr
import capstone

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("angr2sig")

def is_variable_byte(proj, addr, func):
    block = proj.factory.block(addr)
    if not block.capstone.insns:
        logger.debug(f"No instructions at address: {hex(addr)}")
        return False  

    inst = block.capstone.insns[0].insn  
    for op in inst.operands:
        if op.type == capstone.CS_OP_IMM:
            if not (func.addr <= op.imm < func.addr + func.size):
                return True
        if op.type == capstone.CS_OP_MEM:
            if op.mem.base == 0 and op.mem.index == 0:
                return True

    return False

def generate_pattern(proj, func, min_func_length=10):
    if func.size < min_func_length:
        logger.debug("Function is too short")
        return None

    variable_bytes = set()
    bytes_list = []
    referenced_names = {}

    for ea in range(func.addr, func.addr + func.size):
        byte = proj.loader.memory.load(ea, 1)[0]
        bytes_list.append(byte)
        if is_variable_byte(proj, ea, func):
            variable_bytes.add(ea - func.addr)

    if len(bytes_list) < 32:
        logger.debug("Function content is too short")
        return None

    pat = ""
    num_bytes = min(32, len(bytes_list))
    for i in range(num_bytes):
        if i in variable_bytes:
            pat += ".."
        else:
            pat += "%02X" % bytes_list[i]

    if num_bytes < 32:
        pat += ".." * (32 - num_bytes)

    crc_data = []
    for i in range(32, min(len(bytes_list), 32 + 255)):
        if i in variable_bytes:
            break
        crc_data.append(bytes_list[i])

    if crc_data:
        crc = crc16(bytearray(crc_data), 0xFFFF)
        alen = len(crc_data)
    else:
        crc = 0
        alen = 0

    for ea in range(func.addr, func.addr + func.size):
        block = proj.factory.block(ea)
        for insn in block.capstone.insns:
            for op in insn.insn.operands:
                if op.type in [capstone.CS_OP_IMM, capstone.CS_OP_MEM]:
                    addr = op.imm if op.type == capstone.CS_OP_IMM else op.mem.disp
                    symbol = proj.loader.find_symbol(addr)
                    if symbol:
                        offset = ea - func.addr
                        if symbol.name not in referenced_names or referenced_names[symbol.name] > offset:
                            referenced_names[symbol.name] = offset

    referenced_names_str = " ".join([f"^{offset:08X} {name}" for name, offset in sorted(referenced_names.items(), key=lambda item: item[1])])

    module_base = proj.loader.main_object.min_addr
    func_offset = func.addr - module_base
    public_name_str = f":{func_offset:08X} {func.name}"

    tail_bytes = bytes_list[32 + alen:]
    tail_pat = ''.join("..%02X" % b if i in variable_bytes else "%02X" % b for i, b in enumerate(tail_bytes, start=32 + alen))

    pat += f" {alen:02X} {crc:04X} {func.size:08X} {public_name_str} {referenced_names_str} {tail_pat}"

    return pat

def generate_patterns(binary_path, min_func_length=10):
    proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
    cfg = proj.analyses.CFGFast()

    patterns = {}
    for func_addr, func in cfg.functions.items():
        pat = generate_pattern(proj, func, min_func_length)
        if pat:
            patterns[func_addr] = pat

    return patterns

if __name__ == "__main__":
    binary_path = "/home/jahnvi/ASU-Internship/toy_program"
    patterns = generate_patterns(binary_path)
    for start_ea, pat in patterns.items():
        print(f"Function start EA: {hex(start_ea)}, Pattern: {pat}")

