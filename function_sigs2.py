import logging
from binascii import crc_hqx as crc16
import angr
import capstone

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("angr2pat:generate_pattern")

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

    pattern = {
        "start_ea": func.addr,
        "end_ea": func.addr + func.size,
        "bytes": [],
        "variable_bytes": set(),
    }

    for ea in range(func.addr, func.addr + func.size):
        byte = proj.loader.memory.load(ea, 1)[0]
        pattern["bytes"].append(byte)
        if is_variable_byte(proj, ea, func):
            pattern["variable_bytes"].add(ea - func.addr)  

    return pattern

def save_pattern_to_file(patterns, file_path):
    with open(file_path, 'w') as f:
        for pattern in patterns:
            f.write(f"Start EA: {hex(pattern['start_ea'])}\n")
            f.write(f"End EA: {hex(pattern['end_ea'])}\n")
            f.write(f"Bytes: {' '.join(f'{b:02X}' for b in pattern['bytes'])}\n")
            f.write(f"Variable Bytes: {sorted(list(pattern['variable_bytes']))}\n")
            f.write("\n")

def generate_patterns(binary_path, output_file, min_func_length=10):
    proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
    cfg = proj.analyses.CFGFast()

    patterns = []
    for func_addr, func in cfg.functions.items():
        pattern = generate_pattern(proj, func, min_func_length)
        if pattern:
            patterns.append(pattern)

    save_pattern_to_file(patterns, output_file)

def make_func_sig(pattern):
    if pattern["end_ea"] - pattern["start_ea"] < 32:
        logger.debug("Function is too short")
        return None

    sig = ""
    variable_bytes = pattern.get("variable_bytes", set())
    num_bytes = min(32, len(pattern["bytes"]))

    for i in range(num_bytes):
        if i in variable_bytes:
            sig += ".."
        else:
            sig += "%02X" % pattern["bytes"][i]

    if num_bytes < 32:
        sig += ".." * (32 - num_bytes)

    crc_data = []
    for i in range(32, min(len(pattern["bytes"]), 32 + 255)):
        if i in variable_bytes:
            break
        crc_data.append(pattern["bytes"][i])

    if crc_data:
        crc = crc16(bytearray(crc_data), 0xFFFF)
        alen = len(crc_data)
    else:
        crc = 0
        alen = 0

    sig += " %02X" % alen
    sig += " %04X" % crc
    sig += " %08X" % (pattern["end_ea"] - pattern["start_ea"])

    return sig


def generate_signatures_from_patterns(pattern_file):
    patterns = []
    with open(pattern_file, 'r') as f:
        pattern = {}
        for line in f:
            if line.startswith("Start EA:"):
                if pattern: 
                    patterns.append(pattern)
                pattern = {
                    "start_ea": int(line.split(":")[1].strip(), 16),
                    "bytes": [],
                    "variable_bytes": set()
                }
            elif line.startswith("End EA:"):
                pattern["end_ea"] = int(line.split(":")[1].strip(), 16)
            elif line.startswith("Bytes:"):
                pattern["bytes"] = [int(b, 16) for b in line.split(":")[1].strip().split()]
            elif line.startswith("Variable Bytes:"):
                byte_list = line.split(":")[1].strip()
                if byte_list:
                    pattern["variable_bytes"] = set(int(b.strip()) for b in byte_list.strip('[]').split(',') if b.strip())

        if pattern:
            patterns.append(pattern)

    signatures = {}
    for pattern in patterns:
        sig = make_func_sig(pattern)
        if sig:
            signatures[pattern["start_ea"]] = sig

    return signatures


if __name__ == "__main__":
    binary_path = "/home/jahnvi/ASU-Internship/toy_program"
    output_file = "patterns.pat"
    generate_patterns(binary_path, output_file)
    signatures = generate_signatures_from_patterns(output_file)

    for start_ea, sig in signatures.items():
        print(f"Function start EA: {hex(start_ea)}, Signature: {sig}")

