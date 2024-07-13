import angr
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("angr2pat:generate_pattern")

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

    return pattern

def save_pattern_to_file(patterns, file_path):
    with open(file_path, 'w') as f:
        for pattern in patterns:
            f.write(f"Start EA: {hex(pattern['start_ea'])}\n")
            f.write(f"End EA: {hex(pattern['end_ea'])}\n")
            f.write(f"Bytes: {' '.join(f'{b:02X}' for b in pattern['bytes'])}\n")
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

if __name__ == "__main__":
    binary_path = "/home/jahnvi/ASU-Internship/toy_program"
    output_file = "patterns.pat"
    generate_patterns(binary_path, output_file)

import logging
from binascii import crc_hqx as crc16

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("pat2sig:make_func_sig")

def load_patterns_from_file(file_path):
    patterns = []
    with open(file_path, 'r') as f:
        pattern = {}
        for line in f:
            if line.startswith("Start EA:"):
                if pattern:
                    patterns.append(pattern)
                pattern = {
                    "start_ea": int(line.split(":")[1].strip(), 16),
                    "bytes": [],
                }
            elif line.startswith("End EA:"):
                pattern["end_ea"] = int(line.split(":")[1].strip(), 16)
            elif line.startswith("Bytes:"):
                pattern["bytes"] = [int(b, 16) for b in line.split(":")[1].strip().split()]
        if pattern:
            patterns.append(pattern)
    return patterns

def make_func_sig(pattern):
    if pattern["end_ea"] - pattern["start_ea"] < 32:
        logger.debug("Function is too short")
        return None

    sig = ""
    variable_bytes = pattern.get("variable_bytes", set())

    # First 32 bytes or till end of function
    for i in range(min(32, len(pattern["bytes"]))):
        if i in variable_bytes:
            sig += ".."
        else:
            sig += "%02X" % pattern["bytes"][i]

    sig += ".." * (32 - len(sig) // 2)

    if len(pattern["bytes"]) > 32:
        crc_data = pattern["bytes"][32:32 + 255]
        crc = crc16(bytearray(crc_data), 0xFFFF)
        alen = len(crc_data)
    else:
        alen = 0
        crc = 0

    sig += " %02X" % alen
    sig += " %04X" % crc
    sig += " %04X" % (pattern["end_ea"] - pattern["start_ea"])

    logger.debug("sig: %s", sig)
    return sig

def generate_signatures_from_patterns(pattern_file):
    patterns = load_patterns_from_file(pattern_file)
    signatures = {}

    for pattern in patterns:
        sig = make_func_sig(pattern)
        if sig:
            signatures[pattern["start_ea"]] = sig

    return signatures

if __name__ == "__main__":
    pattern_file = "patterns.pat"
    signatures = generate_signatures_from_patterns(pattern_file)

    for start_ea, sig in signatures.items():
        print(f"Function start EA: {hex(start_ea)}, Signature: {sig}")
