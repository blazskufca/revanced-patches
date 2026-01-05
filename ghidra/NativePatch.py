from ghidra.app.util.exporter import OriginalFileExporter
from ghidra.app.plugin.assembler import Assemblers
from java.io import File


def patch_instruction(assembler, addr, new_inst):
    """Helper to assemble and log patches."""
    print("[!] Patching at %s: %s" % (addr, new_inst))
    try:
        assembler.assemble(addr, new_inst)
        return True
    except Exception as e:
        if "b 0x" in new_inst:
            try:
                clean_inst = new_inst.replace("0x", "")
                assembler.assemble(addr, "b " + clean_inst)
                return True
            except:
                pass
        print("[-] Assembler Error at %s: %s" % (addr, str(e)))
        return False


def run():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    try:
        assembler = Assemblers.getAssembler(currentProgram)
    except:
        print("[-] Error: Could not initialize assembler for %s" % currentProgram.getName())
        return

    jni_onload = next((f for f in fm.getFunctions(True) if f.getName() == "JNI_OnLoad"), None)
    if not jni_onload:
        return

    patched = False
    addr = jni_onload.getEntryPoint()
    end = jni_onload.getBody().getMaxAddress()

    print("[*] Starting Two-Pass Patch on %s..." % currentProgram.getName())

    while addr <= end:
        instr = listing.getInstructionAt(addr)
        if not instr:
            addr = addr.next() if addr.next() else end.add(1)
            continue

        mnemonic = instr.getMnemonicString().lower()

        if mnemonic == "bl":
            dest_addr = instr.getFlows()[0] if instr.getFlows() else None
            dest_func = fm.getFunctionAt(dest_addr) if dest_addr else None
            func_name = dest_func.getName() if dest_func else ""

            if "obfs_check1" in func_name:
                print("[+] Found call to %s" % func_name)
                if patch_instruction(assembler, instr.getAddress(), "nop"):
                    patched = True

                if "finish" in func_name:
                    scan_addr = instr.getNext().getAddress()
                    for _ in range(5):
                        target_instr = listing.getInstructionAt(scan_addr)
                        if not target_instr: break

                        t_mnemonic = target_instr.getMnemonicString().lower()
                        if t_mnemonic == "cbz":
                            if patch_instruction(assembler, scan_addr, "nop"):
                                patched = True
                            break

                        elif t_mnemonic == "cbnz":
                            label_obj = target_instr.getOpObjects(1)[0]
                            label_hex = "0x%s" % label_obj.toString()
                            if patch_instruction(assembler, scan_addr, "b %s" % label_hex):
                                patched = True
                            break

                        scan_addr = target_instr.getNext().getAddress()

        addr = instr.getMaxAddress().next()

    if patched:
        exe_path = currentProgram.getExecutablePath()
        print("[+] SUCCESS: Exporting %s" % exe_path)
        exporter = OriginalFileExporter()
        exporter.export(File(exe_path), currentProgram, None, monitor)
    else:
        print("[*] No changes applied to %s." % currentProgram.getName())


run()

