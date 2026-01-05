package app.revanced.patches.sovworks.projecteds

import app.revanced.patcher.patch.bytecodePatch
import app.revanced.patcher.fingerprint
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21c
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction11x
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import app.revanced.patcher.extensions.InstructionExtensions.replaceInstructions

@Suppress("unused")
val unlockModulesPatch = bytecodePatch(
    name = "Unlock Modules",
    description = "Forces the app to consider all modules as Active."
) {
    compatibleWith("com.sovworks.projecteds")

    execute {
        // 1. Find ActivationStatus class via fingerprint
        val activationStatusType = fingerprint {
            strings("Active", "Inactive", "Expired")
        }.classDef.type

        val activationStatusClassDef = classes.first { it.type == activationStatusType }
        
        // 2. Identify Active/Inactive fields (read from immutable definition is fine)
        val statusFields = activationStatusClassDef.staticFields.filter {
            it.type == activationStatusClassDef.type
        }

        if (statusFields.size <= 5) {
            throw IllegalStateException("ActivationStatus class has fewer fields than expected.")
        }
        val inactiveField = statusFields[2]
        val activeField = statusFields[5]
        
        val activeFieldSmali = "${activeField.definingClass}->${activeField.name}:${activeField.type}"

        // 3. Find GetModulesActivationStatusInternalUseCase class
        val internalUseCaseType = fingerprint {
            strings("allItems", "savedActivations", "deviceToken")
        }.classDef.type
        
        val internalUseCaseClassDef = classes.first { it.type == internalUseCaseType }
        
        // Proxy the class to get the mutable version
        val internalUseCaseClass = proxy(internalUseCaseClassDef).mutableClass

        // 4. Find the target method in the mutable class
        val targets = internalUseCaseClass.methods.filter { method ->
            method.parameterTypes.size == 4 &&
            method.parameterTypes[0] == "Ljava/util/Map;" &&
            method.parameterTypes[2] == "Ljava/lang/String;" &&
            method.returnType == "Ljava/util/LinkedHashMap;"
        }

        // Method from mutableClass.methods is already a MutableMethod
        val method = targets.firstOrNull() 
            ?: throw IllegalStateException("Could not find target method in GetModulesActivationStatusInternalUseCase.")

        // 5. Scan instructions to find indices to patch
        val implementation = method.implementation ?: return@execute
        val instructions = implementation.instructions
        
        // List of patches: (Index, SmaliString)
        val patches = mutableListOf<Pair<Int, String>>()

        for (i in instructions.indices) {
            val instruction = instructions[i]

            // Case A: Loading Inactive status (SGET_OBJECT InactiveField) -> SGET_OBJECT ActiveField
            if (instruction.opcode == Opcode.SGET_OBJECT) {
                if (instruction is ReferenceInstruction && instruction.reference == inactiveField) {
                     if (instruction is Instruction21c) {
                         val reg = instruction.registerA
                         // Replace SGET Inactive with SGET Active
                         patches.add(i to "sget-object v$reg, $activeFieldSmali")
                     }
                }
            }

            // Case B: Calculating status via GetModuleActivationStatusUseCase
            // INVOKE_STATIC (returns ActivationStatus) -> NOP
            // MOVE_RESULT_OBJECT -> SGET_OBJECT ActiveField
            if (instruction.opcode == Opcode.INVOKE_STATIC) {
                if (instruction is ReferenceInstruction) {
                    val methodRefVal = instruction.reference
                    if (methodRefVal is MethodReference && methodRefVal.returnType == activationStatusClassDef.type) {
                        // Check if next instruction is move-result-object
                         if (i + 1 < instructions.size && instructions[i + 1].opcode == Opcode.MOVE_RESULT_OBJECT) {
                             // NOP the invoke
                             patches.add(i to "nop")
                             
                             // Replace MOVE_RESULT with SGET_OBJECT ActiveField
                             val moveResult = instructions[i + 1]
                             if (moveResult is Instruction11x) {
                                 val reg = moveResult.registerA
                                 patches.add((i + 1) to "sget-object v$reg, $activeFieldSmali")
                             }
                         }
                    }
                }
            }
        }
        
        // Apply patches in reverse order
        patches.sortByDescending { it.first }
        
        for ((index, smali) in patches) {
            method.replaceInstructions(index, smali)
        }
    }
}