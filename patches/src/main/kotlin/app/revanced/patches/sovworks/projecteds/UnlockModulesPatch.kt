package app.revanced.patches.sovworks.projecteds

import app.revanced.patcher.patch.bytecodePatch
import app.revanced.patcher.fingerprint
import app.revanced.patcher.extensions.InstructionExtensions.addInstructions
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.iface.ClassDef

@Suppress("unused")
val unlockModulesPatch = bytecodePatch(
    name = "Unlock Modules",
    description = "Forces ModuleManager to report all modules as Available."
) {
    compatibleWith("com.sovworks.projecteds")

    execute {
        // Fingerprint: Find ModuleManagerImpl by unique string
        val managerFingerprint = fingerprint {
            strings("moduleVersionRepository size ")
            accessFlags(AccessFlags.PUBLIC, AccessFlags.FINAL)
        }

        val managerClass = managerFingerprint.classDef

        // 1. Find the target method (getModuleStatus / mo53916e)
        // Signature: (LModuleVersion;)LModuleVersionStatus;
        // Logic: Find a public method that takes 1 parameter and returns a reference type (the Enum).
        val targetMethod = managerClass.methods.first { method ->
             AccessFlags.PUBLIC.isSet(method.accessFlags) && 
             method.parameterTypes.size == 1 &&
             method.returnType.startsWith("L") && // Returns a class
             method.returnType != "Ljava/lang/Object;" // Be specific if possible, but the original code implies it returns the Enum directly
        }

        // 2. Resolve the Enum class from the method's return type
        // The return type is like "Lcom/package/Enum;"
        // We need to look up this class definition if we were strict, but we just need the type string to find the field.
        val enumType = targetMethod.returnType
        
        // 3. Find the "Available" field in the Enum class
        // We need to find the class definition for the Enum to be sure, OR we can try to guess it.
        // Better to look it up from the context.classes if possible, but we don't need to strictly inspect it 
        // if we assume standard Enum structure (first static field of its own type is usually the first enum value).
        // However, to be safe and robust (and "idiomatic" as requested), we should try to find the class.
        val enumClass = classes.firstOrNull { it.type == enumType } 
            ?: throw IllegalStateException("Could not find Enum class: $enumType")

        // 4. Find the "Available" field
        // It's a static final field of the same type as the class.
        // Usually Enums have: static final FieldA, static final FieldB, ... static final $VALUES
        // We want the first one, which corresponds to the first defined value ("Available" in the user's decompiled code).
        val availableField = enumClass.fields.first { field ->
            AccessFlags.STATIC.isSet(field.accessFlags) &&
            AccessFlags.FINAL.isSet(field.accessFlags) &&
            AccessFlags.ENUM.isSet(field.accessFlags) &&
            field.type == enumType
        }

        // 5. Apply the patch
        targetMethod.addInstructions(
            0,
            """
                sget-object v0, ${availableField.definingClass}->${availableField.name}:${availableField.type}
                return-object v0
            """
        )
    }
}
