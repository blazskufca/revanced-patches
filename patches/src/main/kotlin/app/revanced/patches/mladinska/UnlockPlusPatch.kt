package app.revanced.patches.mladinska

import app.revanced.patcher.patch.bytecodePatch
import app.revanced.patcher.fingerprint
import app.revanced.patcher.extensions.InstructionExtensions.addInstructions

@Suppress("unused")
val unlockPlusPatch = bytecodePatch(
    name = "Unlock Plus",
    description = "Forces the app to report 'plus' permissions to the server."
) {
    compatibleWith("com.mladinska.mkplus")
    compatibleWith("com.audiorista.android")
    execute {
        val authUserFingerprint = fingerprint {
            custom { method, classDef ->
                classDef.type.endsWith("AuthUser;") && method.name == "getPermissions"
            }
        }

        authUserFingerprint.method.addInstructions(
            0,
            """
                const-string v0, "plus"
                return-object v0
            """
        )
    }
}
