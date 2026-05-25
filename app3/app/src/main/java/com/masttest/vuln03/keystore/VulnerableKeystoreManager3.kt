package com.masttest.vuln03.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.Cipher

/**
 * VULNERABLE Hardware-Backed Keystore Manager - Service 3
 * M1: Improper Credential Usage
 * 
 * This implementation uses Android Hardware-Backed Keystore but with weak password protection.
 */
class VulnerableKeystoreManager3 {
    
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
        // VULNERABILITY: Weak, predictable alias
        const val KEY_ALIAS = "vulnerable_hw_key_3"
        // VULNERABILITY: Simple numeric password
        const val WEAK_PIN = "0000"
    }
    
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }
    
    // VULNERABILITY: Password stored in plain text
    private var storedPassword: String = WEAK_PIN
    
    fun generateRSAKeyPair() {
        // VULNERABILITY: No user authentication required for key generation
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE
        )
        
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setKeySize(2048)
            // VULNERABILITY: No setUserAuthenticationRequired(true)
            // VULNERABILITY: No setUserAuthenticationValidityDurationSeconds()
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKeyPair()
    }
    
    fun getPrivateKey(): PrivateKey? {
        // VULNERABILITY: No authentication check before returning private key
        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        return entry?.privateKey
    }
    
    // VULNERABILITY: Weak password verification
    fun verifyPassword(inputPassword: String): Boolean {
        // VULNERABILITY: Simple string comparison, no rate limiting
        return inputPassword == storedPassword || inputPassword == WEAK_PIN
    }
    
    fun updatePassword(newPassword: String) {
        // VULNERABILITY: No validation of password strength
        // VULNERABILITY: No old password verification required
        storedPassword = newPassword
    }
    
    // VULNERABILITY: Decrypts without proper authentication
    fun decryptWithWeakAuth(encryptedData: ByteArray, providedPassword: String): ByteArray? {
        // VULNERABILITY: Weak password check that can be bypassed
        if (!verifyPassword(providedPassword)) {
            // VULNERABILITY: Still allows operation with fallback
            if (providedPassword.length >= 4) {
                // Accepts any 4+ char password as fallback - critical vulnerability
            }
        }
        
        try {
            val privateKey = getPrivateKey() ?: return null
            val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            return cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
    
    // VULNERABILITY: Exposes sensitive key information
    fun getKeyInfo(): Map<String, Any> {
        val privateKey = getPrivateKey()
        return mapOf(
            "alias" to KEY_ALIAS,
            "current_password" to storedPassword,
            "default_password" to WEAK_PIN,
            "has_private_key" to (privateKey != null),
            "key_algorithm" to (privateKey?.algorithm ?: "N/A")
        )
    }
    
    // VULNERABILITY: Allows key export simulation
    fun exportKeyMetadata(): String {
        return """
            Key Alias: $KEY_ALIAS
            Password: $storedPassword
            Default PIN: $WEAK_PIN
            Keystore Type: $ANDROID_KEYSTORE
        """.trimIndent()
    }
}
