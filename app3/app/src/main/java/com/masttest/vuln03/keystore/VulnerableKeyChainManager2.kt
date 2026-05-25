package com.masttest.vuln03.keystore

import android.content.Context
import android.security.KeyChain
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.crypto.Cipher

/**
 * VULNERABLE KeyChain Manager - Service 2
 * M1: Improper Credential Usage
 * 
 * This implementation uses Android KeyChain with weak password protection.
 */
class VulnerableKeyChainManager2(private val context: Context) {
    
    companion object {
        // VULNERABILITY: Weak, predictable alias name
        const val KEY_ALIAS = "vulnerable_keychain_key_2"
        // VULNERABILITY: Hardcoded weak password
        const val WEAK_PASSWORD = "1234"
    }
    
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    
    // VULNERABILITY: Stores sensitive data in SharedPreferences without encryption
    private val prefs by lazy {
        context.getSharedPreferences("vulnerable_prefs_service2", Context.MODE_WORLD_READABLE)
    }
    
    fun storePrivateKeyWithWeakPassword(
        privateKey: PrivateKey,
        certificateChain: Array<X509Certificate>
    ) {
        // VULNERABILITY: Storing password in plain text in SharedPreferences
        prefs.edit().apply {
            putString("key_password", WEAK_PASSWORD)
            putString("key_alias", KEY_ALIAS)
            apply()
        }
        
        // Note: Actual KeyChain installation requires user interaction via KeyChain.createInstallIntent()
        // This is a simulation showing the vulnerability pattern
        prefs.edit().putBoolean("key_installed", true).apply()
    }
    
    fun getStoredPassword(): String {
        // VULNERABILITY: Returns password without any authentication
        return prefs.getString("key_password", WEAK_PASSWORD) ?: WEAK_PASSWORD
    }
    
    fun getPrivateKey(): PrivateKey? {
        // VULNERABILITY: No authentication required to access private key
        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        return entry?.privateKey
    }
    
    fun getCertificateChain(): Array<X509Certificate>? {
        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        return entry?.certificateChain
    }
    
    // VULNERABILITY: Allows decryption with weak/no password verification
    fun decryptWithWeakPassword(encryptedData: ByteArray): ByteArray? {
        val password = getStoredPassword()
        
        // VULNERABILITY: Password check is trivial and can be bypassed
        if (password.length < 4) {
            return null
        }
        
        try {
            val privateKey = getPrivateKey() ?: return null
            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            return cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
    
    // VULNERABILITY: Exposes credential information
    fun getCredentialInfo(): Map<String, String> {
        return mapOf(
            "alias" to KEY_ALIAS,
            "password" to getStoredPassword(),
            "has_private_key" to (getPrivateKey() != null).toString()
        )
    }
}
