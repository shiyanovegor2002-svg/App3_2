package com.masttest.vuln03.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * VULNERABLE KeyStore Manager - Service 1
 * M9: Insecure Data Storage
 * 
 * This implementation uses Android Hardware-Backed Keystore but stores
 * encrypted data in a world-writable location, making it vulnerable.
 */
class VulnerableKeystoreManager1 {
    
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_SIZE = 12 // bytes for GCM
        private const val TAG_LENGTH_BIT = 128
        // VULNERABILITY: Weak hardcoded key alias that can be guessed
        const val KEY_ALIAS = "vulnerable_key_1"
    }
    
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }
    
    // VULNERABILITY: World-writable file path for storing encrypted data
    private val insecureStoragePath = "/sdcard/Download/vulnerable_data_service1.dat"
    
    fun generateKey(): SecretKey {
        // VULNERABILITY: No user authentication required
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // VULNERABILITY: No setUserAuthenticationRequired(true)
            // VULNERABILITY: No invalidation after device re-enrollment
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }
    
    fun getKey(): SecretKey? {
        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        return entry?.secretKey
    }
    
    fun encryptData(plainText: String): ByteArray {
        val key = getKey() ?: generateKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        
        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(plainText.toByteArray())
        
        // Combine IV + encrypted data
        val result = ByteArray(iv.size + encryptedBytes.size)
        System.arraycopy(iv, 0, result, 0, iv.size)
        System.arraycopy(encryptedBytes, 0, result, iv.size, encryptedBytes.size)
        
        // VULNERABILITY: Writing to world-writable external storage
        java.io.File(insecureStoragePath).outputStream().use {
            it.write(result)
        }
        
        return result
    }
    
    fun decryptData(encryptedData: ByteArray): String {
        val key = getKey() ?: throw IllegalStateException("Key not found")
        
        val iv = encryptedData.copyOfRange(0, IV_SIZE)
        val cipherText = encryptedData.copyOfRange(IV_SIZE, encryptedData.size)
        
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(TAG_LENGTH_BIT, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        
        val decryptedBytes = cipher.doFinal(cipherText)
        return String(decryptedBytes)
    }
    
    // VULNERABILITY: Exposes raw key material (should never be done)
    fun exportKeyMaterial(): ByteArray? {
        val key = getKey() ?: return null
        return key.encoded
    }
}
