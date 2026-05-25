package com.masttest.vuln03.services

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.util.Log
import com.masttest.vuln03.keystore.VulnerableKeystoreManager3

/**
 * Service 3: Vulnerable Hardware-Backed Keystore Service
 * M1: Improper Credential Usage
 * 
 * This service uses Android Hardware-Backed Keystore with weak password protection.
 */
class VulnerableKeystoreService3 : Service() {
    
    private val binder = LocalBinder()
    private lateinit var keystoreManager: VulnerableKeystoreManager3
    
    companion object {
        const val ACTION_GENERATE_KEY = "com.masttest.vuln03.GENERATE_KEY_3"
        const val ACTION_VERIFY_PASSWORD = "com.masttest.vuln03.VERIFY_PASSWORD"
        const val ACTION_DECRYPT = "com.masttest.vuln03.DECRYPT_HW"
        const val EXTRA_DATA = "extra_data"
        const val EXTRA_PASSWORD = "extra_password"
        const val TAG = "VulnService3"
    }
    
    inner class LocalBinder : Binder() {
        fun getService(): VulnerableKeystoreService3 = this@VulnerableKeystoreService3
    }
    
    override fun onCreate() {
        super.onCreate()
        keystoreManager = VulnerableKeystoreManager3()
        Log.d(TAG, "Service 3 created with vulnerable hardware-backed keystore")
    }
    
    override fun onBind(intent: Intent): IBinder {
        return binder
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.action?.let { action ->
            when (action) {
                ACTION_GENERATE_KEY -> {
                    generateKey()
                }
                ACTION_VERIFY_PASSWORD -> {
                    val password = intent.getStringExtra(EXTRA_PASSWORD) ?: ""
                    verifyPassword(password)
                }
                ACTION_DECRYPT -> {
                    val data = intent.getByteArrayExtra(EXTRA_DATA) ?: byteArrayOf()
                    val password = intent.getStringExtra(EXTRA_PASSWORD) ?: ""
                    decryptData(data, password)
                }
            }
        }
        return START_STICKY
    }
    
    fun generateKey() {
        keystoreManager.generateRSAKeyPair()
        Log.d(TAG, "Generated new RSA key pair (vulnerable)")
    }
    
    fun verifyPassword(password: String): Boolean {
        Log.d(TAG, "Verifying password with weak check")
        return keystoreManager.verifyPassword(password)
    }
    
    fun decryptData(encryptedData: ByteArray, password: String): ByteArray? {
        Log.d(TAG, "Decrypting with weak authentication")
        return keystoreManager.decryptWithWeakAuth(encryptedData, password)
    }
    
    fun updatePassword(newPassword: String) {
        keystoreManager.updatePassword(newPassword)
        Log.d(TAG, "Password updated (no strength validation)")
    }
    
    // VULNERABILITY: Exposes key information
    fun getKeyInfo(): Map<String, Any> {
        return keystoreManager.getKeyInfo()
    }
    
    // VULNERABILITY: Exports key metadata
    fun exportKeyMetadata(): String {
        Log.w(TAG, "WARNING: Exporting key metadata - security vulnerability!")
        return keystoreManager.exportKeyMetadata()
    }
}
