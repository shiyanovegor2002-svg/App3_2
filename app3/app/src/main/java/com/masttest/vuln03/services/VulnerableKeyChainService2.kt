package com.masttest.vuln03.services

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.util.Log
import com.masttest.vuln03.keystore.VulnerableKeyChainManager2

/**
 * Service 2: Vulnerable KeyChain Service
 * M1: Improper Credential Usage
 * 
 * This service uses Android KeyChain with weak password protection.
 */
class VulnerableKeyChainService2 : Service() {
    
    private val binder = LocalBinder()
    private lateinit var keyChainManager: VulnerableKeyChainManager2
    
    companion object {
        const val ACTION_STORE_KEY = "com.masttest.vuln03.STORE_KEY"
        const val ACTION_GET_PASSWORD = "com.masttest.vuln03.GET_PASSWORD"
        const val ACTION_DECRYPT = "com.masttest.vuln03.DECRYPT_KEYCHAIN"
        const val EXTRA_DATA = "extra_data"
        const val TAG = "VulnService2"
    }
    
    inner class LocalBinder : Binder() {
        fun getService(): VulnerableKeyChainService2 = this@VulnerableKeyChainService2
    }
    
    override fun onCreate() {
        super.onCreate()
        keyChainManager = VulnerableKeyChainManager2(this)
        Log.d(TAG, "Service 2 created with vulnerable KeyChain")
    }
    
    override fun onBind(intent: Intent): IBinder {
        return binder
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.action?.let { action ->
            when (action) {
                ACTION_GET_PASSWORD -> {
                    getPassword()
                }
                ACTION_DECRYPT -> {
                    val data = intent.getByteArrayExtra(EXTRA_DATA) ?: byteArrayOf()
                    decryptData(data)
                }
            }
        }
        return START_STICKY
    }
    
    fun getPassword(): String {
        Log.d(TAG, "Retrieving stored password (vulnerable)")
        return keyChainManager.getStoredPassword()
    }
    
    fun decryptData(encryptedData: ByteArray): ByteArray? {
        Log.d(TAG, "Decrypting with weak password protection")
        return keyChainManager.decryptWithWeakPassword(encryptedData)
    }
    
    fun getCredentialInfo(): Map<String, String> {
        return keyChainManager.getCredentialInfo()
    }
    
    // VULNERABILITY: Exposes credential information
    fun exportCredentials(): Map<String, String> {
        Log.w(TAG, "WARNING: Exporting credentials - security vulnerability!")
        return keyChainManager.getCredentialInfo()
    }
}
