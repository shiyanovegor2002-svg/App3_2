package com.masttest.vuln03.services

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.util.Log
import com.masttest.vuln03.keystore.VulnerableKeystoreManager1

/**
 * Service 1: Vulnerable Keystore Service
 * M9: Insecure Data Storage
 * 
 * This service uses Android Hardware-Backed Keystore but stores
 * encrypted data in a world-writable location.
 */
class VulnerableKeystoreService1 : Service() {
    
    private val binder = LocalBinder()
    private lateinit var keystoreManager: VulnerableKeystoreManager1
    
    companion object {
        const val ACTION_ENCRYPT = "com.masttest.vuln03.ENCRYPT"
        const val ACTION_DECRYPT = "com.masttest.vuln03.DECRYPT"
        const val EXTRA_DATA = "extra_data"
        const val TAG = "VulnService1"
    }
    
    inner class LocalBinder : Binder() {
        fun getService(): VulnerableKeystoreService1 = this@VulnerableKeystoreService1
    }
    
    override fun onCreate() {
        super.onCreate()
        keystoreManager = VulnerableKeystoreManager1()
        Log.d(TAG, "Service 1 created with vulnerable keystore")
    }
    
    override fun onBind(intent: Intent): IBinder {
        return binder
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.action?.let { action ->
            when (action) {
                ACTION_ENCRYPT -> {
                    val data = intent.getStringExtra(EXTRA_DATA) ?: ""
                    encryptData(data)
                }
                ACTION_DECRYPT -> {
                    val data = intent.getByteArrayExtra(EXTRA_DATA) ?: byteArrayOf()
                    decryptData(data)
                }
            }
        }
        return START_STICKY
    }
    
    fun encryptData(plainText: String): ByteArray {
        Log.d(TAG, "Encrypting data with vulnerable storage")
        return keystoreManager.encryptData(plainText)
    }
    
    fun decryptData(encryptedData: ByteArray): String {
        Log.d(TAG, "Decrypting data from vulnerable storage")
        return keystoreManager.decryptData(encryptedData)
    }
    
    fun generateKey() {
        keystoreManager.generateKey()
        Log.d(TAG, "Generated new vulnerable key")
    }
    
    // VULNERABILITY: Exports key material - should never be allowed
    fun exportKeyMaterial(): ByteArray? {
        return keystoreManager.exportKeyMaterial()
    }
}
