package com.example.testingapp.services

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Сервис 2 - M1: Improper Credential Usage
 * Уязвимость: Использование доступного на чтение хранилища ключей с приватными ключами,
 * защищёнными слабым паролем
 */
class WeakPasswordProtectedKeyService : Service() {

    companion object {
        private const val TAG = "WeakPasswordProtectedKeyService"
        // УЯЗВИМОСТЬ: Слабый пароль для защиты ключей
        private const val WEAK_PASSWORD = "123456"
        private const val KEYSTORE_PROVIDER = "BKS"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            // Создание хранилища ключей со слабым паролем
            val keyStorePath = filesDir.absolutePath + "/keystore.bks"
            val keyStoreFile = File(keyStorePath)
            
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            
            if (!keyStoreFile.exists()) {
                // Инициализация нового хранилища
                keyStore.load(null, WEAK_PASSWORD.toCharArray())
                
                // Генерация секретного ключа со слабым паролем
                val salt = "weak_salt_12345".toByteArray()
                val iterationCount = 100 // УЯЗВИМОСТЬ: Слишком мало итераций
                
                val keySpec = PBEKeySpec(
                    WEAK_PASSWORD.toCharArray(),
                    salt,
                    iterationCount,
                    128
                )
                
                val keyFactory = SecretKeyFactory.getInstance("PBEWITHSHAAND128BITAES-CBC-BC")
                val secretKey = keyFactory.generateSecret(keySpec)
                val keyEntry = KeyStore.SecretKeyEntry(secretKey)
                
                keyStore.setEntry("secret_key", keyEntry, KeyStore.PasswordProtection(WEAK_PASSWORD.toCharArray()))
                
                // Сохранение хранилища
                FileOutputStream(keyStoreFile).use { fos ->
                    keyStore.store(fos, WEAK_PASSWORD.toCharArray())
                }
            } else {
                // Загрузка существующего хранилища со слабым паролем
                FileInputStream(keyStoreFile).use { fis ->
                    keyStore.load(fis, WEAK_PASSWORD.toCharArray())
                }
                
                // Чтение ключа (демонстрация уязвимости)
                val passwordProtection = KeyStore.PasswordProtection(WEAK_PASSWORD.toCharArray())
                val entry = keyStore.getEntry("secret_key", passwordProtection) as? KeyStore.SecretKeyEntry
                entry?.secretKey?.let { key ->
                    // Ключ доступен для чтения любым процессом
                    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                    cipher.init(Cipher.ENCRYPT_MODE, key)
                }
            }
            
            // Дополнительная уязвимость: хранение пароля в открытом виде
            val prefs = getSharedPreferences("service2_credentials", Context.MODE_PRIVATE)
            prefs.edit().apply {
                putString("keystore_password", WEAK_PASSWORD)
                putString("api_secret", "super_secret_api_key_12345")
                apply()
            }
            
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
