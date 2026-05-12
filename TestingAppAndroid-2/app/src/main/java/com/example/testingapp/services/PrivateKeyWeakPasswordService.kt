package com.example.testingapp.services

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.Cipher

/**
 * Сервис 3 - M1: Improper Credential Usage
 * Уязвимость: Использование доступного на чтение хранилища ключей со слабым паролем
 * с закрытыми (приватными) ключами
 */
class PrivateKeyWeakPasswordService : Service() {

    companion object {
        private const val TAG = "PrivateKeyWeakPasswordService"
        // УЯЗВИМОСТЬ: Очень слабый пароль для защиты приватного ключа
        private const val WEAK_PASSWORD = "password"
        private const val KEYSTORE_TYPE = "PKCS12"
        private const val ALIAS = "private_key_alias"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            val keyStorePath = filesDir.absolutePath + "/private_key.keystore"
            val keyStoreFile = File(keyStorePath)
            
            val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
            
            if (!keyStoreFile.exists()) {
                // Инициализация нового хранилища
                keyStore.load(null, WEAK_PASSWORD.toCharArray())
                
                // Генерация пары ключей RSA
                val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                val keyPair = keyPairGenerator.generateKeyPair()
                
                // Сохранение приватного ключа со слабым паролем
                keyStore.setKeyEntry(
                    ALIAS,
                    keyPair.private,
                    WEAK_PASSWORD.toCharArray(),
                    null
                )
                
                // Сохранение хранилища
                FileOutputStream(keyStoreFile).use { fos ->
                    keyStore.store(fos, WEAK_PASSWORD.toCharArray())
                }
            } else {
                // Загрузка хранилища со слабым паролем
                FileInputStream(keyStoreFile).use { fis ->
                    keyStore.load(fis, WEAK_PASSWORD.toCharArray())
                }
                
                // Извлечение приватного ключа (уязвимость)
                val privateKey = getPrivateKey(keyStore, WEAK_PASSWORD)
                privateKey?.let { key ->
                    // Демонстрация использования приватного ключа
                    // В реальном приложении это могло бы использоваться для подписи или дешифрования
                    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
                    cipher.init(Cipher.DECRYPT_MODE, key)
                }
            }
            
            // УЯЗВИМОСТЬ: Хранение пароля в коде и в SharedPreferences
            val prefs = getSharedPreferences("service3_credentials", Context.MODE_PRIVATE)
            prefs.edit().apply {
                putString("private_key_password", WEAK_PASSWORD)
                putString("certificate_pin", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                apply()
            }
            
            // УЯЗВИМОСТЬ: Логирование чувствительной информации
            android.util.Log.d(TAG, "Private key loaded with password: $WEAK_PASSWORD")
            
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        return START_STICKY
    }

    private fun getPrivateKey(keyStore: KeyStore, password: String): PrivateKey? {
        return try {
            val entry = keyStore.getKey(ALIAS, password.toCharArray()) as? PrivateKey
            entry
        } catch (e: Exception) {
            null
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
