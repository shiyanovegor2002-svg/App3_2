package com.example.testingapp.services

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import java.io.File
import java.io.FileOutputStream

/**
 * Сервис 1 - M9: Insecure Data Storage
 * Уязвимость: Использование доступного на запись хранилища ключей
 * Ключи хранятся в общедоступном месте без шифрования
 */
class InsecureWriteStorageService : Service() {

    companion object {
        private const val TAG = "InsecureWriteStorageService"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // УЯЗВИМОСТЬ: Хранение ключей в общедоступном каталоге
        // Любой процесс с доступом к внешнему хранилищу может прочитать эти данные
        val insecureStoragePath = getExternalFilesDir(null)?.absolutePath + "/keys/"
        val keyFile = File(insecureStoragePath, "api_key.txt")
        
        // Создание директории (если не существует)
        File(insecureStoragePath).mkdirs()
        
        // Запись чувствительных данных в незащищённое хранилище
        val apiKey = "sk-prod-a1b2c3d4e5f6g7h8i9j0-secret-key-12345"
        val secretToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
        
        FileOutputStream(keyFile).use { fos ->
            fos.write("API_KEY=$apiKey\n".toByteArray())
            fos.write("SECRET_TOKEN=$secretToken\n".toByteArray())
        }
        
        // Дополнительная уязвимость: хранение в SharedPreferences без шифрования
        val prefs = getSharedPreferences("insecure_keys", Context.MODE_WORLD_READABLE)
        prefs.edit().apply {
            putString("database_password", "admin123")
            putString("encryption_key", "weak_encryption_key_123")
            apply()
        }
        
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
