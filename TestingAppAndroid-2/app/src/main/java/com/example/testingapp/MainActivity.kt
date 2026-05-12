package com.example.testingapp

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.example.testingapp.services.InsecureWriteStorageService
import com.example.testingapp.services.WeakPasswordProtectedKeyService
import com.example.testingapp.services.PrivateKeyWeakPasswordService

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Запуск Сервиса 1 - M9: Insecure Data Storage
        val service1Intent = Intent(this, InsecureWriteStorageService::class.java)
        startService(service1Intent)

        // Запуск Сервиса 2 - M1: Improper Credential Usage (weak password protected keys)
        val service2Intent = Intent(this, WeakPasswordProtectedKeyService::class.java)
        startService(service2Intent)

        // Запуск Сервиса 3 - M1: Improper Credential Usage (private key with weak password)
        val service3Intent = Intent(this, PrivateKeyWeakPasswordService::class.java)
        startService(service3Intent)
    }
}
