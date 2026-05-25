package com.masttest.vuln03.ui

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.masttest.vuln03.R
import com.masttest.vuln03.keystore.VulnerableKeystoreManager1
import com.masttest.vuln03.keystore.VulnerableKeyChainManager2
import com.masttest.vuln03.keystore.VulnerableKeystoreManager3

/**
 * Main Activity demonstrating vulnerable keystore operations
 * for security testing purposes.
 */
class MainActivity : AppCompatActivity() {
    
    private lateinit var statusTextView: TextView
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        statusTextView = findViewById(R.id.statusTextView)
        
        setupService1Buttons()
        setupService2Buttons()
        setupService3Buttons()
    }
    
    private fun setupService1Buttons() {
        findViewById<Button>(R.id.btnService1Encrypt).setOnClickListener {
            try {
                val manager = VulnerableKeystoreManager1()
                val encrypted = manager.encryptData("Secret Data for Service 1")
                statusTextView.text = "Service 1: Encrypted ${encrypted.size} bytes\nStorage: /sdcard/Download/vulnerable_data_service1.dat"
                Toast.makeText(this, "Data encrypted to world-writable location", Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                statusTextView.text = "Service 1 Error: ${e.message}"
            }
        }
        
        findViewById<Button>(R.id.btnService1Export).setOnClickListener {
            try {
                val manager = VulnerableKeystoreManager1()
                val keyMaterial = manager.exportKeyMaterial()
                statusTextView.text = "Service 1: Exported key material (${keyMaterial?.size ?: 0} bytes)"
                Toast.makeText(this, "Key material exported - VULNERABILITY!", Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                statusTextView.text = "Service 1 Error: ${e.message}"
            }
        }
    }
    
    private fun setupService2Buttons() {
        findViewById<Button>(R.id.btnService2Password).setOnClickListener {
            try {
                val manager = VulnerableKeyChainManager2(this)
                val password = manager.getStoredPassword()
                val info = manager.getCredentialInfo()
                statusTextView.text = "Service 2: Password='$password'\nAlias: ${info["alias"]}\nHas Key: ${info["has_private_key"]}"
                Toast.makeText(this, "Weak password exposed: $password", Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                statusTextView.text = "Service 2 Error: ${e.message}"
            }
        }
        
        findViewById<Button>(R.id.btnService2Export).setOnClickListener {
            try {
                val manager = VulnerableKeyChainManager2(this)
                val credentials = manager.exportCredentials()
                statusTextView.text = "Service 2: Exported credentials\n${credentials.map { "${it.key}=${it.value}" }.joinToString("\n")}"
                Toast.makeText(this, "Credentials exported - VULNERABILITY!", Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                statusTextView.text = "Service 2 Error: ${e.message}"
            }
        }
    }
    
    private fun setupService3Buttons() {
        findViewById<Button>(R.id.btnService3Generate).setOnClickListener {
            try {
                val manager = VulnerableKeystoreManager3()
                manager.generateRSAKeyPair()
                statusTextView.text = "Service 3: RSA Key pair generated (no user auth required)"
                Toast.makeText(this, "Key generated without authentication", Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                statusTextView.text = "Service 3 Error: ${e.message}"
            }
        }
        
        findViewById<Button>(R.id.btnService3Info).setOnClickListener {
            try {
                val manager = VulnerableKeystoreManager3()
                val info = manager.getKeyInfo()
                val metadata = manager.exportKeyMetadata()
                statusTextView.text = "Service 3 Key Info:\n$info\n\nMetadata:\n$metadata"
                Toast.makeText(this, "Key info exposed - VULNERABILITY!", Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                statusTextView.text = "Service 3 Error: ${e.message}"
            }
        }
    }
}
