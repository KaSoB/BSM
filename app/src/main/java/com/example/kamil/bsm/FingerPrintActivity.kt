package com.example.kamil.bsm

import android.Manifest
import android.app.KeyguardManager
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.support.v4.app.ActivityCompat
import android.widget.Toast
import java.security.KeyStore
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import android.security.keystore.KeyPermanentlyInvalidatedException
import javax.crypto.SecretKey


class FingerPrintActivity : AppCompatActivity() {

    companion object {
        const val KEY_NAME = "com.example.kamil.bsm"
    }
    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var keyguardManager: KeyguardManager
    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator
    private lateinit var cipher: Cipher
    private lateinit var cryptoObject: FingerprintManager.CryptoObject

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_finger_print)

        keyguardManager = getSystemService(KEYGUARD_SERVICE) as KeyguardManager
        fingerprintManager = getSystemService(FINGERPRINT_SERVICE) as FingerprintManager

        if (!keyguardManager.isKeyguardSecure) {
            Toast.makeText(this, "Lock screen security not enabled in Settings", Toast.LENGTH_LONG).show()
            return
        }

        if (ActivityCompat.checkSelfPermission(this,  Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this,"Fingerprint authentication permission not enabled", Toast.LENGTH_LONG).show()
            return
        }

        if (!fingerprintManager.hasEnrolledFingerprints()) {
            Toast.makeText(this,    "Register at least one fingerprint in Settings", Toast.LENGTH_LONG).show()
            return
        }
        generateKey()

        if (cipherInit()) {
            cryptoObject = FingerprintManager.CryptoObject(cipher)
            val helper = FingerprintHandler(this)
            helper.startAuth(fingerprintManager, cryptoObject)
        }
    }

    private fun generateKey() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: Exception) {
            e.printStackTrace()
        }

        try {
            keyGenerator = KeyGenerator.getInstance( KeyProperties.KEY_ALGORITHM_AES,  "AndroidKeyStore")
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get KeyGenerator instance", e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Failed to get KeyGenerator instance", e)
        }

        try {
            keyStore.load(null)
            keyGenerator.init(KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build())
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        } catch (e: CertificateException) {
            throw RuntimeException(e)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }

   private fun cipherInit():Boolean {
        cipher = Cipher.getInstance( KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7)
       return try {
           keyStore.load(null)
           val key = keyStore.getKey(KEY_NAME, null) as SecretKey
           cipher.init(Cipher.ENCRYPT_MODE, key)
           true
       } catch (e : KeyPermanentlyInvalidatedException ){
           false
       }
    }
}


