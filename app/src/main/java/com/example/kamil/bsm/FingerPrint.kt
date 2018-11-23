package com.example.kamil.bsm

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.v4.app.ActivityCompat
import android.support.v7.app.AppCompatActivity
import android.widget.Toast
import java.io.IOException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


class FingerPrint(var context : Context, private var listener : FingerprintManager.AuthenticationCallback) {
    companion object {
        const val KEY_NAME = "com.example.kamil.bsm"
    }
    private lateinit var keyguardManager: KeyguardManager
    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator
    private lateinit var cipher: Cipher
    private lateinit var cryptoObject: FingerprintManager.CryptoObject


    fun init(){
        keyguardManager = context.getSystemService(AppCompatActivity.KEYGUARD_SERVICE) as KeyguardManager
        fingerprintManager = context.getSystemService(AppCompatActivity.FINGERPRINT_SERVICE) as FingerprintManager

        if (!keyguardManager.isKeyguardSecure) {
            Toast.makeText(context, "Lock screen security not enabled in Settings", Toast.LENGTH_LONG).show()
            return
        }
        //Check whether the user has granted your app the USE_FINGERPRINT permission//
        if (ActivityCompat.checkSelfPermission(context,  Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(context,"Fingerprint authentication permission not enabled", Toast.LENGTH_LONG).show()
            return
        }
        //Check that the user has registered at least one fingerprint//
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            Toast.makeText(context,    "Register at least one fingerprint in Settings", Toast.LENGTH_LONG).show()
            return
        }
        generateKey()

        if (cipherInit()) {
            //If the cipher is initialized successfully, then create a CryptoObject instance//
            cryptoObject = FingerprintManager.CryptoObject(cipher)
            fingerprintManager.authenticate(cryptoObject,CancellationSignal(),0,listener,null)
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
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }
    private fun cipherInit():Boolean {
        cipher = Cipher.getInstance( KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        return try {
            keyStore.load(null)
            val key = keyStore.getKey(KEY_NAME, null) as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, key)
            true
        } catch (e : KeyPermanentlyInvalidatedException){
            false
        }
    }
}
