package com.example.kamil.bsm

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.spec.IvParameterSpec

class MainActivity : Activity() {
    companion object {
        const val SharedPreferenceName = "com.example.kamil.bsm"
        const val SharedPreferencePasswordKey = "PreferencePassword"
        const val SharedPreferenceSaltKey = "PreferenceSalting"
        val charset = StandardCharsets.UTF_8!!
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        ConfirmPasswordButton.setOnClickListener {
            val input = InputPasswordPlainText.text.toString()
            val prefs = getSharedPreferences(SharedPreferenceName, Context.MODE_PRIVATE)
            clearViewContent()
            if (Password.isCorrect(input, prefs)){
                // Show Message
                SecretMessageTextView.text = Message.getMessage()
            }
        }

        ResetButton.setOnClickListener {
            val inputPassword = InputPasswordPlainText.text.toString()
            val inputNewPassword = ResetPasswordPlainText.text.toString()
            val prefs = getSharedPreferences(SharedPreferenceName, Context.MODE_PRIVATE)
            if(inputNewPassword.length < 12) {
                Toast.makeText(applicationContext,"Minimalna długość hasła to 12 znaków",Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            if(!Password.isCorrect(inputPassword,prefs)) {
                Toast.makeText(applicationContext,"Wprowadź poprawne hasło",Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            val salt = Utils.createSalt()
            val hashPassword = Password.generate(inputNewPassword, salt)
            // save hash password and salt to SharedPreference
            prefs.edit().putString(SharedPreferencePasswordKey, hashPassword).apply()
            prefs.edit().putString(SharedPreferenceSaltKey, salt).apply()

            clearViewContent()
        }

        ConfirmMessageButton.setOnClickListener {
            val input = SecretMessagePlainText.text.toString()
            Message.saveMessage(input)
            clearViewContent()
        }

    }
    private fun clearViewContent(){
        ResetPasswordPlainText.text.clear()
        InputPasswordPlainText.text.clear()
        SecretMessagePlainText.text.clear()
        SecretMessageTextView.text = ""
    }
}
object Utils {
    fun createSalt() :String {
        val random = SecureRandom()
        val bytes = ByteArray(128)
        random.nextBytes(bytes)
        return bytes.toString(MainActivity.charset)
    }
    fun createAESKey() : ByteArray {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(128)
        return keyGen.generateKey().encoded
    }
    fun createVector() : String {
        return UUID.randomUUID().toString().take(16) // 16 characters * 8 bit = 128 bits
    }
}
object Message {
    private var encryptedMessage = ByteArray(128)
    private var encryptionMessageKey = ByteArray(128)
    private var encryptionMessageVector = ""

    fun saveMessage(input : String) {
        encryptionMessageKey = Utils.createAESKey()
        encryptionMessageVector = Utils.createVector()
        encryptedMessage = Message.encrypt(input.toByteArray(MainActivity.charset))
    }
    fun getMessage():String {
        return String(decrypt())
    }
    @Throws(Exception::class)
    fun encrypt(text: ByteArray): ByteArray {
        val iv = IvParameterSpec(encryptionMessageVector.toByteArray(MainActivity.charset))
        val secretKeySpec = SecretKeySpec(encryptionMessageKey, "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv)
        return cipher.doFinal(text)
    }
    @Throws(Exception::class)
    fun decrypt(): ByteArray {
        val iv = IvParameterSpec(encryptionMessageVector.toByteArray(MainActivity.charset))
        val secretKeySpec = SecretKeySpec(encryptionMessageKey, "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv)
        return cipher.doFinal(encryptedMessage)
    }
}
object Password {
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun generate(password: String, salt: String) : String {
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val keySpec = PBEKeySpec((password+salt).toCharArray(), salt.toByteArray(), 2048, 256)
        val encoded = secretKeyFactory.generateSecret(keySpec).encoded
        return String(encoded)
    }
    fun isCorrect(input : String, prefs : SharedPreferences) : Boolean {
        val salt = prefs.getString(MainActivity.SharedPreferenceSaltKey,"")
        val hashInput = Password.generate(input,salt)
        val hashPassword = prefs.getString(MainActivity.SharedPreferencePasswordKey,"")
        return hashInput == hashPassword
    }
}
