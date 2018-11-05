package com.example.kamil.bsm

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.spec.IvParameterSpec

class MainActivity : Activity() {
    companion object {
        const val SharedPreferenceName = "com.example.kamil.bsm"
        const val SharedPreferencePasswordKey = "PreferencePassword"
        const val SharedPreferenceSaltKey = "PreferenceSalting"
        const val SharedPreferenceMessage = "Message"
        const val SharedPreferenceKey = "Key"
        const val SharedPreferenceVector = "Vector"
        val charset = StandardCharsets.UTF_8!!
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        ConfirmPasswordButton.setOnClickListener {
            val input = InputPasswordPlainText.text.toString()
            val prefs = getSharedPreferences(SharedPreferenceName, Context.MODE_PRIVATE)
            val salt = prefs.getString(MainActivity.SharedPreferenceSaltKey,"")
            val hashPassword = prefs.getString(MainActivity.SharedPreferencePasswordKey,"")
            clearViewContent()

            if (Password.isCorrect(input, salt, hashPassword)){
                // Show Message
                SecretMessageTextView.text = Message.getMessage(prefs)
            }
        }

        ResetButton.setOnClickListener {
            val inputPassword = InputPasswordPlainText.text.toString()
            val inputNewPassword = ResetPasswordPlainText.text.toString()
            val prefs = getSharedPreferences(SharedPreferenceName, Context.MODE_PRIVATE)
            val saltPref = prefs.getString(MainActivity.SharedPreferenceSaltKey,"")
            val hashPasswordPref = prefs.getString(MainActivity.SharedPreferencePasswordKey,"")
            if(inputNewPassword.length < 12) {
                Toast.makeText(applicationContext,"Minimalna długość hasła to 12 znaków",Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            if(!Password.isCorrect(inputPassword,saltPref,hashPasswordPref)) {
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
            Message.saveMessage(input, getSharedPreferences(SharedPreferenceName, Context.MODE_PRIVATE))
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
        return generateByteArray(128).toString(MainActivity.charset)
    }
    fun generateByteArray(n : Int) : ByteArray {
        val random = SecureRandom()
        val bytes = ByteArray(n)
        random.nextBytes(bytes)
        return bytes
    }
}
object Message {
    fun saveMessage(input : String, prefs: SharedPreferences) {
        val messageVector = Utils.generateByteArray(16)
        val messageKey = Utils.generateByteArray(16)
        val message =  Message.encrypt(input.toByteArray(MainActivity.charset), messageVector, messageKey)

        prefs.edit().putString(MainActivity.SharedPreferenceMessage,  Base64.encodeToString(message, Base64.DEFAULT).trim()).apply()
        prefs.edit().putString(MainActivity.SharedPreferenceVector, Base64.encodeToString(messageVector, Base64.DEFAULT).trim()).apply()
        prefs.edit().putString(MainActivity.SharedPreferenceKey, Base64.encodeToString(messageKey, Base64.DEFAULT).trim()).apply()
    }
    fun getMessage(prefs: SharedPreferences):String {
        val message= prefs.getString(MainActivity.SharedPreferenceMessage,"")
        val vector= prefs.getString(MainActivity.SharedPreferenceVector, "")
        val key= prefs.getString(MainActivity.SharedPreferenceKey, "")

        val messageBytes = Base64.decode(message, Base64.DEFAULT)
        val vectorBytes = Base64.decode(vector, Base64.DEFAULT)
        val keyBytes = Base64.decode(key, Base64.DEFAULT)
        return String(decrypt(messageBytes,vectorBytes,keyBytes))
    }
    @Throws(Exception::class)
    fun encrypt(text: ByteArray, encryptionMessageVector: ByteArray, encryptionMessageKey: ByteArray): ByteArray {
        val iv = IvParameterSpec(encryptionMessageVector)
        val secretKeySpec = SecretKeySpec(encryptionMessageKey, "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv)
        return cipher.doFinal(text)
    }
    @Throws(Exception::class)
    fun decrypt(encryptedMessage : ByteArray, encryptionMessageVector : ByteArray, encryptionMessageKey : ByteArray): ByteArray {
        val iv = IvParameterSpec(encryptionMessageVector)
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
        return String(encoded).trim()
    }
    fun isCorrect(input : String, salt : String, hashPassword : String) : Boolean {
        val hashInput = Password.generate(input,salt)
        return hashInput == hashPassword
    }
}
