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
        const val SharedPreferencePasswordKey = "PasswordKey"
        const val SharedPreferencePasswordSalt = "PasswordSalt"
        const val SharedPreferenceMessage = "Message"
        const val SharedPreferenceMessageSalt = "MessageSalt"
        const val SharedPreferenceMessageVector = "MessageVector"
        val charset = StandardCharsets.UTF_8!!
    }
    private lateinit var prefs : SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        prefs =  getSharedPreferences(SharedPreferenceName,Context.MODE_PRIVATE)

        ConfirmPasswordButton.setOnClickListener {
            val input = InputPasswordPlainText.text.toString()
            val key = prefs.getString(MainActivity.SharedPreferencePasswordKey,"")
            val salt = prefs.getString(MainActivity.SharedPreferencePasswordSalt,"")
            clearViewContent()

            if (PBKDF2WithHmacSHA1.isCorrect(input, salt, key)){
                // show Message
                SecretMessageTextView.text = Message.getMessage(prefs, input)
            } else {
                Toast.makeText(this,"Password is incorrect", Toast.LENGTH_LONG).show()
            }
        }

        ResetPasswordButton.setOnClickListener {
            //TODO: Firstly, we have to check if last stored password is correct
            val input = ResetPasswordPlainText.text.toString()
            val salt = Utils.createSalt()
            val key = PBKDF2WithHmacSHA1.createStringKey(input, salt)

            // save key and salt to SharedPreference
            prefs.edit().putString(SharedPreferencePasswordKey, key).apply()
            prefs.edit().putString(SharedPreferencePasswordSalt, salt).apply()

            clearViewContent()
        }

        SaveMessageButton.setOnClickListener {
            val input = InputPasswordPlainText.text.toString()
            val textMessage = SecretMessagePlainText.text.toString()
            val salt = prefs.getString(MainActivity.SharedPreferencePasswordSalt,"")
            val key = prefs.getString(MainActivity.SharedPreferencePasswordKey,"")
            if (PBKDF2WithHmacSHA1.isCorrect(input, salt, key)){
                Message.saveMessage(textMessage, prefs, input)
            }
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
    fun saveMessage(input : String, prefs: SharedPreferences, password : String) {
        val iv = Utils.generateByteArray(16)
        val salt = Utils.createSalt()
        val key = PBKDF2WithHmacSHA1.createByteArrayKey(password, salt,128)
        val secretMessage =  AESCBCPKCS5Padding.encrypt(input.toByteArray(MainActivity.charset), iv, key)

        // transform some data into string to save in SharedPreference
        val secretMessageString = Base64.encodeToString(secretMessage, Base64.DEFAULT).trim()
        val ivString = Base64.encodeToString(iv, Base64.DEFAULT).trim()
        // save message, iv and (another) salt to SharedPreference
        prefs.edit().putString(MainActivity.SharedPreferenceMessage, secretMessageString).apply()
        prefs.edit().putString(MainActivity.SharedPreferenceMessageSalt, salt).apply()
        prefs.edit().putString(MainActivity.SharedPreferenceMessageVector, ivString).apply()
    }
    fun getMessage(prefs: SharedPreferences, password : String):String {
        val secretMessage = prefs.getString(MainActivity.SharedPreferenceMessage,"")
        val iv = prefs.getString(MainActivity.SharedPreferenceMessageVector, "")
        val salt = prefs.getString(MainActivity.SharedPreferenceMessageSalt,"")
        val key = PBKDF2WithHmacSHA1.createByteArrayKey(password,salt,128)

        val messageBytes = Base64.decode(secretMessage, Base64.DEFAULT)
        val vectorBytes = Base64.decode(iv, Base64.DEFAULT)

        return String(AESCBCPKCS5Padding.decrypt(messageBytes,vectorBytes,key))
    }
}
object AESCBCPKCS5Padding {
    @Throws(Exception::class)
    fun encrypt(content: ByteArray, vector: ByteArray, key: ByteArray): ByteArray {
        val iv = IvParameterSpec(vector)
        val secretKeySpec = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv)
        return cipher.doFinal(content)
    }
    @Throws(Exception::class)
    fun decrypt(content : ByteArray, vector : ByteArray, key : ByteArray): ByteArray {
        val iv = IvParameterSpec(vector)
        val secretKeySpec = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv)
        return cipher.doFinal(content)
    }
}
object PBKDF2WithHmacSHA1 {
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun createStringKey(input: String, salt: String, keyLength : Int = 256) : String {
        return String(createByteArrayKey(input,salt,keyLength)).trim()
    }
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun createByteArrayKey(input: String, salt: String, keyLength : Int = 256) : ByteArray {
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val keySpec = PBEKeySpec((input+salt).toCharArray(), salt.toByteArray(), 2048, keyLength)
        return secretKeyFactory.generateSecret(keySpec).encoded
    }
    fun isCorrect(input : String, salt : String, key : String) : Boolean {
        return key == PBKDF2WithHmacSHA1.createStringKey(input,salt)
    }
}