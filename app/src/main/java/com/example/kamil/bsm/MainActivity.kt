package com.example.kamil.bsm

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.hardware.fingerprint.FingerprintManager
import android.os.Bundle
import android.widget.Toast
import com.example.kamil.bsm.algorithms.PBKDF2WithHmacSHA1
import kotlinx.android.synthetic.main.activity_main.*
import java.nio.charset.StandardCharsets

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

    private var fingerPrintListener = object : FingerprintManager.AuthenticationCallback(){
        override fun onAuthenticationError(errMsgId: Int, errString: CharSequence) {
            Toast.makeText(baseContext,"Authentication error\n$errString", Toast.LENGTH_LONG).show()
        }
        override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence) {
            Toast.makeText(baseContext, "Authentication help\n$helpString", Toast.LENGTH_LONG).show()
        }
        override fun onAuthenticationFailed() {
            Toast.makeText(baseContext,  "Authentication failed.", Toast.LENGTH_LONG).show()
        }
        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult) {
            Toast.makeText(baseContext, "Authentication succeeded.", Toast.LENGTH_LONG).show()
            showMessage(InputPasswordPlainText.text.toString())
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        prefs = getSharedPreferences(SharedPreferenceName,Context.MODE_PRIVATE)

        // Enable fingerprint authorization
        FingerPrint(baseContext,fingerPrintListener).init()

        ConfirmPasswordButton.setOnClickListener {
            val input = InputPasswordPlainText.text.toString()
            val key = prefs.getString(MainActivity.SharedPreferencePasswordKey,"")
            val salt = prefs.getString(MainActivity.SharedPreferencePasswordSalt,"")
            clearViewContent()

            if (PBKDF2WithHmacSHA1.isCorrect(input, salt, key)){
                showMessage(input)
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
    fun showMessage(input : String){
        SecretMessageTextView.text = Message.getMessage(prefs, input)
    }
    private fun clearViewContent(){
        ResetPasswordPlainText.text.clear()
        InputPasswordPlainText.text.clear()
        SecretMessagePlainText.text.clear()
        SecretMessageTextView.text = ""
    }
}

