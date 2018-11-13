package com.example.kamil.bsm

import android.content.SharedPreferences
import android.util.Base64
import com.example.kamil.bsm.algorithms.AESCBCPKCS5Padding
import com.example.kamil.bsm.algorithms.PBKDF2WithHmacSHA1

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