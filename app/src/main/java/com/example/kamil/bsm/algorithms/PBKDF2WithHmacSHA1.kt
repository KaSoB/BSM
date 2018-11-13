package com.example.kamil.bsm.algorithms

import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object PBKDF2WithHmacSHA1 {
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun createStringKey(input: String, salt: String, keyLength : Int = 256) : String {
        return String(createByteArrayKey(input, salt, keyLength)).trim()
    }
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun createByteArrayKey(input: String, salt: String, keyLength : Int = 256) : ByteArray {
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val keySpec = PBEKeySpec((input+salt).toCharArray(), salt.toByteArray(), 2048, keyLength)
        return secretKeyFactory.generateSecret(keySpec).encoded
    }
    fun isCorrect(input : String, salt : String, key : String) : Boolean {
        return key == createStringKey(input, salt)
    }
}