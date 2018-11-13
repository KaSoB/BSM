package com.example.kamil.bsm.algorithms

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

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