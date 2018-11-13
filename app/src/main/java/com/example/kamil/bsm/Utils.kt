package com.example.kamil.bsm

import java.security.SecureRandom

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