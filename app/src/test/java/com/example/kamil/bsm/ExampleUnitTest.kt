package com.example.kamil.bsm

import org.junit.Test

import org.junit.Assert.*


/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class ExampleUnitTest {
    @Test
    fun password_isCorrect() {
        val password =  "testtesttesttest"
        val salt = Utils.createSalt()
        val hashPassword = PBKDF2WithHmacSHA1.createStringKey(password, salt)

        assertEquals(true, PBKDF2WithHmacSHA1.isCorrect(password,salt, hashPassword))
    }
    @Test
    fun password_isCorrect2() {
        val password =  ""
        val salt = Utils.createSalt()
        val hashPassword = PBKDF2WithHmacSHA1.createStringKey(password, salt)

        assertEquals(true, PBKDF2WithHmacSHA1.isCorrect(password,salt, hashPassword))
    }
    @Test
    fun password_isNotCorrect() {
        val password =  "testtesttesttest"
        val salt = Utils.createSalt()
        val hashPassword = PBKDF2WithHmacSHA1.createStringKey(password, salt)

        assertEquals(false, PBKDF2WithHmacSHA1.isCorrect("testtesttesttest2",salt, hashPassword))
    }
    @Test
    fun password_isNotCorrect2() {
        val password =  ""
        val salt = Utils.createSalt()
        val hashPassword = PBKDF2WithHmacSHA1.createStringKey(password, salt)

        assertEquals(false, PBKDF2WithHmacSHA1.isCorrect(" ",salt, hashPassword))
    }

}
