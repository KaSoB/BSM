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
        val hashPassword = Password.generate(password, salt)

        assertEquals(true, Password.isCorrect(password,salt, hashPassword))
    }
    @Test
    fun password_isCorrect2() {
        val password =  ""
        val salt = Utils.createSalt()
        val hashPassword = Password.generate(password, salt)

        assertEquals(true, Password.isCorrect(password,salt, hashPassword))
    }
    @Test
    fun password_isNotCorrect() {
        val password =  "testtesttesttest"
        val salt = Utils.createSalt()
        val hashPassword = Password.generate(password, salt)

        assertEquals(false, Password.isCorrect("testtesttesttest2",salt, hashPassword))
    }
    @Test
    fun password_isNotCorrect2() {
        val password =  ""
        val salt = Utils.createSalt()
        val hashPassword = Password.generate(password, salt)

        assertEquals(false, Password.isCorrect(" ",salt, hashPassword))
    }
}
