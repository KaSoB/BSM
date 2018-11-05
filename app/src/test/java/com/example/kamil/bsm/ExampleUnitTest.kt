package com.example.kamil.bsm

import android.util.Base64
import org.junit.Test

import org.junit.Assert.*
import android.support.test.InstrumentationRegistry.getArguments




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
    @Test
    fun message_isCorrect() {

        val p = Utils.generateByteArray(16)
        val pp = Utils.generateByteArray(16)
        val ppp = Message.encrypt("Test".toByteArray())

        val a1 =  Base64.encodeToString(p, Base64.DEFAULT)
        val b1 = Base64.encodeToString(pp, Base64.DEFAULT)
        val c1 =  Base64.encodeToString(ppp, Base64.DEFAULT)


        val aa = Base64.decode(a1, Base64.DEFAULT)
        val bb = Base64.decode(b1, Base64.DEFAULT)
        val cc = Base64.decode(c1, Base64.DEFAULT)
        assertEquals(p, aa)
        assertEquals(pp, bb)
        assertEquals(ppp, cc)
    }
}
