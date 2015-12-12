package com.github.atok

import com.github.atok.smartcard.CryptoTools
import com.github.atok.smartcard.SimpleSmartCard


fun main(args: Array<String>) {
    CryptoTools.enableBouncyCastle()
    val card = SimpleSmartCard.default()

    try {
        card.selectApplet()
        card.verify("123456")
        val key = card.publicKey()

        val encrypted = CryptoTools.rsaEncrypt(key, "Good morning everyone!".toByteArray(Charsets.UTF_8))

        val decrypted = card.decipher(encrypted)
        println(String(decrypted, Charsets.UTF_8))

    } catch(e: Exception) {
        e.printStackTrace()
    } finally {
        card.disconnect()
    }
}
