package com.github.atok.smartcard

import java.io.File
import java.nio.file.Files

object Example {
    @JvmStatic fun main(args: Array<String>) {
        CryptoTools.enableBouncyCastle()

        val symmetricKey = CryptoTools.desKeyGenerate()

        val message = Files.readAllBytes(File("data/example.txt").toPath())
        val encryptedMessage = CryptoTools.desEncrypt(message, symmetricKey)

        val card = OpenPgpSmartCard.default()

        try {
            card.selectApplet()
            card.verify("123456")
            val key = card.publicKey()
            val encryptedKey = CryptoTools.rsaEncrypt(key, symmetricKey.encoded)

            //--------

            val decrypted = card.decipher(encryptedKey)

            val decryptedMessage = CryptoTools.desDecrypt(encryptedMessage, CryptoTools.desKeyFromBytes(decrypted))
            println(String(decryptedMessage, Charsets.UTF_8))

        } catch(e: Exception) {
            e.printStackTrace()
        } finally {
            card.disconnect()
        }
    }

}
