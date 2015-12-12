package com.github.atok.smartcard

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Security
import javax.crypto.Cipher

public object CryptoTools {

    fun enableBouncyCastle() {
        Security.addProvider(BouncyCastleProvider());
    }

    fun rsaEncrypt(key: PublicKey, data: ByteArray): ByteArray {
        val rsa = Cipher.getInstance("RSA/NONE/PKCS1Padding") // RSA/ECB/PKCS1Padding
        rsa.init(Cipher.ENCRYPT_MODE, key)

        return rsa.doFinal(data)
    }
}