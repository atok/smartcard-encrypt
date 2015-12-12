package com.github.atok.smartcard

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESedeKeySpec
import javax.crypto.spec.IvParameterSpec

public object CryptoTools {

    fun enableBouncyCastle() {
        Security.addProvider(BouncyCastleProvider());
    }

    fun rsaEncrypt(key: PublicKey, data: ByteArray): ByteArray {
        val rsa = Cipher.getInstance("RSA/NONE/PKCS1Padding") // RSA/ECB/PKCS1Padding
        rsa.init(Cipher.ENCRYPT_MODE, key)
        return rsa.doFinal(data)
    }

    fun desKeyGenerate(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("DESede");
        keyGenerator.init(168);

        return keyGenerator.generateKey();
    }

    fun desKeyFromBytes(bytes: ByteArray): SecretKey {
        val spec = DESedeKeySpec(bytes)
        return SecretKeyFactory.getInstance("DESede").generateSecret(spec)
    }

    fun desEncrypt(data: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
        val spec = IvParameterSpec(ByteArray(8));
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        return cipher.doFinal(data)
    }

    fun desDecrypt(data: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
        val spec = IvParameterSpec(ByteArray(8));
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        return cipher.doFinal(data)
    }
}