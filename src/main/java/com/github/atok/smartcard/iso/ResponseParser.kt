package com.github.atok.smartcard.iso

import com.github.atok.smartcard.OffsetBytes
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec

object ResponseParser {

    fun parsePublicKey(byteArray: ByteArray): PublicKey {
        val bytes = OffsetBytes(byteArray, 0)

        if(!bytes.check(0x7f, 0x49)) throw IllegalArgumentException("Expecting 0x7f 0x49")

        val totalLength = readLength(bytes)
        if(!bytes.check(0x81)) throw IllegalArgumentException("Expecting 0x81 - modulus")

        val modulusLength = readLength(bytes)
        val modulusBytes = bytes.next(modulusLength)

        if(!bytes.check(0x82)) throw IllegalArgumentException("Expecting 0x82 - exponent")

        val exponentLength = bytes.nextAsInt()
        val exponentBytes = bytes.next(exponentLength)

        if(!bytes.check(0x90, 0x00)) throw IllegalArgumentException("Expecting 0x90 0x00")

        val spec = RSAPublicKeySpec(BigInteger(hexString(modulusBytes), 16), BigInteger(hexString(exponentBytes), 16))
        val keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(spec)
    }

    fun message(sw1: Int, sw2: Int): String {
        return when(sw1) {
            0x90 -> "OK"
            0x62 -> "WARNING: State of non-volatile memory unchanged, " + when(sw2) {
                0x00 -> ""
                0x81 -> "Part of returned data may be corrupted"
                0x82 -> "End of file/record reached before reading Le bytes"
                0x83 -> "Selected file invalidated"
                0x84 -> "FCI not formatted according to 1.1.5"
                else -> "?"
            }
            0x63 -> "WARNING: State of non-volatile memory changed, " + when(sw2) {
                0x00 -> ""
                0x81 -> "File filled up by the last write"
                else -> "?"
            }
            0x69 -> "Command not allowed, " + when(sw2) {
                0x00 -> ""
                0x81 -> "Command incompatible with file structure"
                0x82 -> "Security status not satisfied"
                0x83 -> "Authentication method blocked"
                0x84 -> "Referenced data invalidated"
                0x85 -> "Conditions of use not satisfied"
                0x86 -> "Command not allowed (no current EF)"
                0x87 -> "Expected SM data objects missing"
                0x88 -> "SM data objects incorrect"
                else -> "?"
            }
            else -> "?"
        }
    }

    private fun hexString(bytes: ByteArray): String {
        return bytes.map {
            val v = it.toInt() and 0xff
            val txt = Integer.toHexString(v)
            if(txt.length == 1) "0" + txt else txt
        }.joinToString("")
    }

    private fun readLength(bytes: OffsetBytes): Int {
        return when(bytes.next()) {
            0x81.toByte() -> bytes.next().toInt() and 0xff
            0x82.toByte() -> (bytes.next().toInt() and 0xff) * 256 + (bytes.next().toInt() and 0xff)
            else -> throw IllegalArgumentException("Expecting 0x81 or 0x82")
        }
    }
}