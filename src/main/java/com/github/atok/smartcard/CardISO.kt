package com.github.atok.smartcard

import com.github.atok.smartcard.OffsetBytes
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec
import javax.smartcardio.CommandAPDU

object CardISO {

    // CLA INS PI P2 LC CDATA
    val OPEN_PGP_AID = bytes(0xD2, 0x76, 0x00, 0x01, 0x24, 0x01)

    enum class Pin { Pin1, Pin2 }

    //TODO 0x81
    fun verify(pin: String, p2: Int = 0x82): CommandAPDU {
        return CommandAPDU(bytes(0x00, 0x20, 0x00, p2, pin.length) + pin.toByteArray(Charsets.UTF_8))
    }

    fun sign(data: ByteArray): CommandAPDU {
        return CommandAPDU(bytes(0x00, 0x2a, 0x9e, 0x9a, data.size) + data + bytes(0x00))
    }

    fun decipher(data: ByteArray, chain: Boolean = false): CommandAPDU {
        val length = data.size
        //        val lenBytes = bytes(0x00, (length shr 8) and 0xFF, length and 0xFF)
        // turns out openPGP in yubikey does not support extended APDU
        val lenBytes = bytes(length)

        val cla = if(chain) 0x10 else 0x00
        val bytes = bytes(cla, 0x2a, 0x80, 0x86) + lenBytes + data + bytes(0x00)
        return CommandAPDU(bytes)
    }

    fun selectApplet(aid: ByteArray = OPEN_PGP_AID): CommandAPDU {
        return CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid)
    }

    fun getPublicKey(): CommandAPDU {
        return CommandAPDU(bytes(0x00, 0x47, 0x00, 0x00, 0x01, 0xB8))
    }

    fun parsePublicKey(byteArray: ByteArray): PublicKey {
        val bytes = OffsetBytes(byteArray, 0)
        if(!bytes.check(bytes(0x7f, 0x49))) throw IllegalArgumentException("Expecting 0x7f 0x49")

        val totalLength = readLength(bytes)
        if(!bytes.check(bytes(0x81))) throw IllegalArgumentException("Expecting 0x81 - modulus")

        val modulusLength = readLength(bytes)
        val modulusBytes = bytes.next(modulusLength)

        if(!bytes.check(bytes(0x82))) throw IllegalArgumentException("Expecting 0x82 - exponent")

        val exponentLength = bytes.nextAsInt()
        val exponentBytes = bytes.next(exponentLength)

        if(!bytes.check(bytes(0x90, 0x00))) throw IllegalArgumentException("Expecting 0x90 0x00")

        val spec = RSAPublicKeySpec(BigInteger(modulusBytes.toHexString(), 16), BigInteger(exponentBytes.toHexString(), 16))
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

    private fun ByteArray.toHexString(): String {
        return this.map {
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

    private fun bytes(vararg byte: Int): ByteArray {
        byte.forEach {
            if(it > 255) throw IllegalArgumentException("Value to big: $it")
        }

        return byte.map { it.toByte() }.toByteArray()
    }
}