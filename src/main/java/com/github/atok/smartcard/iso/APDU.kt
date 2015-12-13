package com.github.atok.smartcard.iso

import javax.smartcardio.CommandAPDU

object APDU {
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

    private fun bytes(vararg byte: Int): ByteArray {
        byte.forEach {
            if(it > 255) throw IllegalArgumentException("Value to big: $it")
        }

        return byte.map { it.toByte() }.toByteArray()
    }
}