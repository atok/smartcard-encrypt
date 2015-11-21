package com.github.atok.smartcard.encrypt

fun bytes(vararg byte: Int): ByteArray {
    byte.forEach {
        if(it > 255) throw IllegalArgumentException("Value to big: $it")
    }

    return byte.map { it.toByte() }.toByteArray()
}