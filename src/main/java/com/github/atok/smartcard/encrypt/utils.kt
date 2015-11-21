package com.github.atok.smartcard.encrypt

fun bytes(vararg byte: Int): ByteArray {
    return byte.map { it.toByte() }.toByteArray()
}