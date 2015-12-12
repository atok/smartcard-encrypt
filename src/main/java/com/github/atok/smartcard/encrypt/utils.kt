package com.github.atok.smartcard.encrypt

fun bytes(vararg byte: Int): ByteArray {
    byte.forEach {
        if(it > 255) throw IllegalArgumentException("Value to big: $it")
    }

    return byte.map { it.toByte() }.toByteArray()
}


fun ByteArray.toHexString(): String {
    return this.map {
        val v = it.toInt() and 0xff
        val txt = Integer.toHexString(v)
        if(txt.length == 1) "0" + txt else txt
    }.joinToString("")
}

