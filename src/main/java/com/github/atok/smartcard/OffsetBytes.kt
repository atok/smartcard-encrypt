package com.github.atok.smartcard

data class OffsetBytes(val bytes: ByteArray, var offset: Int) {
    fun next(): Byte {
        return bytes[offset++]
    }

    fun next(cnt: Int): ByteArray {
        val ret = bytes.sliceArray((offset..offset+cnt-1))
        offset += cnt
        return ret
    }

    fun nextAsInt(): Int {
        return bytes[offset++].toInt() and 0xff
    }

    fun check(checked: ByteArray): Boolean {
        val has = next(checked.size)
        for(i in 0..checked.size-1) {
            if(checked[i] != has[i]) return false
        }
        return true
    }

    fun check(checked: Int): Boolean {
        return check(byteArrayOf(checked.toByte()))
    }

    fun check(vararg checked: Int): Boolean {
        return check(checked.map { it.toByte() }.toByteArray())
    }

    operator fun get(i: Int): Byte {
        return bytes[i]
    }

    override fun toString(): String {
        val printed = bytes.map {
            val v = it.toInt() and 0xff
            Integer.toHexString(v)
        }

        return printed.take(offset).joinToString(" ") + " || " + printed.takeLast(printed.size - offset).joinToString(" ")
    }
}