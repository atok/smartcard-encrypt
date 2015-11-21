package com.github.atok.smartcard.encrypt

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.util.io.Streams
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.SecureRandom
import java.security.Security
import java.util.*
import javax.smartcardio.CommandAPDU
import javax.smartcardio.TerminalFactory


object APDU {

    val decypherTest = CommandAPDU(bytes(0x00, 0x2A, 0x80, 0x86,
            0x23,   // size ? (35)
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02,
            0x1A, 0x05, 0x00, 0x04, 0x14, 0x17, 0x53, 0x5F, 0x4B, 0x91,
            0x59, 0xF1, 0xA8, 0x9D, 0x69, 0xEB, 0x75, 0xE7, 0x5E, 0x9E,
            0x20, 0x24,  0xEF, 0x48, 0xE9,
            0x00))

    val decypherTest2 = CommandAPDU(bytes(0x00, 0x2A, 0x80, 0x86, 0x00, 0x01, 0x01, 0x00, 0xDB, 0x2D, 0x96, 0x07, 0xB0, 0x17, 0x7A, 0x4D,
            0xBF, 0x54, 0xC8, 0x1A, 0x2C, 0x0D, 0x1A, 0x98, 0x32, 0x31, 0xD4, 0xCD, 0xE3, 0x0B, 0xFE, 0xEB,
            0x96, 0x74, 0x00, 0xD2, 0xFC, 0x7A, 0x4C, 0xB6, 0x60, 0xE5, 0xCE, 0x4F, 0x80, 0xEC, 0x9F, 0x9A,
            0x22, 0x40, 0xF6, 0x88, 0xCD, 0x7F, 0xD9, 0x1E, 0xF3, 0xFA, 0x1D, 0xAF, 0xC9, 0xF8, 0xF7, 0x17,
            0x9B, 0x14, 0x73, 0xE0, 0x49, 0xF4, 0x47, 0xE1, 0x9C, 0xFF, 0x4D, 0xEB, 0xAE, 0x60, 0x5B, 0x71,
            0x8D, 0x03, 0xBB, 0x7C, 0x73, 0x62, 0x25, 0x2B, 0xB0, 0xE1, 0x8B, 0xA7, 0x55, 0x96, 0xB4, 0x1C,
            0x89, 0x8D, 0x84, 0x27, 0x04, 0x5A, 0x33, 0xBF, 0x26, 0xB4, 0xD1, 0xEF, 0x5B, 0x68, 0x2B, 0x9C,
            0x42, 0xF0, 0x2E, 0x0F, 0xE7, 0x94, 0x3F, 0x23, 0x81, 0xDC, 0xD2, 0xCD, 0x9F, 0x6B, 0x6C, 0xE0,
            0xD1, 0x12, 0x6B, 0xB7, 0xEA, 0xDF, 0x01, 0x2F, 0x8D, 0x9A, 0xF8, 0x19, 0x7E, 0x60, 0x57, 0x33,
            0x78, 0xBD, 0xB1, 0x96, 0x58, 0x08, 0x4E, 0xE8, 0x23, 0xCB, 0x46, 0x97, 0x5A, 0x43, 0xBA, 0x25,
            0x63, 0x50, 0x4F, 0x03, 0xEE, 0x24, 0x5C, 0x24, 0x61, 0xC0, 0x1F, 0x04, 0x6D, 0xB4, 0xEB, 0x39,
            0xEC, 0x66, 0x82, 0x26, 0xE2, 0x2C, 0x0C, 0xFC, 0x5C, 0x39, 0xD1, 0x9C, 0x3C, 0xE9, 0xDA, 0x6A,
            0x01, 0xA0, 0x1F, 0x01, 0x9A, 0xF4, 0xA2, 0x77, 0x51, 0x2C, 0x30, 0x91, 0x3C, 0x4C, 0x9A, 0x7D,
            0x24, 0xE4, 0x88, 0xDE, 0xD8, 0xA9, 0x67, 0xC0, 0xF3, 0xEF, 0xBA, 0x14, 0x21, 0xFD, 0x4E, 0x12,
            0x60, 0x09, 0xBC, 0xBF, 0xBD, 0x4E, 0xD1, 0x4A, 0xF0, 0xC5, 0x78, 0x23, 0xB3, 0x62, 0x9A, 0x5A,
            0x66, 0x6F, 0x06, 0xBB, 0x52, 0x5D, 0x79, 0xFF, 0xCC, 0x49, 0x36, 0xDF, 0x11, 0xBB, 0xC9, 0x9C,
            0x41, 0xD7, 0x0B, 0xB7, 0x57, 0x4B, 0x78, 0x1D,
            0x01, 0x00   ))

    val OPEN_PGP_AID = bytes(0xD2, 0x76, 0x00, 0x01, 0x24, 0x01)

    fun verify(pin: String, p2: Int): CommandAPDU {
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
}

fun readPublicKey(file: File): PGPPublicKey {
    val stream = PGPUtil.getDecoderStream(file.inputStream())
    val foundKey = stream.use { input ->
        val pkCol = BcPGPPublicKeyRingCollection(input)

        var key: PGPPublicKey? = null

        val keyRings =  pkCol.keyRings as Iterator<PGPPublicKeyRing>
        keyRings.forEach {
            val keys = it.publicKeys as Iterator<PGPPublicKey>
            keys.forEach {
                if(it.isEncryptionKey) key = it
            }
        }

        key
    }

    return foundKey ?: throw RuntimeException("No key")
}

//fun pkcs1cryptogram(message: ByteArray): ByteArray {
//    // at least 8
//
//    val l = message.size
//    val n = 0           //modulus of private key
//    val paddingStringLength = n - 3 - l
//
//    val ps = bytes()
//    return bytes(0x00, 0x02) + ps + bytes(0x00) + message
//}

fun prepareDataForEncryption(secret: ByteArray): ByteArray {
    val secretInputStream = ByteArrayInputStream(secret)
    val literalDataGenerator = PGPLiteralDataGenerator()
    val compressedDataGenerator = PGPCompressedDataGenerator(CompressionAlgorithmTags.UNCOMPRESSED)
    val detaPrepareResultOutputStream = ByteArrayOutputStream()

    val dataPrepareOutputStream = literalDataGenerator.open(
            compressedDataGenerator.open(
                    detaPrepareResultOutputStream
            ),
            PGPLiteralData.BINARY, "f", secretInputStream.available().toLong(), Date()
    )

    Streams.pipeAll(secretInputStream, dataPrepareOutputStream)
    compressedDataGenerator.close() //why this one?

    return detaPrepareResultOutputStream.toByteArray()
}

/**
 * This encryption method is OK. GPG tool is able to decrypt its result!
 */
fun encrypt(key: PGPPublicKey, secret: ByteArray): ByteArray {
    val preparedData = prepareDataForEncryption(secret)

    val jcePgpDataEncryptorBuilder =
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES)
            .setSecureRandom(SecureRandom())

    val pgpEncryptedDataGenerator = PGPEncryptedDataGenerator(jcePgpDataEncryptorBuilder)
    pgpEncryptedDataGenerator.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key))

    val resultOutputStream = ByteArrayOutputStream()
//    val armorOutputStream = ArmoredOutputStream(resultOutputStream)
    val generatorOutputStream = pgpEncryptedDataGenerator.open(resultOutputStream, preparedData.size.toLong())

    generatorOutputStream.write(preparedData)
    generatorOutputStream.close()
//    armorOutputStream.close()

    return resultOutputStream.toByteArray()
}

fun main(args: Array<String>) {
    Security.addProvider(BouncyCastleProvider());

    val terminalFactory = TerminalFactory.getDefault()
    val terminals = terminalFactory.terminals().list()
    println(terminals)

    val terminal = terminals.get(0)
    val card = terminal.connect("*")
    val cardChannel = card.basicChannel

    try {
        val answer = cardChannel.transmit(APDU.selectApplet())
        println("Applet select $answer")

//        val pinAnswer1 = cardChannel.transmit(APDU.verify("123456", 0x81))
//        println("Pin verify PW1 $pinAnswer1")
//
//        val signAnswer = cardChannel.transmit(APDU.sign("test".toByteArray()))
//        println("Sign data $signAnswer")

        val pinAnswer2 = cardChannel.transmit(APDU.verify("123456", 0x82))
        println("Pin verify PW2 $pinAnswer2")

//        val garbageDecipherAnswer = cardChannel.transmit(CommandAPDU("xxxx".toByteArray()))
//        println("Garbage decipher $garbageDecipherAnswer")

        val testAnswer = cardChannel.transmit(APDU.decypherTest)
        println("Test decipher answer $testAnswer")
//
        val publicKey = readPublicKey(File("data/43B6CF90C5DECBBC08B0BE46D56DF27BD3065500.asc"))
        var encrypted = encrypt(publicKey, "xxxx".toByteArray())
        println(String(encrypted))

        val part1 = encrypted.slice((0..200)).toByteArray()
        val part2 = encrypted.slice((201..encrypted.size)).toByteArray()

        val enc2Answer = cardChannel.transmit(APDU.decipher(part1, chain = true))
        println("Decipher data $enc2Answer")

        val enc1Answer = cardChannel.transmit(APDU.decipher(part2))
        println("Decipher data $enc1Answer")

        val decryptedData = enc1Answer.data.map { it.toChar() }.toString()
        println(decryptedData)

    } catch(e: Exception) {
        e.printStackTrace()
    } finally {
        card.disconnect(true)
    }
}
