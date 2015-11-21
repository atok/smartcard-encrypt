package com.github.atok.smartcard.encrypt

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
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

    val OPEN_PGP_AID = bytes(0xD2, 0x76, 0x00, 0x01, 0x24, 0x01)

    fun verify(pin: String, p2: Int): CommandAPDU {
        return CommandAPDU(bytes(0x00, 0x20, 0x00, p2, pin.length) + pin.toByteArray(Charsets.UTF_8))
    }

    fun sign(data: ByteArray): CommandAPDU {
        return CommandAPDU(bytes(0x00, 0x2a, 0x9e, 0x9a, data.size) + data + bytes(0x00))
    }

    fun decipher(data: ByteArray): CommandAPDU {
        return CommandAPDU(bytes(0x00, 0x2a, 0x80, 0x86, data.size) + data + bytes(0x00))
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

fun encrypt(key: PGPPublicKey, data: ByteArray): ByteArray {
    val dataEncryptorBuilder = BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256);
    dataEncryptorBuilder.setWithIntegrityPacket(false);
    dataEncryptorBuilder.setSecureRandom(SecureRandom());

    val encryptedDataGenerator = PGPEncryptedDataGenerator(dataEncryptorBuilder)
    encryptedDataGenerator.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key))

    val literalDataGenerator = PGPLiteralDataGenerator()
    val bout = ByteArrayOutputStream()
    val dataStream = literalDataGenerator.open(bout, PGPLiteralData.TEXT, PGPLiteralData.CONSOLE, 5, Date())
    dataStream.write(data)
    val literalData = bout.toByteArray()

    println("Literal: ${String(literalData)}")

    val resultOutputStream = ByteArrayOutputStream()
    val encryptionStream = encryptedDataGenerator.open(resultOutputStream, literalData.size.toLong())

    encryptionStream.write(literalData)
    encryptionStream.close()

    val result = resultOutputStream.toByteArray()
    return result
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

        val pinAnswer1 = cardChannel.transmit(APDU.verify("123456", 0x81))
        println("Pin verify PW1 $pinAnswer1")

        val signAnswer = cardChannel.transmit(APDU.sign("test".toByteArray()))
        println("Sign data $signAnswer")

        val pinAnswer2 = cardChannel.transmit(APDU.verify("123456", 0x82))
        println("Pin verify PW2 $pinAnswer2")

        val garbageDecipherAnswer = cardChannel.transmit(CommandAPDU("xxxx".toByteArray()))
        println("Garbage decipher $garbageDecipherAnswer")

        val testAnswer = cardChannel.transmit(APDU.decypherTest)
        println("Test decipher answer $testAnswer")

        val publicKey = readPublicKey(File("data/43B6CF90C5DECBBC08B0BE46D56DF27BD3065500.asc"))
        var encrypted = encrypt(publicKey, "abcd".toByteArray())
        println(String(encrypted))

        val enc1Answer = cardChannel.transmit(APDU.decipher(encrypted))
        println("Decipher data $enc1Answer")

        val decryptedData = enc1Answer.data.map { it.toChar() }.toString()
        println(decryptedData)

    } catch(e: Exception) {
        e.printStackTrace()
    } finally {
        card.disconnect(true)
    }
}
