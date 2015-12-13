package com.github.atok.smartcard

import com.github.atok.smartcard.iso.APDU
import com.github.atok.smartcard.iso.ResponseParser
import java.security.PublicKey
import javax.smartcardio.Card
import javax.smartcardio.CardChannel
import javax.smartcardio.ResponseAPDU
import javax.smartcardio.TerminalFactory

public class OpenPgpSmartCard(val card: Card) {

    private val cardChannel: CardChannel = card.basicChannel

    companion object {
        fun default(): OpenPgpSmartCard {
            val terminalFactory = TerminalFactory.getDefault()
            val terminals = terminalFactory.terminals().list()
            val terminal = terminals.firstOrNull() ?: throw IllegalArgumentException("Terminal not found")

            println("Connecting to $terminal")  //TODO remove
            val card = terminal.connect("*")

            return OpenPgpSmartCard(card)
        }
    }

    fun selectApplet() {
        val response = cardChannel.transmit(APDU.selectApplet())
        interpretResponse(response)
    }

    fun verify(pinValue: String) {
        val response = cardChannel.transmit(APDU.verify(pinValue))
        interpretResponse(response)
    }

    fun publicKey(): PublicKey {
        val response = cardChannel.transmit(APDU.getPublicKey())
        interpretResponse(response)

        return ResponseParser.parsePublicKey(response.bytes)
    }

    fun decipher(encrypted: ByteArray): ByteArray {
        //FIXME support other lengths
        if(encrypted.size != 256) throw IllegalArgumentException("Sorry, size has to be = 256")
        val part1 = byteArrayOf(0) + encrypted.sliceArray((0..200))
        val part2 = encrypted.sliceArray((201..255))

        val response1 = cardChannel.transmit(APDU.decipher(part1, chain = true))
        interpretResponse(response1)

        val response2 = cardChannel.transmit(APDU.decipher(part2))
        interpretResponse(response2)

        return response2.data
    }

    fun sign(bytes: ByteArray) {
        val signAnswer = cardChannel.transmit(APDU.sign(bytes))
        println("Sign data $signAnswer")
    }

    fun disconnect() {
        card.disconnect(true)
    }

    private fun interpretResponse(response: ResponseAPDU) {
        val sw1 = response.sW1
        val sw2 = response.sW2

        if(sw1 == 0x90) return //OK
        val msg = ResponseParser.message(sw1, sw2)

        throw RuntimeException("$response $msg")
    }


}
