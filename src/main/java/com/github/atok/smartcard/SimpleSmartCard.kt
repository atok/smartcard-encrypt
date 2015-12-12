package com.github.atok.smartcard

import java.security.PublicKey
import javax.smartcardio.Card
import javax.smartcardio.CardChannel
import javax.smartcardio.ResponseAPDU
import javax.smartcardio.TerminalFactory

public class SimpleSmartCard(val card: Card) {

    private val cardChannel: CardChannel = card.basicChannel

    companion object {
        fun default(): SimpleSmartCard {
            val terminalFactory = TerminalFactory.getDefault()
            val terminals = terminalFactory.terminals().list()
            val terminal = terminals.firstOrNull() ?: throw IllegalArgumentException("Terminal not found")

            println("Connecting to $terminal")  //TODO remove
            val card = terminal.connect("*")

            return SimpleSmartCard(card)
        }
    }

    fun selectApplet() {
        val response = cardChannel.transmit(CardISO.selectApplet())
        interpretResponse(response)
    }

    fun verify(pinValue: String) {
        val response = cardChannel.transmit(CardISO.verify(pinValue))
        interpretResponse(response)
    }

    fun publicKey(): PublicKey {
        val response = cardChannel.transmit(CardISO.getPublicKey())
        interpretResponse(response)

        return CardISO.parsePublicKey(response.bytes)
    }

    fun decipher(encrypted: ByteArray): ByteArray {
        //FIXME support other lengths
        if(encrypted.size != 256) throw IllegalArgumentException("Sorry, size has to be = 256")
        val part1 = byteArrayOf(0) + encrypted.sliceArray((0..200))
        val part2 = encrypted.sliceArray((201..255))

        val response1 = cardChannel.transmit(CardISO.decipher(part1, chain = true))
        interpretResponse(response1)

        val response2 = cardChannel.transmit(CardISO.decipher(part2))
        interpretResponse(response2)

        return response2.data
    }

    fun sign(bytes: ByteArray) {
        val signAnswer = cardChannel.transmit(CardISO.sign(bytes))
        println("Sign data $signAnswer")
    }

    fun disconnect() {
        card.disconnect(true)
    }

    private fun interpretResponse(response: ResponseAPDU) {
        val sw1 = response.sW1
        val sw2 = response.sW2

        if(sw1 == 0x90) return //OK
        val msg = CardISO.message(sw1, sw2)

        throw RuntimeException("$response $msg")
    }


}
