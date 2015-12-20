== OpenPGP SmartCard Java library

After getting my hands on Yubikey NEO device I really wanted to use it for data encryption. It's technically possible as the device contains a SmartCard and a OpenPGP applet. Also, Java has a very handy javax.smartcardio package that handles hardware communication/driver side of things. What was missing was the implementation of OpenPGP applet protocol.

This repository contains the code needed to communicate with OpenPGP applet in order to present the PIN, get card's public key and later decrypt the data inside the card. I used Kotlin to implement it, so it depends on Kotlin runtime and standard library. 
