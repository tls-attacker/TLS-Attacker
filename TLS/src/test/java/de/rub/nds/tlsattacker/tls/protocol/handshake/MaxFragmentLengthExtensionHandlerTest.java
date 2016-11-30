/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionMessage;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class MaxFragmentLengthExtensionHandlerTest {

    private final byte[] extensionMessage
            = {ExtensionType.MAX_FRAGMENT_LENGTH.getValue()[0], ExtensionType.MAX_FRAGMENT_LENGTH.getValue()[1], // Extension type
                (byte) 00, (byte) 01, // Extension length
                MaxFragmentLength.TWO_12.getValue()}; // max_fragment_length is set to 2^12

    private final int newPointer;
    private final MaxFragmentLengthExtensionMessage parsedMessage;
    private final MaxFragmentLengthExtensionMessage initializedMessage;

    public MaxFragmentLengthExtensionHandlerTest() {
        MaxFragmentLengthExtensionHandler maxFragmentHandlerParsed = MaxFragmentLengthExtensionHandler.getInstance();
        newPointer = maxFragmentHandlerParsed.parseExtension(extensionMessage, 0);
        parsedMessage = (MaxFragmentLengthExtensionMessage) maxFragmentHandlerParsed.getExtensionMessage();

        MaxFragmentLengthExtensionHandler maxFragmentHandlerInitialised = MaxFragmentLengthExtensionHandler.getInstance();
        initializedMessage = new MaxFragmentLengthExtensionMessage();
        initializedMessage.setMaxFragmentLengthConfig(MaxFragmentLength.TWO_12);
        maxFragmentHandlerInitialised.initializeClientHelloExtension(initializedMessage);
    }

    /**
     * Tests the returned pointer of the parseExtension method.
     */
    @Test
    public void testParseExtensionPointer() {
        Assert.assertEquals((int) 5, newPointer);
    }

    /**
     * Tests the extension bytes of the parseExtension method.
     */
    @Test
    public void testParseExtensionExtensionBytes() {
        Assert.assertArrayEquals(extensionMessage, parsedMessage.getExtensionBytes().getValue());
    }

    /**
     * Tests the extension length of the parseExtension method.
     */
    @Test
    public void testParseExtensionLength() {
        Assert.assertEquals(new Integer(1), parsedMessage.getExtensionLength().getValue());
    }

    /**
     * Tests the extension type of the parseExtension method.
     */
    @Test
    public void testParseExtensionType() {
        Assert.assertArrayEquals(ExtensionType.MAX_FRAGMENT_LENGTH.getValue(), parsedMessage.getExtensionType().getValue());
    }

    /**
     * Tests the max fragment length of the parseExtension method.
     */
    @Test
    public void testParseExtensionMaxFragmentLength() {
        Assert.assertArrayEquals(MaxFragmentLength.TWO_12.getArrayValue(), parsedMessage.getMaxFragmentLength().getValue());
    }

    /**
     * Tests the extension bytes of the initializeClientHelloExtension method.
     */
    @Test
    public void testInitializeExtensionExtensionBytes() {
        Assert.assertArrayEquals(extensionMessage, initializedMessage.getExtensionBytes().getValue());
    }

    /**
     * Tests the extension length of the initializeClientHelloExtension method.
     */
    @Test
    public void testInitializeExtensionLength() {
        Assert.assertEquals(new Integer(1), initializedMessage.getExtensionLength().getValue());
    }

    /**
     * Tests the extension type of the initializeClientHelloExtension method.
     */
    @Test
    public void testInitializeExtensionType() {
        Assert.assertArrayEquals(ExtensionType.MAX_FRAGMENT_LENGTH.getValue(), initializedMessage.getExtensionType().getValue());
    }

    /**
     * Tests the max fragment length of the initializeClientHelloExtension
     * method.
     */
    @Test
    public void testInitializeExtensionMaxFragmentLength() {
        Assert.assertArrayEquals(MaxFragmentLength.TWO_12.getArrayValue(), initializedMessage.getMaxFragmentLength().getValue());
    }
}
