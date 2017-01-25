/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class MaxFragmentLengthExtensionHandlerTest {

    private final byte[] extensionMessage = { ExtensionType.MAX_FRAGMENT_LENGTH.getValue()[0],
            ExtensionType.MAX_FRAGMENT_LENGTH.getValue()[1], // Extension type
            (byte) 00, (byte) 01, // Extension length
            MaxFragmentLength.TWO_12.getValue() }; // max_fragment_length is set
                                                   // to 2^12

    /**
     * Tests the parseExtension method of MaxFragmentLengthExtensionHandler
     */
    @Test
    public void testParseExtension() {
        MaxFragmentLengthExtensionHandler extensionHandler = MaxFragmentLengthExtensionHandler.getInstance();
        int returnedPointer = extensionHandler.parseExtension(extensionMessage, 0);
        MaxFragmentLengthExtensionMessage parsedMessage = (MaxFragmentLengthExtensionMessage) extensionHandler
                .getExtensionMessage();

        Assert.assertEquals("Tests the returned pointer of the parseExtension method", (int) 5, returnedPointer);
        Assert.assertArrayEquals("Tests if the parseExtension method creates the correct extension bytes",
                extensionMessage, parsedMessage.getExtensionBytes().getValue());
        Assert.assertEquals("Tests the extensionLength of the parseExtension method", new Integer(1), parsedMessage
                .getExtensionLength().getValue());
        Assert.assertArrayEquals("Tests if the extensionType is set correctly",
                ExtensionType.MAX_FRAGMENT_LENGTH.getValue(), parsedMessage.getExtensionType().getValue());
        Assert.assertArrayEquals("Tests if the MaxFragmentLength is set correctly",
                MaxFragmentLength.TWO_12.getArrayValue(), parsedMessage.getMaxFragmentLength().getValue());
    }

    /**
     * Tests the initializeClientHelloExtension method of the
     * MaxFragmentLengthExtensionHandler
     */
    @Test
    public void testInitializeClientHelloExtension() {
        MaxFragmentLengthExtensionMessage initializedMessage;
        MaxFragmentLengthExtensionHandler maxFragmentHandlerInitialised = MaxFragmentLengthExtensionHandler
                .getInstance();
        initializedMessage = new MaxFragmentLengthExtensionMessage();
        initializedMessage.setMaxFragmentLengthConfig(MaxFragmentLength.TWO_12);
        maxFragmentHandlerInitialised.initializeClientHelloExtension(initializedMessage);

        Assert.assertArrayEquals(
                "Tests if the extension bytes are set correctly by the initializeClientHelloExtension method",
                extensionMessage, initializedMessage.getExtensionBytes().getValue());
        Assert.assertEquals(
                "Tests if the extension length is set correctly by the initializeClientHelloExtension method",
                new Integer(1), initializedMessage.getExtensionLength().getValue());
        Assert.assertArrayEquals(
                "Tests if the extension type method is set correctly by the initializeClientHelloExtension method",
                ExtensionType.MAX_FRAGMENT_LENGTH.getValue(), initializedMessage.getExtensionType().getValue());
        Assert.assertArrayEquals(
                "Tests if the max fragment length is set correctly by the initializeClientHelloExtension method",
                MaxFragmentLength.TWO_12.getArrayValue(), initializedMessage.getMaxFragmentLength().getValue());

    }
}
