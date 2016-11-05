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
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionMessage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.junit.After;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SignatureAndHashAlgorithmsExtensionHandlerTest {

    private SignatureAndHashAlgorithmsExtensionHandler msgHandler;
    private SignatureAndHashAlgorithmsExtensionMessage message;
    private int gotPointer;
    private final byte[] createdExtension = {(byte) 0, (byte) 13, // Extension type is signature_algorithms
        (byte) 0, (byte) 6, // Extension length
        (byte) 0, (byte) 4, //Count of supported_signature_algorithms bytes
        (byte) 2, (byte) 2, //SHA-1 and DSA
        (byte) 1, (byte) 1};  // MD5 and RSA
    private final byte[] originalAlgorithms = {(byte) 2, (byte) 2, (byte) 1, (byte) 1};

    /**
     * Creates all new handlers and messages before each test.
     */
    @Before
    public void prepareSAHAEMessage() {
        msgHandler = SignatureAndHashAlgorithmsExtensionHandler.getInstance();
        gotPointer = msgHandler.parseExtension(createdExtension, 0);
        message = (SignatureAndHashAlgorithmsExtensionMessage) msgHandler.getExtensionMessage();
    }

    /**
     * Overwrites the handler and the message after each test.
     */
    @After
    public void cleanupSAHAEMessage() {
        msgHandler = null;
        message = null;
    }

    /**
     * Tests the returned pointer, it should point onto the next byte after the extension.
     */
    @Test
    public void testPointer() {
        assertEquals("The new pointer must be 10", (int) 10, gotPointer);
    }

    /**
     * Tests if the extension bytes are copied correctly.
     */
    @Test
    public void testExtensionBytes() {
        assertArrayEquals("Extension Message should be 00 13 00 06 00 04 02 02 01 01", createdExtension,
                message.getExtensionBytes().getValue());
    }

    /**
     * Tests if the ExtensionType Value is set correctly.
     */
    @Test
    public void testExtensionType() {
        assertArrayEquals("Extension Type should be 00 13", ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue(),
                message.getExtensionType().getValue());
    }

    /**
     * If the parser gets a wrong extension, the parsing method should throw an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testWrongExtension() {
        SignatureAndHashAlgorithmsExtensionHandler newMsgHandler = SignatureAndHashAlgorithmsExtensionHandler.getInstance();
        byte[] newCreatedExtension = {(byte) 1, (byte) 12, // wrong Extension
            (byte) 0, (byte) 6,
            (byte) 0, (byte) 4,
            (byte) 2, (byte) 2,
            (byte) 1, (byte) 1};
        newMsgHandler.parseExtension(newCreatedExtension, 0);
    }

    /**
     * Tests if the SignatureAndHashAlgorithmsLength value is set correctly.
     */
    @Test
    public void testSignatureAndHashAlgorithmLength() {
        assertEquals("The length should be 4, hence there are 2 combinations", new Integer(4), message.getSignatureAndHashAlgorithmsLength().getValue());
    }

    /**
     * Tests if the extension config is set correctly.
     * Checks the array list, not the byte value.
     * @throws IOException 
     */
    @Test
    public void testSignatureAndHashAlgorithmConfig() throws IOException {
        ByteArrayOutputStream parsedAlgorithms = new ByteArrayOutputStream();
        for (SignatureAndHashAlgorithm alg : message.getSignatureAndHashAlgorithmsConfig()) {
            parsedAlgorithms.write(alg.getByteValue());
        }
        /* The ArrayList can't be compared directly due to the hashmap in the datatype SignatureAndHashAlgorithm
        assertEquals detects different ArrayLists, even if the values are identical. */
        assertArrayEquals(originalAlgorithms, parsedAlgorithms.toByteArray());

    }

    /**
     * Tests if the extension byte values are set correctly.
     * Doesn't check the array list.
     */
    @Test
    public void testSignatureAndHashAlgorithms() {
        assertArrayEquals(originalAlgorithms, message.getSignatureAndHashAlgorithms().getValue());
    }

    /**
     * Tests if the extension length value is set correctly.
     */
    @Test
    public void testExtensionLength() {
        assertEquals((int) 6,
                (int) message.getExtensionLength().getValue());
    }

}
