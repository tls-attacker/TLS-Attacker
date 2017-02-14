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
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SignatureAndHashAlgorithmsExtensionHandlerTest {

    private final byte[] createdExtension = { (byte) 0, (byte) 13, // Extension
                                                                   // type is
                                                                   // signature_algorithms
            (byte) 0, (byte) 6, // Extension length
            (byte) 0, (byte) 4, // Count of supported_signature_algorithms bytes
            (byte) 2, (byte) 2, // SHA-1 and DSA
            (byte) 1, (byte) 1 }; // MD5 and RSA
    private final byte[] originalAlgorithms = { (byte) 2, (byte) 2, (byte) 1, (byte) 1 };

    /**
     * Tests the prepareExtension method. The SignatureAndHashAlgorithmsConfig
     * is provided, the method fills in the other values. The method works on
     * the reference of the object.
     */
    @Test
    public void testInitializeClientHelloMethod() {
        byte[] correctExtensionBytes = { (byte) 00, (byte) 13, (byte) 00, (byte) 4, (byte) 0, (byte) 2, (byte) 1,
                (byte) 1 };
        List<SignatureAndHashAlgorithm> signatureAndHashAlgrotims = new ArrayList<>();
        signatureAndHashAlgrotims.add(new SignatureAndHashAlgorithm(new byte[] { 01, 01 }));
        TlsConfig tlsConfig = new TlsConfig();
        tlsConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgrotims);
        SignatureAndHashAlgorithmsExtensionMessage initializeMethodMessage = new SignatureAndHashAlgorithmsExtensionMessage(
                tlsConfig);

        SignatureAndHashAlgorithmsExtensionHandler sigAndHashAlgoHandler = new SignatureAndHashAlgorithmsExtensionHandler();
        sigAndHashAlgoHandler.setExtensionMessage(initializeMethodMessage);
        sigAndHashAlgoHandler.prepareExtension(new TlsContext(tlsConfig));

        assertArrayEquals("Tests the complete extension bytes returned by the initializeClientHello method",
                correctExtensionBytes, initializeMethodMessage.getExtensionBytes().getValue());
        assertEquals("Tests the extension length returned by the initializeClientHello method", new Integer(4),
                initializeMethodMessage.getExtensionLength().getValue());
        assertArrayEquals("Tests the extension type returned by the initializeClientHello method", new byte[] {
                (byte) 0, (byte) 13 }, initializeMethodMessage.getExtensionType().getValue());
        assertArrayEquals("Tests the set signature and hash algorithms returned by the initializeClientHello method",
                new byte[] { (byte) 1, (byte) 1 }, initializeMethodMessage.getSignatureAndHashAlgorithms().getValue());
        assertEquals("Tests the signature and hash algorithms length returned by the initializeClientHello method",
                new Integer(2), initializeMethodMessage.getSignatureAndHashAlgorithmsLength().getValue());

    }

    @Test
    public void testParseExtensionMethod() throws IOException {
        SignatureAndHashAlgorithmsExtensionHandler msgHandler;
        SignatureAndHashAlgorithmsExtensionMessage parseMethodMessage;
        int gotPointer;

        msgHandler = new SignatureAndHashAlgorithmsExtensionHandler();
        gotPointer = msgHandler.parseExtension(createdExtension, 0);
        parseMethodMessage = (SignatureAndHashAlgorithmsExtensionMessage) msgHandler.getExtensionMessage();

        assertEquals("Tests the returned pointer", 10, gotPointer);
        assertArrayEquals("Tests the extension bytes", createdExtension, parseMethodMessage.getExtensionBytes()
                .getValue());
        assertArrayEquals("Tests the extension type", ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue(),
                parseMethodMessage.getExtensionType().getValue());
        assertEquals("Tests the signature and hash algorithms length", new Integer(4), parseMethodMessage
                .getSignatureAndHashAlgorithmsLength().getValue());
        /*
         * The ArrayList can't be compared directly due to the hashmap in the
         * datatype SignatureAndHashAlgorithm assertEquals detects different
         * ArrayLists, even if the values are identical.
         */
        assertArrayEquals("Tests the set signature and hash algorithms bytes", originalAlgorithms, parseMethodMessage
                .getSignatureAndHashAlgorithms().getValue());
        assertEquals("Tests the extension length", 6, parseMethodMessage.getExtensionLength().getValue().byteValue());
    }
}
