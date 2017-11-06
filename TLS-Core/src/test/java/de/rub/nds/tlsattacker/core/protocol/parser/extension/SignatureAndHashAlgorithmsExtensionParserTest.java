/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SignatureAndHashAlgorithmsExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("000d0020001e060106020603050105020503040104020403030103020303020102020203"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("000d0020001e060106020603050105020503040104020403030103020303020102020203"),
                        ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS,
                        32,
                        30,
                        ArrayConverter
                                .hexStringToByteArray("060106020603050105020503040104020403030103020303020102020203") } });
    }

    private byte[] extension;
    private int start;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private int algoListLength;
    private byte[] algoList;

    public SignatureAndHashAlgorithmsExtensionParserTest(byte[] extension, int start, byte[] completeExtension,
            ExtensionType type, int extensionLength, int algoListLength, byte[] algoList) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.algoListLength = algoListLength;
        this.algoList = algoList;
    }

    /**
     * Test of parseExtensionMessageContent method, of class
     * SignatureAndHashAlgorithmsExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        SignatureAndHashAlgorithmsExtensionParser parser = new SignatureAndHashAlgorithmsExtensionParser(start,
                extension);
        SignatureAndHashAlgorithmsExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertArrayEquals(msg.getSignatureAndHashAlgorithms().getValue(), algoList);
        assertTrue(algoListLength == msg.getSignatureAndHashAlgorithmsLength().getValue());
    }
}
