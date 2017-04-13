/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class EllipticCurvesExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a"),
                        ExtensionType.ELLIPTIC_CURVES, 28, 26,
                        ArrayConverter.hexStringToByteArray("00170019001c001b0018001a0016000e000d000b000c0009000a") } });
    }

    private byte[] extension;
    private int start;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private int curvesLength;
    private byte[] curves;

    public EllipticCurvesExtensionParserTest(byte[] extension, int start, byte[] completeExtension, ExtensionType type,
            int extensionLength, int curvesLength, byte[] curves) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.curvesLength = curvesLength;
        this.curves = curves;
    }

    /**
     * Test of parseExtensionMessageContent method, of class
     * EllipticCurvesExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        EllipticCurvesExtensionParser parser = new EllipticCurvesExtensionParser(start, extension);
        EllipticCurvesExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertArrayEquals(msg.getSupportedCurves().getValue(), curves);
        assertTrue(curvesLength == msg.getSupportedCurvesLength().getValue());
    }

}
