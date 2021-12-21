/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class EllipticCurvesExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray("001a00170019001c001b0018001a0016000e000d000b000c0009000a"), 26,
                ArrayConverter.hexStringToByteArray("00170019001c001b0018001a0016000e000d000b000c0009000a") } });
    }

    private final byte[] extension;

    private final int curvesLength;
    private final byte[] curves;

    public EllipticCurvesExtensionParserTest(byte[] extension, int curvesLength, byte[] curves) {
        this.extension = extension;
        this.curvesLength = curvesLength;
        this.curves = curves;
    }

    /**
     * Test of parseExtensionMessageContent method, of class EllipticCurvesExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        EllipticCurvesExtensionParser parser =
            new EllipticCurvesExtensionParser(new ByteArrayInputStream(extension), Config.createConfig());
        EllipticCurvesExtensionMessage msg = new EllipticCurvesExtensionMessage();
        parser.parse(msg);
        assertArrayEquals(msg.getSupportedGroups().getValue(), curves);
        assertTrue(curvesLength == msg.getSupportedGroupsLength().getValue());
    }

}
