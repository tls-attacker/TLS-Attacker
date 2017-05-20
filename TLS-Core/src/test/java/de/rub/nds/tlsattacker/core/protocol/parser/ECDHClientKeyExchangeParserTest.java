/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
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
public class ECDHClientKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("100000424104ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("100000424104ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c"),
                        HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                        66,
                        65,
                        ArrayConverter
                                .hexStringToByteArray("04ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c") } });
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    private int serializedKeyLength;
    private byte[] serializedKey;

    public ECDHClientKeyExchangeParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, int serializedKeyLength, byte[] serializedKey) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
    }

    /**
     * Test of parse method, of class ECDHClientKeyExchangeParser.
     */
    @Test
    public void testParse() {
        ECDHClientKeyExchangeParser parser = new ECDHClientKeyExchangeParser(start, message, ProtocolVersion.TLS12);
        ECDHClientKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getSerializedPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getSerializedPublicKey().getValue());
    }

}
