/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECDHClientKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ArrayConverter
                                        .hexStringToByteArray("100000424104ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                66,
                                65,
                                ArrayConverter
                                        .hexStringToByteArray("04ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c"),
                                ProtocolVersion.TLS12 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("100000424104b4b5b76d94709ec280af4f806b13e20e227e60d98a65204935e804076c829cd33ca5b7ff016584aeccc42a0b6db366cbb64a20af8c03ba6311a59552b3fad23e"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                66,
                                65,
                                ArrayConverter
                                        .hexStringToByteArray("04b4b5b76d94709ec280af4f806b13e20e227e60d98a65204935e804076c829cd33ca5b7ff016584aeccc42a0b6db366cbb64a20af8c03ba6311a59552b3fad23e"),
                                ProtocolVersion.TLS11 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("1000004241043775fe5c151587cc5b28958ea43b62ed642e02df9d6d58a17ac91756cbc8638ff5d22490ffc3e3abc144a5ecc5b54e84a576e7cd0df6863b35a55464e5038777"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                66,
                                65,
                                ArrayConverter
                                        .hexStringToByteArray("043775fe5c151587cc5b28958ea43b62ed642e02df9d6d58a17ac91756cbc8638ff5d22490ffc3e3abc144a5ecc5b54e84a576e7cd0df6863b35a55464e5038777"),
                                ProtocolVersion.TLS10 } });
    }

    private byte[] message;

    private HandshakeMessageType type;
    private int length;

    private int serializedKeyLength;
    private byte[] serializedKey;
    private ProtocolVersion version;

    public ECDHClientKeyExchangeParserTest(byte[] message, HandshakeMessageType type, int length,
            int serializedKeyLength, byte[] serializedKey, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.version = version;
    }

    /**
     * Test of parse method, of class ECDHClientKeyExchangeParser.
     */
    @Test
    public void testParse() {
        ECDHClientKeyExchangeParser<ECDHClientKeyExchangeMessage> parser = new ECDHClientKeyExchangeParser(0, message,
                version);
        ECDHClientKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getPublicKey().getValue());
    }

}
