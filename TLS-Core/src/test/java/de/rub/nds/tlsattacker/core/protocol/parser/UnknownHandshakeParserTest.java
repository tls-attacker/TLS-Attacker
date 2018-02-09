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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class UnknownHandshakeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("040000a60000012c00a02f8dbba0bca89176bf21d4e640f729dcbded6af280556e9b4b18a6c8218f01976780232a6765e278ecc516fb19bb9ec6e3913ed27a6123eefa188212c4e5d611c85c55fb32358c0896c00781392039aae9df79ebad27860e9d5016df72bd6de898502e6221481e0f375c949e44adb6fd7fcf33e9d431a223dcf7bb72fc585ae1d8df34178bbdc5e553657dd615dc38c59b49970129c937e961f1a87a60af1e26"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("040000a60000012c00a02f8dbba0bca89176bf21d4e640f729dcbded6af280556e9b4b18a6c8218f01976780232a6765e278ecc516fb19bb9ec6e3913ed27a6123eefa188212c4e5d611c85c55fb32358c0896c00781392039aae9df79ebad27860e9d5016df72bd6de898502e6221481e0f375c949e44adb6fd7fcf33e9d431a223dcf7bb72fc585ae1d8df34178bbdc5e553657dd615dc38c59b49970129c937e961f1a87a60af1e26"),
                        HandshakeMessageType.NEW_SESSION_TICKET,
                        166,
                        ArrayConverter
                                .hexStringToByteArray("0000012c00a02f8dbba0bca89176bf21d4e640f729dcbded6af280556e9b4b18a6c8218f01976780232a6765e278ecc516fb19bb9ec6e3913ed27a6123eefa188212c4e5d611c85c55fb32358c0896c00781392039aae9df79ebad27860e9d5016df72bd6de898502e6221481e0f375c949e44adb6fd7fcf33e9d431a223dcf7bb72fc585ae1d8df34178bbdc5e553657dd615dc38c59b49970129c937e961f1a87a60af1e26") }, });
    }

    private byte[] message;

    private HandshakeMessageType type;
    private int length;
    private byte[] data;

    public UnknownHandshakeParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, byte[] data) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.data = data;
    }

    /**
     * Test of parse method, of class UnknownHandshakeParser.
     */
    @Test
    public void testParse() {
        UnknownHandshakeParser parser = new UnknownHandshakeParser(0, message, ProtocolVersion.TLS12);
        UnknownHandshakeMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertArrayEquals(data, msg.getData().getValue());
    }

}
