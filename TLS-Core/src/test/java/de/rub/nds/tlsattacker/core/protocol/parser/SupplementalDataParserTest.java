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
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SupplementalDataParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        { ArrayConverter.hexStringToByteArray("1700001100000e4002000a0008010005aaaaaaaaaa"),
                                HandshakeMessageType.SUPPLEMENTAL_DATA, 17, 14,
                                ArrayConverter.hexStringToByteArray("4002000a0008010005aaaaaaaaaa"),
                                ProtocolVersion.TLS11 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("1700001F00001c4002000a0008010005aaaaaaaaaa4002000a0008010005aaaaaaaaaa"),
                                HandshakeMessageType.SUPPLEMENTAL_DATA,
                                31,
                                28,
                                ArrayConverter
                                        .hexStringToByteArray("4002000a0008010005aaaaaaaaaa4002000a0008010005aaaaaaaaaa"),
                                ProtocolVersion.TLS11 } });
    }

    private byte[] message;
    private HandshakeMessageType type;
    private int length;

    private int supplementalDataLength;
    private byte[] supplementalDataBytes;
    private ProtocolVersion version;

    public SupplementalDataParserTest(byte[] message, HandshakeMessageType type, int length,
            int supplementalDataLength, byte[] supplementalDataBytes, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.supplementalDataLength = supplementalDataLength;
        this.supplementalDataBytes = supplementalDataBytes;
        this.version = version;
    }

    @Test
    public void testParse() {
        SupplementalDataParser parser = new SupplementalDataParser(0, message, version);
        SupplementalDataMessage suppDataMessage = parser.parse();
        assertArrayEquals(suppDataMessage.getCompleteResultingMessage().getValue(), message);
        assertTrue(suppDataMessage.getType().getValue() == type.getValue());
        assertTrue(suppDataMessage.getLength().getValue() == length);
        assertTrue(suppDataMessage.getSupplementalDataLength().getValue() == supplementalDataLength);
        assertArrayEquals(suppDataMessage.getSupplementalDataBytes().getValue(), supplementalDataBytes);
    }

}
