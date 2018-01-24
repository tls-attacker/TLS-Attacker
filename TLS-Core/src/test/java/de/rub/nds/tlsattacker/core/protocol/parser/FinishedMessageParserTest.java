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
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class FinishedMessageParserTest {

    private static final byte[] MSG_RECORD_HANDSHAKE = new byte[] { 0x16 };
    private static final byte[] MSG_RECORD_VERSION = new byte[] { 0x03, 0x03 };
    private static final byte[] MSG_RECORD_LENGTH = new byte[] { 0x00, 0x00, 0x10 };
    private static final byte[] MSG_HANDSHAKE_FINISHED = new byte[] { 0x14 };
    private static final byte[] MSG_LENGTH = new byte[] { 0x00, 0x00, 0x0c };
    private static final byte[] MSG_0_VERIFY_DATA = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x66,
            0x55, 0x44, 0x33 };
    private static final byte[] MSG_0 = ArrayConverter.concatenate(MSG_HANDSHAKE_FINISHED, MSG_LENGTH,
            MSG_0_VERIFY_DATA);
    private static final byte[] MSG_1 = ArrayConverter.concatenate(MSG_RECORD_HANDSHAKE, MSG_RECORD_VERSION,
            MSG_RECORD_LENGTH, MSG_0);
    private static final byte[] MSG_DECRYPTED_WIRESHARK_CAP_0 = ArrayConverter
            .hexStringToByteArray("1400000ccc111ca8d8d84321f1039b92");
    private static final byte[] MSG_DECRYPTED_WIRESHARK_CAP_0_VERIFY_DATA = ArrayConverter
            .hexStringToByteArray("cc111ca8d8d84321f1039b92");
    private static final byte[] MSG_DECRYPTED_WIRESHARK_CAP_1 = ArrayConverter
            .hexStringToByteArray("1400000c5ddfb413e7b592b4ec0186c5");
    private static final byte[] MSG_DECRYPTED_WIRESHARK_CAP_1_VERIFY_DATA = ArrayConverter
            .hexStringToByteArray("5ddfb413e7b592b4ec0186c5");
    private static final byte[] MSG_CLIENT_FINISHED_VERIFY_DATA_SSL3 = ArrayConverter
            .hexStringToByteArray("ca89059c0d65ae7d5e0c11d99e7de49f830776fa43be27550285015fe254946754b8306f");
    private static final byte[] MSG_SERVER_FINISHED_VERIFY_DATA_SSL3 = ArrayConverter
            .hexStringToByteArray("d9f3911c7cd84b44bd3aa9fa730fc9883fdadfa90ac7e7d1c68fa7ef19749f263c3a1811");
    private static final byte[] SSL3_FINISHED_HEADER = ArrayConverter.hexStringToByteArray("14000024");
    private static final byte[] MSG_CLIENT_FINISHED_SSL3 = ArrayConverter.concatenate(SSL3_FINISHED_HEADER,
            MSG_CLIENT_FINISHED_VERIFY_DATA_SSL3);
    private static final byte[] MSG_SERVER_FINISHED_SSL3 = ArrayConverter.concatenate(SSL3_FINISHED_HEADER,
            MSG_SERVER_FINISHED_VERIFY_DATA_SSL3);

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { MSG_0, 0, MSG_0, HandshakeMessageType.FINISHED, 12, MSG_0_VERIFY_DATA, ProtocolVersion.TLS12 },
                { MSG_1, 6, MSG_0, HandshakeMessageType.FINISHED, 12, MSG_0_VERIFY_DATA, ProtocolVersion.TLS12 },
                { MSG_DECRYPTED_WIRESHARK_CAP_0, 0, MSG_DECRYPTED_WIRESHARK_CAP_0, HandshakeMessageType.FINISHED, 12,
                        MSG_DECRYPTED_WIRESHARK_CAP_0_VERIFY_DATA, ProtocolVersion.TLS12 },
                { MSG_DECRYPTED_WIRESHARK_CAP_1, 0, MSG_DECRYPTED_WIRESHARK_CAP_1, HandshakeMessageType.FINISHED, 12,
                        MSG_DECRYPTED_WIRESHARK_CAP_1_VERIFY_DATA, ProtocolVersion.TLS12 },

                { MSG_CLIENT_FINISHED_SSL3, 0, MSG_CLIENT_FINISHED_SSL3, HandshakeMessageType.FINISHED, 36,
                        MSG_CLIENT_FINISHED_VERIFY_DATA_SSL3, ProtocolVersion.SSL3 },
                { MSG_SERVER_FINISHED_SSL3, 0, MSG_SERVER_FINISHED_SSL3, HandshakeMessageType.FINISHED, 36,
                        MSG_SERVER_FINISHED_VERIFY_DATA_SSL3, ProtocolVersion.SSL3 } });
    }

    private final byte[] message;
    private final int start;
    private final byte[] expectedPart;

    private final HandshakeMessageType type;
    private final int length;

    private final byte[] verifyData;

    private final ProtocolVersion version;

    public FinishedMessageParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, byte[] verifyData, ProtocolVersion version) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.verifyData = verifyData;
        this.version = version;
    }

    /**
     * Test of parse method, of class FinishedParser.
     */
    @Test
    public void testParse() {
        FinishedParser parser = new FinishedParser(start, message, version);
        FinishedMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertArrayEquals(verifyData, msg.getVerifyData().getValue());
    }
}