/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class FinishedMessageParserTest {

    private static final byte[] MSG_0_VERIFY_DATA =
        new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x66, 0x55, 0x44, 0x33 };

    private static final byte[] MSG_DECRYPTED_WIRESHARK_CAP_0 =
        ArrayConverter.hexStringToByteArray("cc111ca8d8d84321f1039b92");
    private static final byte[] MSG_DECRYPTED_WIRESHARK_CAP_0_VERIFY_DATA =
        ArrayConverter.hexStringToByteArray("cc111ca8d8d84321f1039b92");
    private static final byte[] MSG_DECRYPTED_WIRESHARK_CAP_1 =
        ArrayConverter.hexStringToByteArray("5ddfb413e7b592b4ec0186c5");
    private static final byte[] MSG_DECRYPTED_WIRESHARK_CAP_1_VERIFY_DATA =
        ArrayConverter.hexStringToByteArray("5ddfb413e7b592b4ec0186c5");
    private static final byte[] MSG_CLIENT_FINISHED_VERIFY_DATA_SSL3 =
        ArrayConverter.hexStringToByteArray("ca89059c0d65ae7d5e0c11d99e7de49f830776fa43be27550285015fe254946754b8306f");
    private static final byte[] MSG_SERVER_FINISHED_VERIFY_DATA_SSL3 =
        ArrayConverter.hexStringToByteArray("d9f3911c7cd84b44bd3aa9fa730fc9883fdadfa90ac7e7d1c68fa7ef19749f263c3a1811");

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { MSG_0_VERIFY_DATA, MSG_0_VERIFY_DATA, ProtocolVersion.TLS12 },
            { MSG_DECRYPTED_WIRESHARK_CAP_0, MSG_DECRYPTED_WIRESHARK_CAP_0_VERIFY_DATA, ProtocolVersion.TLS12 },
            { MSG_DECRYPTED_WIRESHARK_CAP_1, MSG_DECRYPTED_WIRESHARK_CAP_1_VERIFY_DATA, ProtocolVersion.TLS12 },
            { MSG_CLIENT_FINISHED_VERIFY_DATA_SSL3, MSG_CLIENT_FINISHED_VERIFY_DATA_SSL3, ProtocolVersion.SSL3 } });
    }

    private final byte[] message;

    private final byte[] verifyData;

    private final ProtocolVersion version;
    private final Config config = Config.createConfig();

    public FinishedMessageParserTest(byte[] message, byte[] verifyData, ProtocolVersion version) {
        this.message = message;
        this.verifyData = verifyData;
        this.version = version;
    }

    /**
     * Test of parse method, of class FinishedParser.
     */
    @Test
    public void testParse() {
        FinishedParser parser = new FinishedParser(new ByteArrayInputStream(message), version, new TlsContext(config));
        FinishedMessage msg = new FinishedMessage();
        parser.parse(msg);
        assertArrayEquals(verifyData, msg.getVerifyData().getValue());
    }
}
