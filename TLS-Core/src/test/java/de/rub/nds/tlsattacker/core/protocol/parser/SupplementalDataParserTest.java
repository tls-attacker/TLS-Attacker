/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
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
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray("00000e4002000a0008010005aaaaaaaaaa"), 14,
                ArrayConverter.hexStringToByteArray("4002000a0008010005aaaaaaaaaa"), ProtocolVersion.TLS11 },
            { ArrayConverter.hexStringToByteArray("00001c4002000a0008010005aaaaaaaaaa4002000a0008010005aaaaaaaaaa"), 28,
                ArrayConverter.hexStringToByteArray("4002000a0008010005aaaaaaaaaa4002000a0008010005aaaaaaaaaa"),
                ProtocolVersion.TLS11 } });
    }

    private byte[] message;
    private int supplementalDataLength;
    private byte[] supplementalDataBytes;
    private ProtocolVersion version;
    private final Config config = Config.createConfig();

    public SupplementalDataParserTest(byte[] message, int supplementalDataLength, byte[] supplementalDataBytes,
        ProtocolVersion version) {
        this.message = message;
        this.supplementalDataLength = supplementalDataLength;
        this.supplementalDataBytes = supplementalDataBytes;
        this.version = version;
    }

    @Test
    public void testParse() {
        SupplementalDataParser parser =
            new SupplementalDataParser(new ByteArrayInputStream(message), version, new TlsContext(config));
        SupplementalDataMessage suppDataMessage = new SupplementalDataMessage();
        parser.parse(suppDataMessage);
        assertTrue(suppDataMessage.getSupplementalDataLength().getValue() == supplementalDataLength);
        assertArrayEquals(suppDataMessage.getSupplementalDataBytes().getValue(), supplementalDataBytes);
    }

}
