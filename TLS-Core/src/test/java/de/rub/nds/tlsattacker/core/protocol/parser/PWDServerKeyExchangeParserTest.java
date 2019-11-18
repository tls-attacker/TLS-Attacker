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
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class PWDServerKeyExchangeParserTest {

    public PWDServerKeyExchangeParserTest() {
    }

    @Test
    public void testParse() {

        byte[] message = ArrayConverter.hexStringToByteArray(("0c 00 00 87 20 96 3c 77 cd c1\n"
                + "     3a 2a 8d 75 cd dd d1 e0 44 99 29 84 37 11 c2 1d\n"
                + "     47 ce 6e 63 83 cd da 37 e4 7d a3 03 00 1a 41 04\n"
                + "     22 bb d5 6b 48 1d 7f a9 0c 35 e8 d4 2f cd 06 61\n"
                + "     8a 07 78 de 50 6b 1b c3 88 82 ab c7 31 32 ee f3\n"
                + "     7f 02 e1 3b d5 44 ac c1 45 bd d8 06 45 0d 43 be\n"
                + "     34 b9 28 83 48 d0 3d 6c d9 83 24 87 b1 29 db e1\n"
                + "     20 2f 70 48 96 69 9f c4 24 d3 ce c3 37 17 64\n"
                + "     4f 5a df 7f 68 48 34 24 ee 51 49 2b b9 66 13 fc\n" + "     49 21").replaceAll("\\s+", ""));

        byte[] salt = ArrayConverter.hexStringToByteArray(("96 3c 77 cd c1 3a 2a 8d 75 cd dd d1 e0 44 99 29\n"
                + "             84 37 11 c2 1d 47 ce 6e 63 83 cd da 37 e4 7d a3").replaceAll("\\s+", ""));

        byte[] element = ArrayConverter.hexStringToByteArray(("04 22 bb d5 6b 48 1d 7f a9 0c 35 e8 d4 2f cd 06\n"
                + "             61 8a 07 78 de 50 6b 1b c3 88 82 ab c7 31 32 ee\n"
                + "             f3 7f 02 e1 3b d5 44 ac c1 45 bd d8 06 45 0d 43\n"
                + "             be 34 b9 28 83 48 d0 3d 6c d9 83 24 87 b1 29 db\n" + "             e1").replaceAll(
                "\\s+", ""));

        byte[] scalar = ArrayConverter.hexStringToByteArray(("2f 70 48 96 69 9f c4 24 d3 ce c3 37 17 64 4f 5a\n"
                + "             df 7f 68 48 34 24 ee 51 49 2b b9 66 13 fc 49 21").replaceAll("\\s+", ""));
        PWDServerKeyExchangeParser parser = new PWDServerKeyExchangeParser(0, message, ProtocolVersion.TLS12);
        PWDServerKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertEquals(135, (long) msg.getLength().getValue());
        assertEquals(HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue(), (long) msg.getType().getValue());
        assertEquals(32, (long) msg.getSaltLength().getValue());
        assertEquals(EllipticCurveType.NAMED_CURVE.getValue(), (long) msg.getGroupType().getValue());
        assertArrayEquals(NamedGroup.BRAINPOOLP256R1.getValue(), msg.getNamedGroup().getValue());
        assertArrayEquals(salt, msg.getSalt().getValue());
        assertEquals(65, (long) msg.getElementLength().getValue());
        assertArrayEquals(element, msg.getElement().getValue());
        assertEquals(32, (long) msg.getScalarLength().getValue());
        assertArrayEquals(scalar, msg.getScalar().getValue());
    }

}
