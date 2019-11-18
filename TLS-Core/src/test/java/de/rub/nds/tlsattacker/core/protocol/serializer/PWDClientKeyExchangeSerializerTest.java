/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import static org.junit.Assert.*;
import org.junit.Test;

public class PWDClientKeyExchangeSerializerTest {

    @Test
    public void serializeHandshakeMessageContent() {
        byte[] message = ArrayConverter.hexStringToByteArray(("10 00 00 63 41 04 a0 c6 9b 45 0b\n"
                + "     85 ae e3 9f 64 6b 6e 64 d3 c1 08 39 5f 4b a1 19\n"
                + "     2d bf eb f0 de c5 b1 89 13 1f 59 5d d4 ba cd bd\n"
                + "     d6 83 8d 92 19 fd 54 29 91 b2 c0 b0 e4 c4 46 bf\n"
                + "     e5 8f 3c 03 39 f7 56 e8 9e fd a0 20 66 92 44\n"
                + "     aa 67 cb 00 ea 72 c0 9b 84 a9 db 5b b8 24 fc 39\n"
                + "     82 42 8f cd 40 69 63 ae 08 0e 67 7a 48").replaceAll("\\s+", ""));

        byte[] element = ArrayConverter.hexStringToByteArray(("04 a0 c6 9b 45 0b 85 ae e3 9f 64 6b 6e 64 d3 c1\n"
                + "             08 39 5f 4b a1 19 2d bf eb f0 de c5 b1 89 13 1f\n"
                + "             59 5d d4 ba cd bd d6 83 8d 92 19 fd 54 29 91 b2\n"
                + "             c0 b0 e4 c4 46 bf e5 8f 3c 03 39 f7 56 e8 9e fd\n" + "             a0").replaceAll(
                "\\s+", ""));

        byte[] scalar = ArrayConverter.hexStringToByteArray(("66 92 44 aa 67 cb 00 ea 72 c0 9b 84 a9 db 5b b8\n"
                + "             24 fc 39 82 42 8f cd 40 69 63 ae 08 0e 67 7a 48").replaceAll("\\s+", ""));

        PWDClientKeyExchangeMessage msg = new PWDClientKeyExchangeMessage();
        msg.setType(HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue());
        msg.setLength(99);
        msg.setElement(element);
        msg.setElementLength(65);
        msg.setScalar(scalar);
        msg.setScalarLength(32);
        PWDClientKeyExchangeSerializer serializer = new PWDClientKeyExchangeSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(message, serializer.serialize());
    }
}