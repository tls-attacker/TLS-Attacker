/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.io.ByteArrayInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TokenBindingMessageParserTest {

    private ProtocolVersion version;

    private Config config;

    private byte[] toParse;

    @BeforeEach
    public void setUp() {
        config = Config.createConfig();
        toParse =
                ArrayConverter.hexStringToByteArray(
                        "00890002004140cf5e4044bfbb1a32467d030e860b716aaf9ba3a8de9d25235b377d18dd223e9dc3cc0b0afd115a4c6ec8d026800424516c66f3f25fc12f0cce205856e27910270040636328a37f1d393a3e94c7a45b522fd20eeb87435cade5b714c6a95b28fba126a44a3d1c933aaba0d6aa095d86dbf05bdc368ea591a6082f77f8eda85538f2c70000");
        version = ProtocolVersion.TLS12;
    }

    /** Test of parseMessageContent method, of class TokenBindingMessageParser. */
    @Test
    public void testParseMessageContent() {
        TokenBindingMessageParser parser =
                new TokenBindingMessageParser(new ByteArrayInputStream(toParse));
        TokenBindingMessage message = new TokenBindingMessage();
        parser.parse(message);
        assertArrayEquals(new byte[0], message.getExtensionBytes().getValue());
        assertEquals(0, (int) message.getExtensionLength().getValue());
        assertEquals(0x40, (int) message.getSignatureLength().getValue());
        assertEquals(0x40, (int) message.getPointLength().getValue());
        assertEquals(0x02, (byte) message.getKeyParameter().getValue());
        // TODO
        TokenBindingMessageSerializer serializer = new TokenBindingMessageSerializer(message);
        byte[] serialized = serializer.serialize();
        assertArrayEquals(toParse, serialized);
    }
}
