/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import org.junit.Assert;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TokenBindingMessageParserTest {

    private TokenBindingMessageParser parser;

    private ProtocolVersion version;

    private byte[] toParse;

    @Before
    public void setUp() {
        toParse = ArrayConverter
                .hexStringToByteArray("00890002004140cf5e4044bfbb1a32467d030e860b716aaf9ba3a8de9d25235b377d18dd223e9dc3cc0b0afd115a4c6ec8d026800424516c66f3f25fc12f0cce205856e27910270040636328a37f1d393a3e94c7a45b522fd20eeb87435cade5b714c6a95b28fba126a44a3d1c933aaba0d6aa095d86dbf05bdc368ea591a6082f77f8eda85538f2c70000");
        version = ProtocolVersion.TLS12;
    }

    /**
     * Test of parseMessageContent method, of class TokenBindingMessageParser.
     */
    @Test
    public void testParseMessageContent() {
        parser = new TokenBindingMessageParser(0, toParse, version);
        TokenBindingMessage message = parser.parse();
        Assert.assertArrayEquals(new byte[0], message.getExtensionBytes().getValue());
        assertTrue(message.getExtensionLength().getValue() == 0);
        assertTrue(message.getSignatureLength().getValue() == 0x40);
        assertTrue(message.getPointLength().getValue() == 0x40);
        assertTrue(message.getKeyParameter().getValue() == 0x02);
        // TODO
        TokenBindingMessageSerializer serializer = new TokenBindingMessageSerializer(message, version);
        byte[] serialized = serializer.serialize();
        Assert.assertArrayEquals(toParse, serialized);
    }
}
