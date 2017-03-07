/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class RSAClientKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("100001020100dda7c19f09a87558e10eff5d9dfc1cda6f189959ea3771b872601ff02bcda22cf6b252a4c57c6c26c211289e8fd1fc24386f65ac80e66bc540b6e147b8852d1550c4bfa738aa1f090099a88ae1d8a2c80b7f78cd8e335ca70d2d35bb3f47cda0956cf3d7c5873730c31dbd7cf35409cdf9641ffc331d0384bd9165e82e4ee8518e1cb9b56121b94bfd2facbb6d0f7c107e76f7f04d3591e52cfe2f25387c9bc21c4176ffeb6fff10c09dd11dacf434949b760a3122a462010081cac196fb375f565dc94faf16c317388e797c45b6bb06d283ba4a6259712cd4a443b97ed9129407fc64dbe5134040f3374860f0b6f443365446a980e29841a8b6e3569b5929f6"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("100001020100dda7c19f09a87558e10eff5d9dfc1cda6f189959ea3771b872601ff02bcda22cf6b252a4c57c6c26c211289e8fd1fc24386f65ac80e66bc540b6e147b8852d1550c4bfa738aa1f090099a88ae1d8a2c80b7f78cd8e335ca70d2d35bb3f47cda0956cf3d7c5873730c31dbd7cf35409cdf9641ffc331d0384bd9165e82e4ee8518e1cb9b56121b94bfd2facbb6d0f7c107e76f7f04d3591e52cfe2f25387c9bc21c4176ffeb6fff10c09dd11dacf434949b760a3122a462010081cac196fb375f565dc94faf16c317388e797c45b6bb06d283ba4a6259712cd4a443b97ed9129407fc64dbe5134040f3374860f0b6f443365446a980e29841a8b6e3569b5929f6"),
                        HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                        258,
                        256,
                        ArrayConverter
                                .hexStringToByteArray("dda7c19f09a87558e10eff5d9dfc1cda6f189959ea3771b872601ff02bcda22cf6b252a4c57c6c26c211289e8fd1fc24386f65ac80e66bc540b6e147b8852d1550c4bfa738aa1f090099a88ae1d8a2c80b7f78cd8e335ca70d2d35bb3f47cda0956cf3d7c5873730c31dbd7cf35409cdf9641ffc331d0384bd9165e82e4ee8518e1cb9b56121b94bfd2facbb6d0f7c107e76f7f04d3591e52cfe2f25387c9bc21c4176ffeb6fff10c09dd11dacf434949b760a3122a462010081cac196fb375f565dc94faf16c317388e797c45b6bb06d283ba4a6259712cd4a443b97ed9129407fc64dbe5134040f3374860f0b6f443365446a980e29841a8b6e3569b5929f6") }, });
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    private int serializedKeyLength;
    private byte[] serializedKey;

    public RSAClientKeyExchangeParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, int serializedKeyLength, byte[] serializedKey) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
    }

    /**
     * Test of parse method, of class RSAClientKeyExchangeParser.
     */
    @Test
    public void testParse() {
        RSAClientKeyExchangeParser parser = new RSAClientKeyExchangeParser(start, message);
        RSAClientKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getSerializedPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getSerializedPublicKey().getValue());
    }

}
