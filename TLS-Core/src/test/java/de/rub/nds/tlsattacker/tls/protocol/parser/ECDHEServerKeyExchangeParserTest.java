/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
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
public class ECDHEServerKeyExchangeParserTest {
    
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                            ArrayConverter.hexStringToByteArray(""),
                        },
                        });
    }
    private byte[] message;
    private int start;
    private byte[] expectedPart;
    
    private HandshakeMessageType type;
    private int length;
    
    private int serializedKeyLength;
    private byte[] serializedKey;

    public ECDHEServerKeyExchangeParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type, int length, int serializedKeyLength, byte[] serializedKey) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
    }

    /**
     * Test of parse method, of class ECDHEServerKeyExchangeParser.
     */
    @Test
    public void testParse() {
        ECDHEServerKeyExchangeParser parser = new ECDHEServerKeyExchangeParser(start, message);
        ECDHEServerKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getSerializedPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getSerializedPublicKey().getValue());
    }
}
