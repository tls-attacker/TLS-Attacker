/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloRequestMessage;
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
public class HelloRequestParserTest {
    
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                        },
                        {
                        }});
    }
    private byte[] message;
    private int start;
    private byte[] expectedPart;
    
    private HandshakeMessageType type;
    private int length;

    public HelloRequestParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type, int length) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
    }
    
    /**
     * Test of parse method, of class HelloRequestParser.
     */
    @Test
    public void testParse() {
        HelloRequestParser parser = new HelloRequestParser(start, message);
        HelloRequestMessage msg = parser.parse();
        assertArrayEquals(expectedPart,msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length );
        assertTrue(msg.getType().getValue() == type.getValue() );
    }
    
}
