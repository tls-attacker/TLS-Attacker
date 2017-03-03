/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.protocol.message.UnknownMessage;
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
public class UnknownMessageParserTest {

    private UnknownMessageParser parser;

    public UnknownMessageParserTest() {
    }

    /**
     * Test of parse method, of class UnknownMessageParser.
     */
    @Test
    public void testParse() {
        parser = new UnknownMessageParser(0, new byte[] { 0, 1, 2, 3 });
        UnknownMessage message = parser.parse();
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, message.getCompleteResultingMessage().getValue());
        parser = new UnknownMessageParser(1, new byte[] { 0, 1, 2, 3 });
        message = parser.parse();
        assertArrayEquals(new byte[] { 1, 2, 3 }, message.getCompleteResultingMessage().getValue());
    }

}
