/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import static org.junit.Assert.*;
import org.junit.Test;

public class UnknownParserTest {

    private UnknownParser parser;

    /**
     * Test of parse method, of class UnknownParser.
     */
    @Test
    public void testParse() {
        parser = new UnknownParser(0, new byte[] { 0, 1, 2, 3 }, ProtocolVersion.TLS12);
        UnknownMessage message = parser.parse();
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, message.getCompleteResultingMessage().getValue());
        parser = new UnknownParser(1, new byte[] { 0, 1, 2, 3 }, ProtocolVersion.TLS12);
        message = parser.parse();
        assertArrayEquals(new byte[] { 1, 2, 3 }, message.getCompleteResultingMessage().getValue());
    }

}
