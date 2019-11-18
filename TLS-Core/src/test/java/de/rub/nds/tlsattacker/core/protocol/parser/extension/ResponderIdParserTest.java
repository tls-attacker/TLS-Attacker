/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class ResponderIdParserTest {

    private final Integer idLength = 6;
    private final byte[] id = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    private final byte[] payloadBytes = new byte[] { 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    private final int startParsing = 0;
    private ResponderIdParser parser;
    private ResponderId parsedId;

    @Test
    public void testParser() {
        parser = new ResponderIdParser(startParsing, payloadBytes);
        parsedId = parser.parse();

        assertEquals(idLength, parsedId.getIdLength().getValue());
        assertArrayEquals(id, parsedId.getId().getValue());
    }
}
