/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class HttpsResponseParserTest {

    private HttpsResponseParser parser;

    public HttpsResponseParserTest() {
    }

    @Before
    public void setUp() {
        parser = new HttpsResponseParser(0, ArrayConverter.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAA"),
                ProtocolVersion.TLS12);
    }

    /**
     * Test of parseMessageContent method, of class HttpsResponseParser.
     */
    @Test(expected = ParserException.class)
    public void testParseMessageContent() {
        parser.parse();
    }

}
