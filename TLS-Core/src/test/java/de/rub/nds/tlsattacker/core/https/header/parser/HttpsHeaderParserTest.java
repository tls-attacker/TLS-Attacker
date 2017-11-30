/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import org.junit.Test;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HttpsHeaderParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("486f73743a207275622e636f6d0A"), 0,
                "Host", "rub.com" } });
    }

    private final byte[] message;
    private final int start;
    private final String headerName;
    private final String headerValue;

    public HttpsHeaderParserTest(byte[] message, int start, String headerName, String headerValue) {
        this.message = message;
        this.start = start;
        this.headerName = headerName;
        this.headerValue = headerValue;
    }

    /**
     * Test of parse method, of class HttpsHeaderParser.
     */
    @Test
    public void testParse() {
        HttpsHeaderParser parser = new HttpsHeaderParser(0, message);
        HttpsHeader header = parser.parse();

        assertTrue(headerName.equals(header.getHeaderName().getValue()));
        assertTrue(headerValue.equals(header.getHeaderValue().getValue()));
    }

}