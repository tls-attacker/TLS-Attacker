/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.converters;

import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class StarttlsTypeConverterTest {
    private StarttlsTypeConverter converter;

    @Before
    public void setUp() {
        converter = new StarttlsTypeConverter();
    }

    /**
     * Test of convert method, of class StarttlsTypeConverter.
     */
    @Test
    public void testConvert() {
        assertTrue(StarttlsType.FTP == converter.convert("FTP"));
        assertTrue(StarttlsType.IMAP == converter.convert("IMAP"));
        assertTrue(StarttlsType.POP3 == converter.convert("POP3"));
        assertTrue(StarttlsType.SMTP == converter.convert("SMTP"));
    }

}
