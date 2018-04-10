/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateVerifyParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateVerifyPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateVerifySerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class CertificateVerifyHandlerTest {

    private CertificateVerifyHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new CertificateVerifyHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class CertificateVerifyHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof CertificateVerifyParser);
    }

    /**
     * Test of getPreparator method, of class CertificateVerifyHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new CertificateVerifyMessage()) instanceof CertificateVerifyPreparator);
    }

    /**
     * Test of getSerializer method, of class CertificateVerifyHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new CertificateVerifyMessage()) instanceof CertificateVerifySerializer);
    }

    /**
     * Test of adjustTLSContext method, of class CertificateVerifyHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        CertificateVerifyMessage message = new CertificateVerifyMessage();
        handler.adjustTLSContext(message);
        // TODO make sure that nothing changed
    }

}
