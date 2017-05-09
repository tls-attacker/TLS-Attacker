/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.handler.CertificateVerifyHandler;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateVerifyMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateVerifyMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateVerifyMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateVerifyHandlerTest {

    private CertificateVerifyHandler handler;
    private TlsContext context;

    public CertificateVerifyHandlerTest() {
    }

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
        assertTrue(handler.getParser(new byte[1], 0) instanceof CertificateVerifyMessageParser);
    }

    /**
     * Test of getPreparator method, of class CertificateVerifyHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new CertificateVerifyMessage()) instanceof CertificateVerifyMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class CertificateVerifyHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new CertificateVerifyMessage()) instanceof CertificateVerifyMessageSerializer);
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
