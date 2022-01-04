/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateStatusPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateStatusSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class CertificateStatusHandlerTest {

    private CertificateStatusHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new CertificateStatusHandler(context);
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof CertificateStatusParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new CertificateStatusMessage()) instanceof CertificateStatusPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new CertificateStatusMessage()) instanceof CertificateStatusSerializer);
    }

    @Test
    public void testAdjustTLSContext() {
        CertificateStatusMessage message = new CertificateStatusMessage();
        handler.adjustTLSContext(message);
        // TODO: make sure that nothing changed
    }
}
