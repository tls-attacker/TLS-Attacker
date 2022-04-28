/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CertificateVerifyHandlerTest {

    private CertificateVerifyHandler handler;
    private TlsContext tlsContext;

    @Before
    public void setUp() {
        tlsContext = new TlsContext();
        handler = new CertificateVerifyHandler(tlsContext);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of adjustContext method, of class CertificateVerifyHandler.
     */
    @Test
    public void testadjustContext() {
        CertificateVerifyMessage message = new CertificateVerifyMessage();
        handler.adjustContext(message);
        // TODO make sure that nothing changed
    }

}
