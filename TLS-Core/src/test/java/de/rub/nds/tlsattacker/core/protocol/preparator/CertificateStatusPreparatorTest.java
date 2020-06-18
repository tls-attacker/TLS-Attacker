/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

public class CertificateStatusPreparatorTest {

    private CertificateStatusMessage message;
    private CertificateStatusPreparator preparator;
    private TlsContext context;

    @Before
    public void setUp() {
        message = new CertificateStatusMessage();
        context = new TlsContext();
        preparator = new CertificateStatusPreparator(context.getChooser(), message);
    }

    // TODO: Preparator is a stub so far, so no special tests here so far.
    @Test
    public void testPrepare() {
        preparator.prepare();
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
