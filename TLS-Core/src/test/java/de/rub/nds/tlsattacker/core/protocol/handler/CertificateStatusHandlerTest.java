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
import org.junit.jupiter.api.Test;

public class CertificateStatusHandlerTest
    extends AbstractTlsMessageHandlerTest<CertificateStatusMessage, CertificateStatusHandler> {

    public CertificateStatusHandlerTest() {
        super(CertificateStatusMessage::new, CertificateStatusHandler::new);
    }

    @Test
    @Override
    public void testAdjustTLSContext() {
        CertificateStatusMessage message = new CertificateStatusMessage();
        handler.adjustTLSContext(message);
        // TODO: make sure that nothing changed
    }
}
