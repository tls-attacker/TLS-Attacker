/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class ClientCertificateUrlExtensionHandlerTest {
    private ClientCertificateUrlExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ClientCertificateUrlExtensionHandler(context);
    }

    @Test
    public void testadjustContext() {
        ClientCertificateUrlExtensionMessage message = new ClientCertificateUrlExtensionMessage();
        handler.adjustContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.CLIENT_CERTIFICATE_URL));
    }
}
