/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

public class CertificateVerifyHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                CertificateVerifyMessage, CertificateVerifyHandler> {

    public CertificateVerifyHandlerTest() {
        super(CertificateVerifyMessage::new, CertificateVerifyHandler::new);
    }

    /** Test of adjustContext method, of class CertificateVerifyHandler. */
    @Test
    @Override
    public void testadjustContext() {
        CertificateVerifyMessage message = new CertificateVerifyMessage();
        message.getPreparator(new Context(new State(new Config()), new OutboundConnection()))
                .prepare();
        handler.adjustContext(message);
    }
}
