/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class SendActionTest extends AbstractActionTest<SendAction> {

    public SendActionTest() {
        super(new SendAction(), SendAction.class);
        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        alert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        action.setMessages(alert);

        TlsContext context = state.getTlsContext();
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        context.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    // TODO: Override testExecute and check fake transport handler
}
