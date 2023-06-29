/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class GenericReceiveActionTest extends AbstractActionTest<GenericReceiveAction> {

    private final TlsContext tlsContext;

    private final AlertMessage alert;

    public GenericReceiveActionTest() {
        super(new GenericReceiveAction(), GenericReceiveAction.class);

        alert = new AlertMessage();
        alert.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        alert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());

        tlsContext = state.getTlsContext();
        tlsContext
                .getContext()
                .getTcpContext()
                .setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    }

    /** Test of execute method, of class GenericReceiveAction. */
    @Test
    public void testExecute() throws Exception {
        ((FakeTransportHandler) tlsContext.getContext().getTransportHandler())
                .setFetchableByte(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50});
        super.testExecute();
        assertEquals(action.getReceivedMessages().get(0), alert);
    }
}
