/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.application;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ApplicationHandler extends ProtocolMessageHandler<ApplicationMessage> {

    public ApplicationHandler(TlsContext tlsContext) {
        super(tlsContext);
        this.correctProtocolMessageClass = ApplicationMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
        protocolMessage.setData("test".getBytes());
        byte[] result = protocolMessage.getData().getValue();
        return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
        protocolMessage.setData(Arrays.copyOfRange(message, pointer, message.length));
        return pointer + message.length;
    }

}