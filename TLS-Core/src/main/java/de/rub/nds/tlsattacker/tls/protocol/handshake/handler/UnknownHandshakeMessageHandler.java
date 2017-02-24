/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.handler;

import de.rub.nds.tlsattacker.tls.protocol.handshake.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownHandshakeMessageHandler extends HandshakeMessageHandler<UnknownHandshakeMessage> {

    public UnknownHandshakeMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
        throw new UnsupportedOperationException("Unsupported yet");
    }

    @Override
    protected byte[] prepareMessageAction() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected int parseMessageAction(byte[] message, int pointer) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
