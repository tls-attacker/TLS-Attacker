/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class TokenBindingMessageHandler extends ProtocolMessageHandler<TokenBindingMessage> {

    public TokenBindingMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public TokenBindingMessageParser getParser(byte[] message, int pointer) {
        return new TokenBindingMessageParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public TokenBindingMessagePreparator getPreparator(TokenBindingMessage message) {
        return new TokenBindingMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public TokenBindingMessageSerializer getSerializer(TokenBindingMessage message) {
        return new TokenBindingMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(TokenBindingMessage message) {

    }

}
