/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.protocol.handler.TlsMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class TokenBindingMessageHandler extends TlsMessageHandler<TokenBindingMessage> {

    public TokenBindingMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public TokenBindingMessageParser getParser(byte[] message, int pointer) {
        return new TokenBindingMessageParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
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
