/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class UnknownMessageHandler extends ProtocolMessageHandler<UnknownMessage> {

    private final ProtocolMessageType recordContentMessageType;

    public UnknownMessageHandler(TlsContext tlsContext, ProtocolMessageType recordContentMessageType) {
        super(tlsContext);
        this.recordContentMessageType = recordContentMessageType;
    }

    @Override
    public void adjustContext(UnknownMessage message) {
        // Nothing to do
    }

}
