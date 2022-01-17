/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.TlsMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;

public class UnknownMessageHandler extends ProtocolMessageHandler<UnknownMessage> {

    private final TlsMessageType recordContentMessageType;

    public UnknownMessageHandler(TlsContext context, TlsMessageType recordContentMessageType) {
        super(context);
        this.recordContentMessageType = recordContentMessageType;
    }

    @Override
    public void adjustContext(UnknownMessage message) {
        // Nothing to do
    }

}
