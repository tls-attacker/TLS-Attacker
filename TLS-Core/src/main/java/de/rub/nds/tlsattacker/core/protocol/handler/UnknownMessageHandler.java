/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class UnknownMessageHandler extends TlsMessageHandler<UnknownMessage> {

    private final ProtocolMessageType recordContentMessageType;

    public UnknownMessageHandler(TlsContext tlsContext, ProtocolMessageType recordContentMessageType) {
        super(tlsContext);
        this.recordContentMessageType = recordContentMessageType;
    }

    @Override
    public UnknownMessageParser getParser(byte[] message, int pointer) {
        return new UnknownMessageParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            recordContentMessageType, tlsContext.getConfig());
    }

    @Override
    public UnknownMessagePreparator getPreparator(UnknownMessage message) {
        return new UnknownMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public UnknownMessageSerializer getSerializer(UnknownMessage message) {
        return new UnknownMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(UnknownMessage message) {
        // Nothing to do
    }

}
