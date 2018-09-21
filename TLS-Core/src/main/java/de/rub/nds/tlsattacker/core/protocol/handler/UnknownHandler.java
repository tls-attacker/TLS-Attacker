/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class UnknownHandler extends ProtocolMessageHandler<UnknownMessage> {

    public UnknownHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public UnknownParser getParser(byte[] message, int pointer) {
        return new UnknownParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public UnknownPreparator getPreparator(UnknownMessage message) {
        return new UnknownPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public UnknownSerializer getSerializer(UnknownMessage message) {
        return new UnknownSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(UnknownMessage message) {
        // Nothing to do
    }

}
