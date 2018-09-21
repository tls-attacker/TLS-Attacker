/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownHandshakePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownHandshakeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class UnknownHandshakeHandler extends HandshakeMessageHandler<UnknownHandshakeMessage> {

    public UnknownHandshakeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSContext(UnknownHandshakeMessage message) {
        // nothing to adjust here
    }

    @Override
    public UnknownHandshakeParser getParser(byte[] message, int pointer) {
        return new UnknownHandshakeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public UnknownHandshakePreparator getPreparator(UnknownHandshakeMessage message) {
        return new UnknownHandshakePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public UnknownHandshakeSerializer getSerializer(UnknownHandshakeMessage message) {
        return new UnknownHandshakeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }
}
