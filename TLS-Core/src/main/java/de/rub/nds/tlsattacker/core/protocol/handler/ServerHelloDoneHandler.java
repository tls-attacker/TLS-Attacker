/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloDoneParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloDonePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloDoneSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ServerHelloDoneHandler extends HandshakeMessageHandler<ServerHelloDoneMessage> {

    public ServerHelloDoneHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ServerHelloDoneParser getParser(byte[] message, int pointer) {
        return new ServerHelloDoneParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public ServerHelloDonePreparator getPreparator(ServerHelloDoneMessage message) {
        return new ServerHelloDonePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ServerHelloDoneSerializer getSerializer(ServerHelloDoneMessage message) {
        return new ServerHelloDoneSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(ServerHelloDoneMessage message) {
        // nothing to adjust here
    }
}
