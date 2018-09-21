/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.SSL2ServerVerifyParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ServerVerifyPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class SSL2ServerVerifyHandler extends HandshakeMessageHandler<SSL2ServerVerifyMessage> {

    public SSL2ServerVerifyHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ProtocolMessageParser<SSL2ServerVerifyMessage> getParser(byte[] message, int pointer) {
        return new SSL2ServerVerifyParser(message, pointer, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public ProtocolMessagePreparator<SSL2ServerVerifyMessage> getPreparator(SSL2ServerVerifyMessage message) {
        return new SSL2ServerVerifyPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public void adjustTLSContext(SSL2ServerVerifyMessage message) {
    }

    @Override
    public ProtocolMessageSerializer<SSL2ServerVerifyMessage> getSerializer(SSL2ServerVerifyMessage message) {
        // We currently don't send ServerVerify messages, only receive them.
        return null;
    }

}
