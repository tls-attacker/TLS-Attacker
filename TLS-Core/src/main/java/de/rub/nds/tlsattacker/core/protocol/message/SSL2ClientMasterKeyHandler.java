/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ClientMasterKeyPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.SSL2ClientMasterKeySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class SSL2ClientMasterKeyHandler extends ProtocolMessageHandler<SSL2ClientMasterKeyMessage> {

    public SSL2ClientMasterKeyHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        // TODO
        return null;
    }

    @Override
    public SSL2ClientMasterKeyPreparator getPreparator(SSL2ClientMasterKeyMessage message) {
        return new SSL2ClientMasterKeyPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public SSL2ClientMasterKeySerializer getSerializer(SSL2ClientMasterKeyMessage message) {
        return new SSL2ClientMasterKeySerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(SSL2ClientMasterKeyMessage message) {
        // we do not adjust anything since we dont support the complete ssl2
        // handshake anyways
    }

}
