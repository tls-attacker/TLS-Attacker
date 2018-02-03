/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ClientMasterKeyPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SSL2ClientMasterKeySerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class SSL2ClientMasterKeyHandler extends ProtocolMessageHandler<SSL2ClientMasterKeyMessage> {

    public SSL2ClientMasterKeyHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ProtocolMessageParser<SSL2ClientMasterKeyMessage> getParser(byte[] message, int pointer) {
        // We currently don't receive ClientMasterKey messages, only send them.
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
        byte[] premasterSecret = message.getComputations().getPremasterSecret().getValue();
        tlsContext.setPreMasterSecret(premasterSecret);
    }

}
