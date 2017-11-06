/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.SupplementalDataMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SupplementalDataMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SupplementalDataMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;



public class SupplementalDataMessageHandler extends HandshakeMessageHandler<SupplementalDataMessage> {
    public SupplementalDataMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public SupplementalDataMessageParser getParser(byte[] message, int pointer) {
        return new SupplementalDataMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public SupplementalDataMessagePreparator getPreparator(SupplementalDataMessage message) {
        return new SupplementalDataMessagePreparator(this.tlsContext.getChooser(), message);
    }

    @Override
    public SupplementalDataMessageSerializer getSerializer(SupplementalDataMessage message) {
        return new SupplementalDataMessageSerializer(message, this.tlsContext.getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(SupplementalDataMessage message) {

    }
}
