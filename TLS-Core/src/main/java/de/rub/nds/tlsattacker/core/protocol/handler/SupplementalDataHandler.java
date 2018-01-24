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
import de.rub.nds.tlsattacker.core.protocol.parser.SupplementalDataParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SupplementalDataPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SupplementalDataSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class SupplementalDataHandler extends HandshakeMessageHandler<SupplementalDataMessage> {
    public SupplementalDataHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public SupplementalDataParser getParser(byte[] message, int pointer) {
        return new SupplementalDataParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public SupplementalDataPreparator getPreparator(SupplementalDataMessage message) {
        return new SupplementalDataPreparator(this.tlsContext.getChooser(), message);
    }

    @Override
    public SupplementalDataSerializer getSerializer(SupplementalDataMessage message) {
        return new SupplementalDataSerializer(message, this.tlsContext.getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(SupplementalDataMessage message) {

    }
}
