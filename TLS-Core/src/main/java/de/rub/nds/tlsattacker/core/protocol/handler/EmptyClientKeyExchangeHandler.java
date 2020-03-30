/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.EmptyClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.EmptyClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.EmptyClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * Handler for DH and DHE ClientKeyExchange messages
 */
public class EmptyClientKeyExchangeHandler extends ClientKeyExchangeHandler<EmptyClientKeyExchangeMessage> {

    public EmptyClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public EmptyClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new EmptyClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public EmptyClientKeyExchangePreparator getPreparator(EmptyClientKeyExchangeMessage message) {
        return new EmptyClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public EmptyClientKeyExchangeSerializer getSerializer(EmptyClientKeyExchangeMessage message) {
        return new EmptyClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(EmptyClientKeyExchangeMessage message) {
        setRecordCipher();
        spawnNewSession();
    }
}
