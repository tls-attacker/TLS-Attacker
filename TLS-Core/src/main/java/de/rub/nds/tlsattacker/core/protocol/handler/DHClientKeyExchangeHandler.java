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
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * Handler for DH and DHE ClientKeyExchange messages
 */
public class DHClientKeyExchangeHandler extends ClientKeyExchangeHandler<DHClientKeyExchangeMessage> {

    public DHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public DHClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new DHClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public DHClientKeyExchangePreparator getPreparator(DHClientKeyExchangeMessage message) {
        return new DHClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public DHClientKeyExchangeSerializer getSerializer(DHClientKeyExchangeMessage message) {
        return new DHClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(DHClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
