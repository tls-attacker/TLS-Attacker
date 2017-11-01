/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.SRPClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.SRPClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SRPClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SRPClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * Handler for SRP ClientKeyExchange messages
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class SRPClientKeyExchangeHandler extends ClientKeyExchangeHandler<SRPClientKeyExchangeMessage> {

    public SRPClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public SRPClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new SRPClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public SRPClientKeyExchangePreparator getPreparator(SRPClientKeyExchangeMessage message) {
        return new SRPClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public SRPClientKeyExchangeSerializer getSerializer(SRPClientKeyExchangeMessage message) {
        return new SRPClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(SRPClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
