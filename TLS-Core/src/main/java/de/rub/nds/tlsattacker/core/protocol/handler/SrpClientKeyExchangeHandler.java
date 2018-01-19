/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.SrpClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.SrpClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SrpClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SrpClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * Handler for SRP ClientKeyExchange messages
 *
 */
public class SrpClientKeyExchangeHandler extends ClientKeyExchangeHandler<SrpClientKeyExchangeMessage> {

    public SrpClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public SrpClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new SrpClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public SrpClientKeyExchangePreparator getPreparator(SrpClientKeyExchangeMessage message) {
        return new SrpClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public SrpClientKeyExchangeSerializer getSerializer(SrpClientKeyExchangeMessage message) {
        return new SrpClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(SrpClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
