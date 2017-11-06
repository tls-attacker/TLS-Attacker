/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.RSAClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.RSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RSAClientKeyExchangeHandler extends ClientKeyExchangeHandler<RSAClientKeyExchangeMessage> {

    public RSAClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public RSAClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new RSAClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public RSAClientKeyExchangePreparator getPreparator(RSAClientKeyExchangeMessage message) {
        return new RSAClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public RSAClientKeyExchangeSerializer getSerializer(RSAClientKeyExchangeMessage message) {
        return new RSAClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(RSAClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
