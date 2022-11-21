/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.RSAClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.RSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RSAClientKeyExchangeHandler<T extends RSAClientKeyExchangeMessage> extends ClientKeyExchangeHandler<T> {

    public RSAClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public RSAClientKeyExchangeParser<T> getParser(byte[] message, int pointer) {
        return new RSAClientKeyExchangeParser<>(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public RSAClientKeyExchangePreparator<T> getPreparator(T message) {
        return new RSAClientKeyExchangePreparator<>(tlsContext.getChooser(), message);
    }

    @Override
    public RSAClientKeyExchangeSerializer<T> getSerializer(T message) {
        return new RSAClientKeyExchangeSerializer<>(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(T message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        spawnNewSession();
    }
}
