/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PWDClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PWDClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PWDClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

public class PWDClientKeyExchangeHandler extends ClientKeyExchangeHandler<PWDClientKeyExchangeMessage> {
    public PWDClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PWDClientKeyExchangeParser getParser(InputStream stream) {
        return new PWDClientKeyExchangeParser(stream, tlsContext.getChooser().getLastRecordVersion(),
            AlgorithmResolver.getKeyExchangeAlgorithm(tlsContext.getChooser().getSelectedCipherSuite()),
            tlsContext.getConfig());
    }

    @Override
    public PWDClientKeyExchangePreparator getPreparator(PWDClientKeyExchangeMessage message) {
        return new PWDClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PWDClientKeyExchangeSerializer getSerializer(PWDClientKeyExchangeMessage message) {
        return new PWDClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PWDClientKeyExchangeMessage message) {
        if (message.getComputations() != null) {
            tlsContext.setPWDPE(message.getComputations().getPasswordElement());
            tlsContext.setClientPWDPrivate(message.getComputations().getPrivateKeyScalar());
        }

        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        spawnNewSession();
    }
}