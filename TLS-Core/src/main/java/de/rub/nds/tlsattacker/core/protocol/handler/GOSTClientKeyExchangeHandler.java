/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.GOSTClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.GOST01ClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.GOST12ClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.GOSTClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class GOSTClientKeyExchangeHandler extends ClientKeyExchangeHandler<GOSTClientKeyExchangeMessage> {

    public GOSTClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        return new GOSTClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public ProtocolMessagePreparator getPreparator(GOSTClientKeyExchangeMessage message) {
        CipherSuite cipherSuite = tlsContext.getChooser().getSelectedCipherSuite();
        KeyExchangeAlgorithm exchangeAlg = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);
        if (exchangeAlg == KeyExchangeAlgorithm.VKO_GOST12) {
            return new GOST12ClientKeyExchangePreparator(tlsContext.getChooser(), message);
        } else {
            return new GOST01ClientKeyExchangePreparator(tlsContext.getChooser(), message);
        }
    }

    @Override
    public ProtocolMessageSerializer getSerializer(GOSTClientKeyExchangeMessage message) {
        return new GOSTClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(GOSTClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }

}
