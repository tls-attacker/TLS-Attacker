/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import java.math.BigInteger;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.RSAServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.RSAServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RSAServerKeyExchangeHandler extends ServerKeyExchangeHandler<RSAServerKeyExchangeMessage> {

    public RSAServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        return new RSAServerKeyExchangeParser<>(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
                AlgorithmResolver.getKeyExchangeAlgorithm(tlsContext.getChooser().getSelectedCipherSuite()),
                tlsContext.getConfig());
    }

    @Override
    public ProtocolMessagePreparator getPreparator(RSAServerKeyExchangeMessage message) {
        return new RSAServerKeyExchangePreparator<RSAServerKeyExchangeMessage>(tlsContext.getChooser(), message);
    }

    @Override
    public ProtocolMessageSerializer getSerializer(RSAServerKeyExchangeMessage message) {
        return new RSAServerKeyExchangeSerializer<RSAServerKeyExchangeMessage>(message, tlsContext.getChooser()
                .getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(RSAServerKeyExchangeMessage message) {
        tlsContext.setServerRsaModulus(new BigInteger(1, message.getModulus().getValue()));
        tlsContext.setServerRSAPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        if (message.getComputations() != null && message.getComputations().getPrivateKey() != null) {
            tlsContext.setServerRSAPrivateKey(message.getComputations().getPrivateKey().getValue());
        }
    }

}
