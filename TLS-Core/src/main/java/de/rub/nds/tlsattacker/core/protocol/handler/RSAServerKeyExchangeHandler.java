/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import java.math.BigInteger;

import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.RSAServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.RSAServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RSAServerKeyExchangeHandler extends ServerKeyExchangeHandler<RSAServerKeyExchangeMessage> {

    public RSAServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HandshakeMessageParser<RSAServerKeyExchangeMessage> getParser(byte[] message, int pointer) {
        return new RSAServerKeyExchangeParser<>(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public HandshakeMessagePreparator<RSAServerKeyExchangeMessage> getPreparator(RSAServerKeyExchangeMessage message) {
        return new RSAServerKeyExchangePreparator<RSAServerKeyExchangeMessage>(tlsContext.getChooser(), message);
    }

    @Override
    public HandshakeMessageSerializer<RSAServerKeyExchangeMessage> getSerializer(RSAServerKeyExchangeMessage message) {
        return new RSAServerKeyExchangeSerializer<RSAServerKeyExchangeMessage>(message,
            tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(RSAServerKeyExchangeMessage message) {
        tlsContext.setServerRSAModulus(new BigInteger(1, message.getModulus().getValue()));
        tlsContext.setServerRSAPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        if (message.getComputations() != null && message.getComputations().getPrivateKey() != null) {
            tlsContext.setServerRSAPrivateKey(message.getComputations().getPrivateKey().getValue());
        }
    }

}
