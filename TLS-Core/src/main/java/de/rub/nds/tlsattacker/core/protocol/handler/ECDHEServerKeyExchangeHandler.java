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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.crypto.ec_.Point;
import de.rub.nds.tlsattacker.core.crypto.ec_.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHEServerKeyExchangeHandler<T extends ECDHEServerKeyExchangeMessage> extends ServerKeyExchangeHandler<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECDHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ECDHEServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new ECDHEServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
                AlgorithmResolver.getKeyExchangeAlgorithm(tlsContext.getChooser().getSelectedCipherSuite()));
    }

    @Override
    public ECDHEServerKeyExchangePreparator getPreparator(ECDHEServerKeyExchangeMessage message) {
        return new ECDHEServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ECDHEServerKeyExchangeSerializer getSerializer(ECDHEServerKeyExchangeMessage message) {
        return new ECDHEServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(ECDHEServerKeyExchangeMessage message) {
        adjustECParameter(message);
        if (message.getComputations() != null) {
            tlsContext.setServerEcPrivateKey(message.getComputations().getPrivateKey().getValue());
        }
    }

    protected void adjustECParameter(ECDHEServerKeyExchangeMessage message) {
        NamedGroup group = NamedGroup.getNamedGroup(message.getNamedGroup().getValue());
        tlsContext.setSelectedGroup(group);
        if (group != null) {
            Point publicKeyPoint = PointFormatter.formatFromByteArray(group, message.getPublicKey().getValue());
            CustomECPoint publicKey = new CustomECPoint(publicKeyPoint.getX().getData(), publicKeyPoint.getY()
                    .getData());
            tlsContext.setServerEcPublicKey(publicKey);
        } else {
            LOGGER.warn("Could not adjust server public key, named group is unknown.");
        }
    }
}
