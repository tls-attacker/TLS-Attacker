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
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
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
        if (group != null) {
            LOGGER.debug("Adjusting selected named group: " + group.name());
            tlsContext.setSelectedGroup(group);
        }
        if (group == NamedGroup.ECDH_X448 || group == NamedGroup.ECDH_X25519) {
            LOGGER.debug("Adjusting Montgomery EC Point");
            Point publicKey = Point.createPoint(new BigInteger(message.getPublicKey().getValue()), null, group);
            tlsContext.setServerEcPublicKey(publicKey);
        } else if (group != null) {
            LOGGER.debug("Adjusting EC Point");
            Point publicKeyPoint = PointFormatter.formatFromByteArray(group, message.getPublicKey().getValue());
            tlsContext.setServerEcPublicKey(publicKeyPoint);
        } else {
            LOGGER.warn("Could not adjust server public key, named group is unknown.");
        }
    }
}
