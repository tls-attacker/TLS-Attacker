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

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElementF2m;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHClientKeyExchangeHandler extends ClientKeyExchangeHandler<ECDHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECDHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ECDHClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new ECDHClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
            tlsContext.getConfig());
    }

    @Override
    public ECDHClientKeyExchangePreparator getPreparator(ECDHClientKeyExchangeMessage message) {
        return new ECDHClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ECDHClientKeyExchangeSerializer getSerializer(ECDHClientKeyExchangeMessage message) {
        return new ECDHClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(ECDHClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        adjustClientPublicKey(message);
        setRecordCipher();
        spawnNewSession();
    }

    private void adjustClientPublicKey(ECDHClientKeyExchangeMessage message) {
        byte[] serializedPoint = message.getPublicKey().getValue();
        NamedGroup usedGroup = tlsContext.getChooser().getSelectedNamedGroup();
        if (usedGroup == NamedGroup.ECDH_X25519 || usedGroup == NamedGroup.ECDH_X448) {
            LOGGER.debug("Adjusting Montgomery EC PublicKey");
            // TODO This is only a temporary solution. Montgomery Curves need to
            // be integrated into the new EC framework
            RFC7748Curve curve = (RFC7748Curve) CurveFactory.getCurve(usedGroup);
            BigInteger xcoordinate;
            if (serializedPoint.length != 0) {
                xcoordinate = new BigInteger(serializedPoint);
            } else {
                LOGGER.warn("Encoding 0 length byte-array");
                xcoordinate = BigInteger.ZERO;
            }
            tlsContext.setClientEcPublicKey(curve.createAPointOnCurve(new BigInteger(serializedPoint)));
        } else {
            LOGGER.debug("Adjusting EC Point");
            Point publicKey = PointFormatter.formatFromByteArray(usedGroup, serializedPoint);
            tlsContext.setClientEcPublicKey(publicKey);
        }
    }
}
