/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.crypto.ec_.Point;
import de.rub.nds.tlsattacker.core.crypto.ec_.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;

public class ECDHClientKeyExchangeHandler extends ClientKeyExchangeHandler<ECDHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECDHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ECDHClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new ECDHClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
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
            tlsContext.setClientEcPublicKey(new CustomECPoint(new BigInteger(serializedPoint), null));
        } else {
            LOGGER.debug("Adjusting EC Point");
            Point publicKey = PointFormatter.formatFromByteArray(usedGroup, serializedPoint);
            tlsContext.setClientEcPublicKey(new CustomECPoint(publicKey.getX().getData(), publicKey.getY().getData()));
        }
    }
}
