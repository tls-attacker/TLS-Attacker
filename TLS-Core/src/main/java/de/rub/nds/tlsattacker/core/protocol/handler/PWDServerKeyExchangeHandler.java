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
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PWDServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PWDServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PWDServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;

public class PWDServerKeyExchangeHandler extends ServerKeyExchangeHandler<PWDServerKeyExchangeMessage> {
    public PWDServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PWDServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PWDServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
                AlgorithmResolver.getKeyExchangeAlgorithm(tlsContext.getChooser().getSelectedCipherSuite()));
    }

    @Override
    public PWDServerKeyExchangePreparator getPreparator(PWDServerKeyExchangeMessage message) {
        return new PWDServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PWDServerKeyExchangeSerializer getSerializer(PWDServerKeyExchangeMessage message) {
        return new PWDServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PWDServerKeyExchangeMessage message) {
        tlsContext.setSelectedGroup(NamedGroup.getNamedGroup(message.getNamedGroup().getValue()));
        ECCurve curve = ECNamedCurveTable.getParameterSpec(tlsContext.getSelectedGroup().getJavaName()).getCurve();
        tlsContext.setServerPWDSalt(message.getSalt().getValue());
        tlsContext.setServerPWDElement(curve.decodePoint(message.getElement().getValue()));
        tlsContext.setServerPWDScalar(new BigInteger(1, message.getScalar().getValue()));
        if (message.getComputations() != null) {
            tlsContext.setPWDPE(message.getComputations().getPE());
            tlsContext.setServerPWDPrivate(message.getComputations().getPrivate());
        }
    }
}
