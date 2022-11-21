/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHClientKeyExchangeHandler<T extends ECDHClientKeyExchangeMessage> extends ClientKeyExchangeHandler<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECDHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ECDHClientKeyExchangeParser<T> getParser(byte[] message, int pointer) {
        return new ECDHClientKeyExchangeParser<>(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public ECDHClientKeyExchangePreparator<T> getPreparator(T message) {
        return new ECDHClientKeyExchangePreparator<>(tlsContext.getChooser(), message);
    }

    @Override
    public ECDHClientKeyExchangeSerializer<T> getSerializer(T message) {
        return new ECDHClientKeyExchangeSerializer<>(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(T message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        adjustClientPublicKey(message);
        spawnNewSession();
    }

    private void adjustClientPublicKey(T message) {
        byte[] serializedPoint = message.getPublicKey().getValue();
        NamedGroup usedGroup = tlsContext.getChooser().getSelectedNamedGroup();
        LOGGER.debug("Adjusting EC Point");
        Point publicKey = PointFormatter.formatFromByteArray(usedGroup, serializedPoint);
        tlsContext.setClientEcPublicKey(publicKey);
    }
}
