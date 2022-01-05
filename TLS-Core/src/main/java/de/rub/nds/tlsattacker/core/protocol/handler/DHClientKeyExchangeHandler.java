/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Handler for DH and DHE ClientKeyExchange messages
 */
public class DHClientKeyExchangeHandler<T extends DHClientKeyExchangeMessage> extends ClientKeyExchangeHandler<T> {

    private Logger LOGGER = LogManager.getLogger();

    public DHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public DHClientKeyExchangeParser<T> getParser(byte[] message, int pointer) {
        return new DHClientKeyExchangeParser<T>(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
            tlsContext.getConfig());
    }

    @Override
    public DHClientKeyExchangePreparator<T> getPreparator(T message) {
        return new DHClientKeyExchangePreparator<T>(tlsContext.getChooser(), message);
    }

    @Override
    public DHClientKeyExchangeSerializer<T> getSerializer(T message) {
        return new DHClientKeyExchangeSerializer<T>(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(T message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        adjustClientPublicKey(message);
        spawnNewSession();
    }

    private void adjustClientPublicKey(DHClientKeyExchangeMessage message) {
        if (message.getPublicKey().getValue().length == 0) {
            LOGGER.debug("Empty DH Key");
        } else {
            tlsContext.setClientDhPublicKey(new BigInteger(message.getPublicKey().getValue()));
        }
    }
}
