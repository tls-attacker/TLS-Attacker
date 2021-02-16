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
public class DHClientKeyExchangeHandler extends ClientKeyExchangeHandler<DHClientKeyExchangeMessage> {

    private Logger LOGGER = LogManager.getLogger();

    public DHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public DHClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new DHClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
            tlsContext.getConfig());
    }

    @Override
    public DHClientKeyExchangePreparator getPreparator(DHClientKeyExchangeMessage message) {
        return new DHClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public DHClientKeyExchangeSerializer getSerializer(DHClientKeyExchangeMessage message) {
        return new DHClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(DHClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        adjustClientPublicKey(message);
        setRecordCipher();
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
