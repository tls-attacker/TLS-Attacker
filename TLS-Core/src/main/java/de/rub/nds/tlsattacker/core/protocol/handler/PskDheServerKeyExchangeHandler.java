/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskDheServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskDheServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskDheServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDheServerKeyExchangeHandler extends ServerKeyExchangeHandler<PskDheServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PskDheServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PskDheServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PskDheServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PskDheServerKeyExchangePreparator getPreparator(PskDheServerKeyExchangeMessage message) {
        return new PskDheServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PskDheServerKeyExchangeSerializer getSerializer(PskDheServerKeyExchangeMessage message) {
        return new PskDheServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PskDheServerKeyExchangeMessage message) {
        adjustPSKGenerator(message);
        adjustPSKModulus(message);
        adjustServerPublicKey(message);
        if (message.getComputations() != null && message.getComputations().getPrivateKey() != null) {
            adjustServerPrivateKey(message);
        }
    }

    /**
     *
     * @param context
     */
    private void adjustPSKGenerator(PskDheServerKeyExchangeMessage message) {
        tlsContext.setPSKGenerator(new BigInteger(1, message.getGenerator().getValue()));
        LOGGER.debug("PSK Generator: " + tlsContext.getPSKGenerator());
    }

    private void adjustPSKModulus(PskDheServerKeyExchangeMessage message) {
        tlsContext.setPSKModulus(new BigInteger(1, message.getModulus().getValue()));
        LOGGER.debug("PSK Modulus: " + tlsContext.getPSKModulus());
    }

    private void adjustServerPublicKey(PskDheServerKeyExchangeMessage message) {
        tlsContext.setServerPSKPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        LOGGER.debug("Server PublicKey: " + tlsContext.getServerPSKPublicKey());
    }

    private void adjustServerPrivateKey(PskDheServerKeyExchangeMessage message) {
        tlsContext.setServerPSKPrivateKey(message.getComputations().getPrivateKey().getValue());
        LOGGER.debug("Server PrivateKey: " + tlsContext.getServerPSKPrivateKey());
    }
}
