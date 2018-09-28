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
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DHEServerKeyExchangeHandler extends ServerKeyExchangeHandler<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public DHEServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new DHEServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
                AlgorithmResolver.getKeyExchangeAlgorithm(tlsContext.getChooser().getSelectedCipherSuite()));
    }

    @Override
    public DHEServerKeyExchangePreparator getPreparator(DHEServerKeyExchangeMessage message) {
        return new DHEServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public DHEServerKeyExchangeSerializer getSerializer(DHEServerKeyExchangeMessage message) {
        return new DHEServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(DHEServerKeyExchangeMessage message) {
        adjustDhGenerator(message);
        adjustDhModulus(message);
        adjustServerPublicKey(message);
        if (message.getComputations() != null && message.getComputations().getPrivateKey() != null) {
            adjustServerPrivateKey(message);
        }
    }

    /**
     * @param context
     */
    private void adjustDhGenerator(DHEServerKeyExchangeMessage message) {
        tlsContext.setServerDhGenerator(new BigInteger(1, message.getGenerator().getValue()));
        LOGGER.debug("Dh Generator: " + tlsContext.getServerDhGenerator());
    }

    private void adjustDhModulus(DHEServerKeyExchangeMessage message) {
        tlsContext.setServerDhModulus(new BigInteger(1, message.getModulus().getValue()));
        LOGGER.debug("Dh Modulus: " + tlsContext.getServerDhModulus());
    }

    private void adjustServerPublicKey(DHEServerKeyExchangeMessage message) {
        tlsContext.setServerDhPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        LOGGER.debug("Server PublicKey: " + tlsContext.getServerDhPublicKey());
    }

    private void adjustServerPrivateKey(DHEServerKeyExchangeMessage message) {
        tlsContext.setServerDhPrivateKey(message.getComputations().getPrivateKey().getValue());
        LOGGER.debug("Server PrivateKey: " + tlsContext.getServerDhPrivateKey());
    }
}
