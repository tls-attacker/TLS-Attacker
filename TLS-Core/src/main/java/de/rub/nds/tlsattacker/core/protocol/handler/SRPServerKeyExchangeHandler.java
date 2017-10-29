/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.message.SRPServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.SRPServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SRPServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SRPServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;

/**
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class SRPServerKeyExchangeHandler extends ServerKeyExchangeHandler<SRPServerKeyExchangeMessage> {

    public SRPServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public SRPServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new SRPServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public SRPServerKeyExchangePreparator getPreparator(SRPServerKeyExchangeMessage message) {
        return new SRPServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public SRPServerKeyExchangeSerializer getSerializer(SRPServerKeyExchangeMessage message) {
        return new SRPServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(SRPServerKeyExchangeMessage message) {
        adjustSRPGenerator(message);
        adjustSRPModulus(message);
        adjustSalt(message);
        adjustServerPublicKey(message);
        if (message.getComputations() != null && message.getComputations().getPrivateKey() != null) {
            adjustServerPrivateKey(message);
        }
    }

    /**
     *
     * @param context
     */
    private void adjustSRPGenerator(SRPServerKeyExchangeMessage message) {
        tlsContext.setSRPGenerator(new BigInteger(1, message.getGenerator().getValue()));
        LOGGER.debug("SRP Generator: " + tlsContext.getSRPGenerator());
    }

    private void adjustSRPModulus(SRPServerKeyExchangeMessage message) {
        tlsContext.setSRPModulus(new BigInteger(1, message.getModulus().getValue()));
        LOGGER.debug("SRP Modulus: " + tlsContext.getSRPModulus());
    }

    private void adjustServerPublicKey(SRPServerKeyExchangeMessage message) {
        tlsContext.setServerSRPPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        LOGGER.debug("Server PublicKey: " + tlsContext.getServerSRPPublicKey());
    }

    private void adjustServerPrivateKey(SRPServerKeyExchangeMessage message) {
        tlsContext.setServerSRPPrivateKey(message.getComputations().getPrivateKey().getValue());
        LOGGER.debug("Server PrivateKey: " + tlsContext.getServerSRPPrivateKey());
    }

    private void adjustSalt(SRPServerKeyExchangeMessage message) {
        tlsContext.setSRPSalt(message.getSalt().getValue());
        LOGGER.debug("SRP Salt: " + tlsContext.getSRPSalt());
    }
}
