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
import de.rub.nds.tlsattacker.core.protocol.message.PSKDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PSKDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PSKDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PSKDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;

/**
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKDHEServerKeyExchangeHandler extends ServerKeyExchangeHandler<PSKDHEServerKeyExchangeMessage> {

    public PSKDHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PSKDHEServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PSKDHEServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PSKDHEServerKeyExchangePreparator getPreparator(PSKDHEServerKeyExchangeMessage message) {
        return new PSKDHEServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PSKDHEServerKeyExchangeSerializer getSerializer(PSKDHEServerKeyExchangeMessage message) {
        return new PSKDHEServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PSKDHEServerKeyExchangeMessage message) {
        adjustDhGenerator(message);
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
    private void adjustDhGenerator(PSKDHEServerKeyExchangeMessage message) {
        tlsContext.setPSKGenerator(new BigInteger(1, message.getGenerator().getValue()));
        LOGGER.debug("PSK Generator: " + tlsContext.getPSKGenerator());
    }

    private void adjustPSKModulus(PSKDHEServerKeyExchangeMessage message) {
        tlsContext.setPSKModulus(new BigInteger(1, message.getModulus().getValue()));
        LOGGER.debug("PSK Modulus: " + tlsContext.getPSKModulus());
    }

    private void adjustServerPublicKey(PSKDHEServerKeyExchangeMessage message) {
        tlsContext.setServerPSKPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        LOGGER.debug("Server PublicKey: " + tlsContext.getServerPSKPublicKey());
    }

    private void adjustServerPrivateKey(PSKDHEServerKeyExchangeMessage message) {
        tlsContext.setServerPSKPrivateKey(message.getComputations().getPrivateKey().getValue());
        LOGGER.debug("Server PrivateKey: " + tlsContext.getServerPSKPrivateKey());
    }
}
