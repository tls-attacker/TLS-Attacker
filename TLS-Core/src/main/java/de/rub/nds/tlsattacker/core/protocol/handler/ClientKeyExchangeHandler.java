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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <Message>
 */
public abstract class ClientKeyExchangeHandler<Message extends ClientKeyExchangeMessage> extends
        HandshakeMessageHandler<Message> {

    public ClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    protected void adjustPremasterSecret(ClientKeyExchangeMessage message) {
        if (message.getComputations().getPremasterSecret() != null) {
            byte[] premasterSecret = message.getComputations().getPremasterSecret().getValue();
            tlsContext.setPreMasterSecret(premasterSecret);
            LOGGER.debug("Set PremasterSecret in Context to " + ArrayConverter.bytesToHexString(premasterSecret));
        } else {
            LOGGER.debug("Did not set in Context PremasterSecret");
        }
    }

    protected byte[] calculateMasterSecret(ClientKeyExchangeMessage message) {
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getSelectedProtocolVersion(),
                tlsContext.getSelectedCipherSuite());
        if (tlsContext.isExtendedMasterSecretExtension()) {
            LOGGER.debug("Calculating ExtendedMasterSecret");
            byte[] sessionHash = tlsContext.getDigest().digest(tlsContext.getSelectedProtocolVersion(),
                    tlsContext.getSelectedCipherSuite());
            byte[] extendedMasterSecret = PseudoRandomFunction.compute(prfAlgorithm, tlsContext.getPreMasterSecret(),
                    PseudoRandomFunction.EXTENDED_MASTER_SECRET_LABEL, sessionHash, HandshakeByteLength.MASTER_SECRET);
            return extendedMasterSecret;
        } else {
            LOGGER.debug("Calculating MasterSecret");
            byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, tlsContext.getPreMasterSecret(),
                    PseudoRandomFunction.MASTER_SECRET_LABEL, message.getComputations().getClientRandom().getValue(),
                    HandshakeByteLength.MASTER_SECRET);
            return masterSecret;
        }
    }

    protected void adjustMasterSecret(ClientKeyExchangeMessage message) {
        byte[] masterSecret = calculateMasterSecret(message);
        tlsContext.setMasterSecret(masterSecret);
        LOGGER.debug("Set MasterSecret in Context to " + ArrayConverter.bytesToHexString(masterSecret));
    }
}
