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
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import static de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    public FinishedHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public FinishedMessageParser getParser(byte[] message, int pointer) {
        return new FinishedMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public FinishedMessagePreparator getPreparator(FinishedMessage message) {
        return new FinishedMessagePreparator(tlsContext, message);
    }

    @Override
    public FinishedMessageSerializer getSerializer(FinishedMessage message) {
        return new FinishedMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(FinishedMessage message) {
        if (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.TLS13
                && tlsContext.getTalkingConnectionEnd() == ConnectionEnd.SERVER) {
            adjustApplicationTrafficSecrets();
        }
        if (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.TLS13
                && tlsContext.getTalkingConnectionEnd() == ConnectionEnd.CLIENT) {
            tlsContext.setUpdateKeys(true);
        }
    }

    private void adjustApplicationTrafficSecrets() {
        MacAlgorithm macAlg = AlgorithmResolver.getHKDFAlgorithm(tlsContext.getSelectedCipherSuite()).getMacAlgorithm();
        // byte[] saltMasterSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), tlsContext.getHandshakeSecret(), HKDFunction.DERIVED, new byte[] {});
        // byte[] masterSecret = HKDFunction.extract(macAlg.getJavaName(), saltMasterSecret, new byte[32]);
        byte[] masterSecret = HKDFunction.extract(macAlg.getJavaName(), tlsContext.getHandshakeSecret(), new byte[32]);
        byte[] clientApplicationTrafficSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), masterSecret,
                        HKDFunction.CLIENT_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().
                        digest(tlsContext.getSelectedProtocolVersion(), tlsContext.getSelectedCipherSuite()));
        tlsContext.setClientApplicationTrafficSecret0(clientApplicationTrafficSecret);
        LOGGER.debug("Set clientApplicationTrafficSecret in Context to " + ArrayConverter.bytesToHexString(clientApplicationTrafficSecret));
        byte[] serverApplicationTrafficSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), masterSecret,
                        HKDFunction.SERVER_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest()
                        .digest(tlsContext.getSelectedProtocolVersion(), tlsContext.getSelectedCipherSuite()));
        tlsContext.setServerApplicationTrafficSecret0(serverApplicationTrafficSecret);
        LOGGER.debug("Set serverApplicationTrafficSecret in Context to " + ArrayConverter.bytesToHexString(serverApplicationTrafficSecret));
    }
}
