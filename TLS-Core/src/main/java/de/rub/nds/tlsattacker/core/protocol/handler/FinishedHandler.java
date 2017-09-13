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
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import static de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    public FinishedHandler(TlsContext context) {
        super(context);
    }

    @Override
    public FinishedMessageParser getParser(byte[] message, int pointer) {
        return new FinishedMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public FinishedMessagePreparator getPreparator(FinishedMessage message) {
        return new FinishedMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public FinishedMessageSerializer getSerializer(FinishedMessage message) {
        return new FinishedMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(FinishedMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
                adjustApplicationTrafficSecrets();
            } else {
                tlsContext.setUpdateKeys(true);
            }
        }
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setLastClientVerifyData(message.getVerifyData().getValue());
        } else {
            tlsContext.setLastServerVerifyData(message.getVerifyData().getValue());
        }
    }

    private void adjustApplicationTrafficSecrets() {
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser()
                .getSelectedCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(tlsContext.getChooser()
                .getSelectedProtocolVersion(), tlsContext.getChooser().getSelectedCipherSuite());
        try {
            int macLength = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] saltMasterSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    tlsContext.getHandshakeSecret(), HKDFunction.DERIVED, ArrayConverter.hexStringToByteArray(""));
            byte[] masterSecret = HKDFunction.extract(hkdfAlgortihm, saltMasterSecret, new byte[macLength]);
            byte[] clientApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    masterSecret, HKDFunction.CLIENT_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setClientApplicationTrafficSecret0(clientApplicationTrafficSecret);
            LOGGER.debug("Set clientApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(clientApplicationTrafficSecret));
            byte[] serverApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    masterSecret, HKDFunction.SERVER_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setServerApplicationTrafficSecret0(serverApplicationTrafficSecret);
            LOGGER.debug("Set serverApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(serverApplicationTrafficSecret));
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }
}
