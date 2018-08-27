/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.crypto.SSLUtils;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FinishedPreparator extends HandshakeMessagePreparator<FinishedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private byte[] verifyData;
    private final FinishedMessage msg;

    public FinishedPreparator(Chooser chooser, FinishedMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing FinishedMessage");
        try {
            verifyData = computeVerifyData();
        } catch (CryptoException ex) {
            LOGGER.warn("Could not compute VerifyData! Using empty verifyData.", ex);
            verifyData = new byte[0];
        }
        prepareVerifyData(msg);
    }

    private byte[] computeVerifyData() throws CryptoException {
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            try {
                HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(chooser.getSelectedCipherSuite());
                Mac mac = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName());
                byte[] finishedKey;
                LOGGER.debug("Connection End: " + chooser.getConnectionEndType());
                if (chooser.getConnectionEndType() == ConnectionEndType.SERVER) {
                    finishedKey = HKDFunction.expandLabel(hkdfAlgortihm, chooser.getServerHandshakeTrafficSecret(),
                            HKDFunction.FINISHED, new byte[0], mac.getMacLength());
                } else {
                    finishedKey = HKDFunction.expandLabel(hkdfAlgortihm, chooser.getClientHandshakeTrafficSecret(),
                            HKDFunction.FINISHED, new byte[0], mac.getMacLength());
                }
                LOGGER.debug("Finished key: " + ArrayConverter.bytesToHexString(finishedKey));
                SecretKeySpec keySpec = new SecretKeySpec(finishedKey, mac.getAlgorithm());
                mac.init(keySpec);
                mac.update(chooser.getContext().getDigest()
                        .digest(chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite()));
                return mac.doFinal();
            } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                throw new CryptoException(ex);
            }
        } else if (chooser.getSelectedProtocolVersion().isSSL()) {
            LOGGER.trace("Calculating VerifyData:");
            final byte[] handshakeMessageContent = chooser.getContext().getDigest().getRawBytes();
            final byte[] masterSecret = chooser.getMasterSecret();
            LOGGER.debug("Using MasterSecret:" + ArrayConverter.bytesToHexString(masterSecret));
            final ConnectionEndType endType = chooser.getConnectionEndType();
            return SSLUtils.calculateFinishedData(handshakeMessageContent, masterSecret, endType);
        } else {
            LOGGER.trace("Calculating VerifyData:");
            PRFAlgorithm prfAlgorithm = chooser.getPRFAlgorithm();
            LOGGER.trace("Using PRF:" + prfAlgorithm.name());
            byte[] masterSecret = chooser.getMasterSecret();
            LOGGER.debug("Using MasterSecret:" + ArrayConverter.bytesToHexString(masterSecret));
            byte[] handshakeMessageHash = chooser.getContext().getDigest()
                    .digest(chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite());
            LOGGER.debug("Using HandshakeMessage Hash:" + ArrayConverter.bytesToHexString(handshakeMessageHash));

            String label;
            if (chooser.getConnectionEndType() == ConnectionEndType.SERVER) {
                // TODO put this in seperate config option
                label = PseudoRandomFunction.SERVER_FINISHED_LABEL;
            } else {
                label = PseudoRandomFunction.CLIENT_FINISHED_LABEL;
            }
            byte[] res = PseudoRandomFunction.compute(prfAlgorithm, masterSecret, label, handshakeMessageHash,
                    HandshakeByteLength.VERIFY_DATA);
            return res;
        }
    }

    private void prepareVerifyData(FinishedMessage msg) {
        msg.setVerifyData(verifyData);
        LOGGER.debug("VerifyData: " + ArrayConverter.bytesToHexString(msg.getVerifyData().getValue()));
    }

}
