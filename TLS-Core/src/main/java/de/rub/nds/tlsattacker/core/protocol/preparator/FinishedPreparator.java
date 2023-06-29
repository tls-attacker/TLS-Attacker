/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

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
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

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
                HKDFAlgorithm hkdfAlgorithm =
                        AlgorithmResolver.getHKDFAlgorithm(chooser.getSelectedCipherSuite());
                String javaMacName = hkdfAlgorithm.getMacAlgorithm().getJavaName();
                boolean isHmacSM3 = javaMacName.equals("HmacSM3");
                int macLength;
                if (isHmacSM3) {
                    macLength = 32;
                } else {
                    macLength = Mac.getInstance(javaMacName).getMacLength();
                }
                LOGGER.debug("Connection End: " + chooser.getConnectionEndType());
                byte[] trafficSecret;
                if (chooser.getConnectionEndType() == ConnectionEndType.SERVER) {
                    trafficSecret = chooser.getServerHandshakeTrafficSecret();
                } else {
                    trafficSecret = chooser.getClientHandshakeTrafficSecret();
                }
                byte[] finishedKey =
                        HKDFunction.expandLabel(
                                hkdfAlgorithm,
                                trafficSecret,
                                HKDFunction.FINISHED,
                                new byte[0],
                                macLength);
                LOGGER.debug("Finished key: {}", finishedKey);
                SecretKeySpec keySpec = new SecretKeySpec(finishedKey, javaMacName);
                byte[] result;
                if (isHmacSM3) {
                    HMac hmac = new HMac(new SM3Digest());
                    KeyParameter keyParameter = new KeyParameter(keySpec.getEncoded());
                    hmac.init(keyParameter);
                    hmac.update(
                            chooser.getContext()
                                    .getTlsContext()
                                    .getDigest()
                                    .digest(
                                            chooser.getSelectedProtocolVersion(),
                                            chooser.getSelectedCipherSuite()),
                            0,
                            32);
                    result = new byte[hmac.getMacSize()];
                    hmac.doFinal(result, 0);
                } else {
                    Mac mac = Mac.getInstance(javaMacName);
                    mac.init(keySpec);
                    mac.update(
                            chooser.getContext()
                                    .getTlsContext()
                                    .getDigest()
                                    .digest(
                                            chooser.getSelectedProtocolVersion(),
                                            chooser.getSelectedCipherSuite()));
                    result = mac.doFinal();
                }
                return result;
            } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                throw new CryptoException(ex);
            }
        } else if (chooser.getSelectedProtocolVersion().isSSL()) {
            LOGGER.trace("Calculating VerifyData:");
            final byte[] handshakeMessageContent =
                    chooser.getContext().getTlsContext().getDigest().getRawBytes();
            final byte[] masterSecret = chooser.getMasterSecret();
            LOGGER.debug("Using MasterSecret: {}", masterSecret);
            final ConnectionEndType endType = chooser.getConnectionEndType();
            return SSLUtils.calculateFinishedData(handshakeMessageContent, masterSecret, endType);
        } else {
            LOGGER.debug("Calculating VerifyData:");
            PRFAlgorithm prfAlgorithm = chooser.getPRFAlgorithm();
            LOGGER.debug("Using PRF:" + prfAlgorithm.name());
            byte[] masterSecret = chooser.getMasterSecret();
            LOGGER.debug("Using MasterSecret: {}", masterSecret);
            byte[] handshakeMessageHash =
                    chooser.getContext()
                            .getTlsContext()
                            .getDigest()
                            .digest(
                                    chooser.getSelectedProtocolVersion(),
                                    chooser.getSelectedCipherSuite());
            LOGGER.debug("Using HandshakeMessage Hash: {}", handshakeMessageHash);

            String label;
            if (chooser.getConnectionEndType() == ConnectionEndType.SERVER) {
                // TODO put this in separate config option
                label = PseudoRandomFunction.SERVER_FINISHED_LABEL;
            } else {
                label = PseudoRandomFunction.CLIENT_FINISHED_LABEL;
            }
            byte[] res =
                    PseudoRandomFunction.compute(
                            prfAlgorithm,
                            masterSecret,
                            label,
                            handshakeMessageHash,
                            HandshakeByteLength.VERIFY_DATA);
            return res;
        }
    }

    private void prepareVerifyData(FinishedMessage msg) {
        msg.setVerifyData(verifyData);
        LOGGER.debug("VerifyData: {}", msg.getVerifyData().getValue());
    }
}
