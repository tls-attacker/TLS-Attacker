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
import de.rub.nds.tlsattacker.core.constants.CertificateVerifiyConstants;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.SSLUtils;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateVerifyPreparator extends HandshakeMessagePreparator<CertificateVerifyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private SignatureAndHashAlgorithm algorithm;
    private byte[] signature;
    private final CertificateVerifyMessage msg;

    public CertificateVerifyPreparator(Chooser chooser, CertificateVerifyMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing CertificateVerifiyMessage");
        algorithm = chooser.getSelectedSigHashAlgorithm();
        signature = new byte[0];
        try {
            signature = createSignature();
        } catch (CryptoException E) {
            LOGGER.warn("Could not generate Signature! Using empty one instead!", E);
        }
        prepareSignature(msg);
        prepareSignatureLength(msg);
        prepareSignatureHashAlgorithm(msg);
    }

    private byte[] createSignature() throws CryptoException {
        byte[] toBeSigned = chooser.getContext().getDigest().getRawBytes();
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                toBeSigned = ArrayConverter
                        .concatenate(
                                ArrayConverter
                                        .hexStringToByteArray("20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"),
                                CertificateVerifiyConstants.CLIENT_CERTIFICATE_VERIFY.getBytes(),
                                new byte[] { (byte) 0x00 },
                                chooser.getContext().getDigest()
                                        .digest(chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite()));
            } else {
                toBeSigned = ArrayConverter
                        .concatenate(
                                ArrayConverter
                                        .hexStringToByteArray("20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"),
                                CertificateVerifiyConstants.SERVER_CERTIFICATE_VERIFY.getBytes(),
                                new byte[] { (byte) 0x00 },
                                chooser.getContext().getDigest()
                                        .digest(chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite()));
            }
        } else if (chooser.getSelectedProtocolVersion().isSSL()) {
            final byte[] handshakeMessageContent = chooser.getContext().getDigest().getRawBytes();
            final byte[] masterSecret = chooser.getMasterSecret();
            return SSLUtils.calculateSSLCertificateVerifySignature(handshakeMessageContent, masterSecret);
        }
        algorithm = chooser.getSelectedSigHashAlgorithm();
        return SignatureCalculator.generateSignature(algorithm, chooser, toBeSigned);
    }

    private void prepareSignature(CertificateVerifyMessage msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

    private void prepareSignatureLength(CertificateVerifyMessage msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void prepareSignatureHashAlgorithm(CertificateVerifyMessage msg) {
        msg.setSignatureHashAlgorithm(algorithm.getByteValue());
        LOGGER.debug("SignatureHasAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureHashAlgorithm().getValue()));
    }
}
