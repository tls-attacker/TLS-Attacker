/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CertificateVerifyConstants;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.SSLUtils;
import de.rub.nds.tlsattacker.core.crypto.TlsSignatureUtil;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateVerifyPreparator
        extends HandshakeMessagePreparator<CertificateVerifyMessage> {

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
        LOGGER.debug("Preparing CertificateVerifyMessage");
        algorithm = chooseSignatureAndHashAlgorithm();
        signature = new byte[0];
        try {
            signature = createSignature();
        } catch (CryptoException e) {
            LOGGER.warn("Could not generate Signature! Using empty one instead!", e);
        }
        prepareSignature(msg);
        prepareSignatureLength(msg);
        prepareSignatureHashAlgorithm(msg);
    }

    private byte[] createSignature() throws CryptoException {
        byte[] toBeSigned = chooser.getContext().getTlsContext().getDigest().getRawBytes();
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                toBeSigned =
                        ArrayConverter.concatenate(
                                ArrayConverter.hexStringToByteArray(
                                        "2020202020202020202020202020202020202020202020202020"
                                                + "2020202020202020202020202020202020202020202020202020202020202020202020202020"),
                                CertificateVerifyConstants.CLIENT_CERTIFICATE_VERIFY.getBytes(),
                                new byte[] {(byte) 0x00},
                                chooser.getContext()
                                        .getTlsContext()
                                        .getDigest()
                                        .digest(
                                                chooser.getSelectedProtocolVersion(),
                                                chooser.getSelectedCipherSuite()));
            } else {
                toBeSigned =
                        ArrayConverter.concatenate(
                                ArrayConverter.hexStringToByteArray(
                                        "2020202020202020202020202020202020202020202020202020"
                                                + "2020202020202020202020202020202020202020202020202020202020202020202020202020"),
                                CertificateVerifyConstants.SERVER_CERTIFICATE_VERIFY.getBytes(),
                                new byte[] {(byte) 0x00},
                                chooser.getContext()
                                        .getTlsContext()
                                        .getDigest()
                                        .digest(
                                                chooser.getSelectedProtocolVersion(),
                                                chooser.getSelectedCipherSuite()));
            }
        } else if (chooser.getSelectedProtocolVersion().isSSL()) {
            final byte[] handshakeMessageContent =
                    chooser.getContext().getTlsContext().getDigest().getRawBytes();
            final byte[] masterSecret = chooser.getMasterSecret();
            return SSLUtils.calculateSSLCertificateVerifySignature(
                    handshakeMessageContent, masterSecret);
        }
        algorithm = chooser.getSelectedSigHashAlgorithm();
        TlsSignatureUtil signatureUtil = new TlsSignatureUtil();
        signatureUtil.computeSignature(
                chooser,
                algorithm,
                toBeSigned,
                msg.getSignatureComputations(algorithm.getSignatureAlgorithm()));
        return msg.getSignatureComputations(algorithm.getSignatureAlgorithm())
                .getSignatureBytes()
                .getValue();
    }

    protected SignatureAndHashAlgorithm chooseSignatureAndHashAlgorithm() {
        SignatureAndHashAlgorithm signHashAlgo;
        if (chooser.getConfig().getAutoAdjustSignatureAndHashAlgorithm()) {
            X509PublicKeyType publicKeyType;
            if (chooser.getTalkingConnectionEnd() == ConnectionEndType.SERVER) {
                publicKeyType =
                        chooser.getContext()
                                .getTlsContext()
                                .getServerX509Context()
                                .getChooser()
                                .getSubjectPublicKeyType();
            } else {
                publicKeyType =
                        chooser.getContext()
                                .getTlsContext()
                                .getClientX509Context()
                                .getChooser()
                                .getSubjectPublicKeyType();
            }
            List<SignatureAndHashAlgorithm> candidateList = new LinkedList<>();
            for (SignatureAndHashAlgorithm tempSignatureAndHashAlgorithm :
                    SignatureAndHashAlgorithm.getImplemented()) {
                if (publicKeyType.canBeUsedWithSignatureAlgorithm(
                        tempSignatureAndHashAlgorithm.getSignatureAlgorithm())) {
                    candidateList.add(tempSignatureAndHashAlgorithm);
                }
            }

            List<SignatureAndHashAlgorithm> peerSupported;
            if (chooser.getTalkingConnectionEnd() == ConnectionEndType.SERVER) {
                peerSupported = chooser.getClientSupportedSignatureAndHashAlgorithms();
            } else {
                peerSupported = chooser.getServerSupportedSignatureAndHashAlgorithms();
            }
            candidateList.retainAll(peerSupported);
            if (candidateList.isEmpty()) {
                signHashAlgo = chooser.getSelectedSigHashAlgorithm();
            } else {
                signHashAlgo = candidateList.get(0);
            }
        } else {
            signHashAlgo = chooser.getConfig().getDefaultSelectedSignatureAndHashAlgorithm();
        }
        return signHashAlgo;
    }

    private void prepareSignature(CertificateVerifyMessage msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }

    private void prepareSignatureLength(CertificateVerifyMessage msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void prepareSignatureHashAlgorithm(CertificateVerifyMessage msg) {
        msg.setSignatureHashAlgorithm(algorithm.getByteValue());
        LOGGER.debug("SignatureHasAlgorithm: {}", msg.getSignatureHashAlgorithm().getValue());
    }
}
