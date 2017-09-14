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
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificateVerifyMessagePreparator extends HandshakeMessagePreparator<CertificateVerifyMessage> {

    private SignatureAndHashAlgorithm algorithm;
    private byte[] signature;
    private final CertificateVerifyMessage msg;

    public CertificateVerifyMessagePreparator(Chooser chooser, CertificateVerifyMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing CertificateVerifiyMessage");
        algorithm = chooser.getSelectedSigHashAlgorithm();
        signature = createSignature();
        prepareSignature(msg);
        prepareSignatureLength(msg);
        prepareSignatureHashAlgorithm(msg);
    }

    private byte[] createSignature() {
        byte[] toBeSigned = chooser.getContext().getDigest().getRawBytes();
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            if (chooser.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
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
