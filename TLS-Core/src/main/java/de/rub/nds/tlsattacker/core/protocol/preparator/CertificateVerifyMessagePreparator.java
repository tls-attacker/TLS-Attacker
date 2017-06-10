/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateVerifyMessagePreparator extends HandshakeMessagePreparator<CertificateVerifyMessage> {

    private SignatureAndHashAlgorithm algorithm;
    private byte[] signature;
    private final CertificateVerifyMessage msg;

    public CertificateVerifyMessagePreparator(TlsContext context, CertificateVerifyMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        algorithm = selectSigHashAlgorithm();
        signature = createSignature();
        prepareSignature(msg);
        prepareSignatureLength(msg);
        prepareSignatureHashAlgorithm(msg);
    }

    private SignatureAndHashAlgorithm selectSigHashAlgorithm() {
        PrivateKey key = context.getConfig().getPrivateKey();
        for (SignatureAndHashAlgorithm algo : context.getConfig().getSupportedSignatureAndHashAlgorithms()) {
            if (algo.getSignatureAlgorithm().getJavaName().equals(key.getAlgorithm())) {
                return algo;
            }
        }
        throw new PreparationException("No SignatureAlgorithm supported for the configured private Key:"
                + key.getAlgorithm());
    }

    private byte[] createSignature() {
        try {
            byte[] toSigned = context.getDigest().getRawBytes();
            if(context.getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
                toSigned = context.getDigest().digest(context.getSelectedProtocolVersion(), context.getSelectedCipherSuite());
                byte[] string1 = ArrayConverter.hexStringToByteArray("20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020");
                byte[] string2;
                if (context.getConfig().getConnectionEnd() == ConnectionEnd.CLIENT) {
                    string2 = ArrayConverter.hexStringToByteArray("544c5320312e332c20636c69656e7420436572746966696361746556657269667900");
                } else {
                    string2 = ArrayConverter.hexStringToByteArray("544c5320312e332c2073657276657220436572746966696361746556657269667900");
                }
                toSigned = ArrayConverter.concatenate(string1, string2, toSigned);
            }            
            algorithm = selectSigHashAlgorithm();
            Signature tempSignature = Signature.getInstance(algorithm.getJavaName());
            tempSignature.initSign(context.getConfig().getPrivateKey(), RandomHelper.getBadSecureRandom());
            tempSignature.update(toSigned);
            return tempSignature.sign();
        } catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new PreparationException("Could not create Signature!", ex);
        }
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
