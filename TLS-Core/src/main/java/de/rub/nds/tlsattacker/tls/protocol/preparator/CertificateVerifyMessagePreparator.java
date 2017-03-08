/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateVerifyMessagePreparator extends HandshakeMessagePreparator<CertificateVerifyMessage> {

    private final CertificateVerifyMessage message;

    public CertificateVerifyMessagePreparator(TlsContext context, CertificateVerifyMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        SignatureAndHashAlgorithm algorithm = selectSigHashAlgorithm();
        byte[] signature = createSignature();
        message.setSignature(signature);
        message.setSignatureLength(message.getSignature().getValue().length);
        message.setSignatureHashAlgorithm(algorithm.getByteValue());
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
            byte[] rawHandshakeBytes = context.getDigest().getRawBytes();
            SignatureAndHashAlgorithm algorithm = selectSigHashAlgorithm();
            Signature signature = Signature.getInstance(algorithm.getJavaName());
            signature.initSign(context.getConfig().getPrivateKey(),RandomHelper.getBadSecureRandom());
            signature.update(rawHandshakeBytes);
            return signature.sign();
        } catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new PreparationException("Could not create Signature!", ex);
        }
    }
}
