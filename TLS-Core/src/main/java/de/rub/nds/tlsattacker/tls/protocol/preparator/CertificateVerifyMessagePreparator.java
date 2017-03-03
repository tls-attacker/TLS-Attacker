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
    public void prepare() {
        SignatureAndHashAlgorithm algorithm = selectSigHashAlgorithm();
        byte[] signature = createSignature();
        message.setSignature(signature);
        message.setSignatureLength(message.getSignature().getValue().length);
        message.setSignatureHashAlgorithm(algorithm.getByteValue());
    }

    
    private SignatureAndHashAlgorithm selectSigHashAlgorithm() {
        PrivateKey key = context.getConfig().getPrivateKey();
        List<SignatureAndHashAlgorithm> possibleList = null;
        switch (key.getAlgorithm()) {
            case "RSA":
                possibleList = context.getConfig().getSupportedSignatureAndHashAlgorithmsForRSA();
                break;
            case "EC":
                possibleList = context.getConfig().getSupportedSignatureAndHashAlgorithmsForEC();
                break;
        }
        if (possibleList == null || possibleList.isEmpty()) {
            throw new PreparationException("No SignatureAlgorithm supported for the configured private Key:" + key.getAlgorithm());
        }
        return possibleList.get(0);
    }

    private byte[] createSignature() {
        try {
            byte[] rawHandshakeBytes = context.getDigest().getRawBytes();
            selectSigHashAlgorithm();
            Signature signature = Signature.getInstance(context.getSelectedSigHashAlgorithm().getJavaName());
            signature.initSign(context.getConfig().getPrivateKey());
            signature.update(rawHandshakeBytes);
            return signature.sign();
        } catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new PreparationException("Could not create Signature!",ex);
        }
    }
}
