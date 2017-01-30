/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SignatureAndHashAlgorithmDelegate extends Delegate {

    // todo define parameter
    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;

    public SignatureAndHashAlgorithmDelegate() {
        signatureAndHashAlgorithms = new LinkedList<>();
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA512));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA512));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA384));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA384));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA384));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA256));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA256));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA224));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA224));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA224));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA1));
        signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.SHA1));
    }

    public List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms() {
        return signatureAndHashAlgorithms;
    }

    public void setSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
        this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        config.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
    }
}
