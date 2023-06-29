/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.util.Collections;
import java.util.List;

public class SignatureAlgorithmCertDelegate extends Delegate {

    @Parameter(
            names = "-signature_algo_cert",
            description =
                    "Supported Signature and Hash Algorithms for Certificates separated by comma eg. RSA-SHA512,DSA-SHA512")
    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = null;

    public List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms() {
        if (signatureAndHashAlgorithms == null) {
            return null;
        }
        return Collections.unmodifiableList(signatureAndHashAlgorithms);
    }

    public void setSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
        this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        if (signatureAndHashAlgorithms != null) {
            config.setAddSignatureAlgorithmsCertExtension(true);
            config.setDefaultServerSupportedCertificateSignAlgorithms(signatureAndHashAlgorithms);
            config.setDefaultClientSupportedCertificateSignAlgorithms(signatureAndHashAlgorithms);
            config.setDefaultSelectedSignatureAlgorithmCert(signatureAndHashAlgorithms.get(0));
        }
    }
}
