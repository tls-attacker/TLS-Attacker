/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CcaDelegate extends Delegate {

    @Parameter(names = "-certificatePath", description = "ASN.1 PEM encoded client certificate used for basic "
        + "authentication bypass testing. Required for basic CCA test cases.")
    private String clientCertificatePath;
    @Parameter(names = "-certificateInputDirectory", description = "Path to directory that contains root certificates "
        + "for CCA test cases. Required for further CCA tests.")
    private String certificateInputDirectory;
    @Parameter(names = "-certificateOutputDirectory", description = "Path to directory to which certificates generated "
        + "for test cases are written. Required for further CCA tests.")
    private String certificateOutputDirectory;
    @Parameter(names = "-keyDirectory",
        description = "Path to directory containing pre generated keys for "
            + "certificates that will be generated, as well as the keys to the root certificates. Keys for root "
            + "certificates need to have the same name as the certificate. Required for further CCA tests.")
    private String keyDirectory;

    public CcaDelegate() {
    }

    public byte[] getClientCertificate() {
        FileInputStream fileInputStream = null;
        X509Certificate x509Certificate = null;
        if (this.clientCertificatePath == null) {
            LOGGER.debug("Certificate path not supplied.");
        } else {
            try {

                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                fileInputStream = new FileInputStream(this.clientCertificatePath);
                x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);

            } catch (FileNotFoundException e) {
                LOGGER.error("Couldn't find client certificate." + e);
            } catch (CertificateException ce) {
                LOGGER.error("Error while generating certificate from clientCertificatePath input." + ce);
            }

            if (x509Certificate != null) {
                try {
                    return x509Certificate.getEncoded();
                } catch (CertificateEncodingException cee) {
                    LOGGER.error("Couldn't encode clientCertificate into byte array." + cee);
                }
            }
        }
        return null;
    }

    public Boolean clientCertificateSupplied() {
        return clientCertificatePath != null && getClientCertificate() != null;
    }

    public Boolean directoriesSupplied() {
        return certificateInputDirectory != null && certificateOutputDirectory != null && keyDirectory != null;
    }

    public String getClientCertificatePath() {
        return clientCertificatePath;
    }

    public String getCertificateInputDirectory() {
        return certificateInputDirectory;
    }

    public String getCertificateOutputDirectory() {
        return certificateOutputDirectory;
    }

    public String getKeyDirectory() {
        return keyDirectory;
    }

    @Override
    public void applyDelegate(Config config) {
    }
}
