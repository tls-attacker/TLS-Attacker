/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class CcaDelegate extends Delegate {

    @Parameter(names = "-certificatePath", description = "ASN.1 DER encoded client certificate used for basic "
            + "authentication bypass testing. Required for basic CCA test cases.")
    private String clientCertificatePath;
    @Parameter(names = "-certificateInputDirectory", description = "Path to directory that contains root certificates " +
            "for CCA test cases. Required for further CCA tests.")
    private String certificateInputDirectory;
    @Parameter(names = "-certificateOutputDirectory", description = "Path to directory to which certificates generated " +
            "for test cases are written. Required for further CCA tests.")
    private String certificateOutputDirectory;
    @Parameter(names = "-keyDirectory", description = "Path to directory containing pre generated keys for certificates " +
            "that will be generated, as well as the keys to the root certificates. Keys for root certificates need to " +
            "have the same name as the certificate. Required for further CCA tests.")
    private String keyDirectory;
    @Parameter(names = "-xmlCertificateDirectory", description = "Path to directory that contains XML files describing " +
            "certificates in the format of X509Attacker. Required for further CCA tests.")
    private String xmlDirectory;


    public CcaDelegate() {
    }

    public byte[] getClientCertificate() {
        FileInputStream fileInputStream = null;
        if (this.clientCertificatePath == null) {
            LOGGER.error("Certificate path not supplied.");
        }
        File file = new File(this.clientCertificatePath);
        byte certificate[] = new byte[(int) file.length()];

        try {
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(certificate);
        } catch (FileNotFoundException e) {
            LOGGER.error("File not found. " + e);
        } catch (IOException ioe) {
            LOGGER.error("Exception while reading file. " + ioe);
        } finally {
            try {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            } catch (IOException ioe) {
                LOGGER.error("Error while closing stream: " + ioe);
            }
        }
        return certificate;
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

    public String getXmlDirectory() {
        return xmlDirectory;
    }

    @Override
    public void applyDelegate(Config config) {
    }
}
