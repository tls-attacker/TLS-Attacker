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

    @Parameter(names = "-certificate_path", description = "ASN.1 DER encoded client certificate used for basic "
            + "authentication bypass testing.")
    private String clientCertificatePath;

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

    @Override
    public void applyDelegate(Config config) {
    }
}
