/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.forensics.config;

import com.beust.jcommander.Parameter;

public class TlsForensicsConfig {

    public static final String COMMAND = "analyze";

    @Parameter(names = "-workflow", description = "The Workflow which should be analyzed", required = true)
    private String workflowInput = null;

    @Parameter(names = "-key", description = "The private key of the Server used (RSA only). Otherwise we cannot decrypt after the CKE/CCS")
    private String keyFile = null;

    @Parameter(names = "-debug", description = "Enables debug mode")
    private boolean debug = false;

    public TlsForensicsConfig() {
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }
}
