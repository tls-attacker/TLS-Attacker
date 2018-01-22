/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.forensics.config;

import com.beust.jcommander.Parameter;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsForensicsConfig {

    public static final String COMMAND = "analyze";

    @Parameter(names = "-workflow", description = "The Workflow which should be analyzed", required = true)
    private String workflowInput = null;

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
}
