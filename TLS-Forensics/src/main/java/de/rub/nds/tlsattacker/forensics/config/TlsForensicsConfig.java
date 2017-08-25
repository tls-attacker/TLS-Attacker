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

    public TlsForensicsConfig() {
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }
    
}