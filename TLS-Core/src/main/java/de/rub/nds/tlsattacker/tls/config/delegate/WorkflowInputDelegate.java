/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.util.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.FileInputStream;
import java.io.IOException;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowInputDelegate extends Delegate {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(WorkflowInputDelegate.class);

    @Parameter(names = "-workflow_input", description = "This parameter allows you to load the whole workflow trace from the specified XML configuration file")
    private String workflowInput;

    public WorkflowInputDelegate() {
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        FileInputStream fis = null;
        config.setWorkflowInput(workflowInput);
        if (workflowInput != null) {
            try {
                fis = new FileInputStream(workflowInput);
                WorkflowTrace workflowTrace = WorkflowTraceSerializer.read(fis);
                config.setWorkflowTrace(workflowTrace);
            } catch (JAXBException | XMLStreamException | IOException ex) {
                throw new ConfigurationException("Could not read WorkflowTrace from " + workflowInput, ex);
            } finally {
                try {
                    fis.close();
                } catch (IOException ex) {
                    throw new ConfigurationException("Could not read WorkflowTrace from " + workflowInput, ex);
                }
            }
        }
    }
}
