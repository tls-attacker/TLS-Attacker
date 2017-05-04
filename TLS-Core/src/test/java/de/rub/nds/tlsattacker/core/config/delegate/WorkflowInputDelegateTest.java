/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.delegate.WorkflowInputDelegate;
import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import javax.xml.bind.JAXBException;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowInputDelegateTest {

    private WorkflowInputDelegate delegate;
    private JCommander jcommander;
    private String[] args;
    private TemporaryFolder tempFolder;
    private File tempFile;

    public WorkflowInputDelegateTest() {
    }

    @Before
    public void setUp() throws IOException, FileNotFoundException, JAXBException {
        this.delegate = new WorkflowInputDelegate();
        this.jcommander = new JCommander(delegate);
        WorkflowTrace trace = new WorkflowTrace();
        tempFolder = new TemporaryFolder();
        tempFolder.create();
        tempFile = tempFolder.newFile();
        WorkflowTraceSerializer.write(tempFile, trace);
    }

    /**
     * Test of getWorkflowInput method, of class WorkflowInputDelegate.
     */
    @Test
    public void testGetWorkflowInput() {
        args = new String[2];
        args[0] = "-workflow_input";
        args[1] = tempFile.getAbsolutePath();
        assertFalse(tempFile.getAbsolutePath().equals(delegate.getWorkflowInput()));
        jcommander.parse(args);
        assertTrue(tempFile.getAbsolutePath().equals(delegate.getWorkflowInput()));
    }

    /**
     * Test of setWorkflowInput method, of class WorkflowInputDelegate.
     */
    @Test
    public void testSetWorkflowInput() {
        assertFalse(tempFile.getAbsolutePath().equals(delegate.getWorkflowInput()));
        delegate.setWorkflowInput(tempFile.getAbsolutePath());
        assertTrue(tempFile.getAbsolutePath().equals(delegate.getWorkflowInput()));
    }

    /**
     * Test of applyDelegate method, of class WorkflowInputDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = TlsConfig.createConfig();
        config.setWorkflowInput(null);
        args = new String[2];
        args[0] = "-workflow_input";
        args[1] = tempFile.getAbsolutePath();
        jcommander.parse(args);
        assertFalse(config.getWorkflowInput() != null);
        delegate.applyDelegate(config);
        assertTrue(config.getWorkflowInput() != null);
    }

    // TODO add configurationException test

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }
}
