/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.delegate.DynamicWorkflowDelegate;
import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DynamicWorkflowDelegateTest {

    private DynamicWorkflowDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public DynamicWorkflowDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new DynamicWorkflowDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isDynamicWorkflow method, of class DynamicWorkflowDelegate.
     */
    @Test
    public void testIsDynamicWorkflow() {
        args = new String[1];
        args[0] = "-dynamic_workflow";
        assertTrue(delegate.isDynamicWorkflow() == null);
        jcommander.parse(args);
        assertTrue(delegate.isDynamicWorkflow());
    }

    /**
     * Test of setDynamicWorkflow method, of class DynamicWorkflowDelegate.
     */
    @Test
    public void testSetDynamicWorkflow() {
        assertTrue(delegate.isDynamicWorkflow() == null);
        delegate.setDynamicWorkflow(true);
        assertTrue(delegate.isDynamicWorkflow());
    }

    /**
     * Test of applyDelegate method, of class DynamicWorkflowDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = TlsConfig.createConfig();
        config.setDynamicWorkflow(false);
        args = new String[1];
        args[0] = "-dynamic_workflow";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isDynamicWorkflow());
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
                                                                                // ugly
    }
}
