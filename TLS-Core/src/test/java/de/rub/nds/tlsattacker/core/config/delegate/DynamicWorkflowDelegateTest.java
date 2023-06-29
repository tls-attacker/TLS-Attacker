/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class DynamicWorkflowDelegateTest extends AbstractDelegateTest<DynamicWorkflowDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new DynamicWorkflowDelegate());
    }

    /** Test of isDynamicWorkflow method, of class DynamicWorkflowDelegate. */
    @Test
    @Disabled("Dynamic workflow not implemented")
    public void testIsDynamicWorkflow() {
        args = new String[1];
        args[0] = "-dynamic_workflow";
        assertNull(delegate.isDynamicWorkflow());
        jcommander.parse(args);
        assertTrue(delegate.isDynamicWorkflow());
    }

    /** Test of setDynamicWorkflow method, of class DynamicWorkflowDelegate. */
    @Test
    @Disabled("Dynamic workflow not implemented")
    public void testSetDynamicWorkflow() {
        assertNull(delegate.isDynamicWorkflow());
        delegate.setDynamicWorkflow(true);
        assertTrue(delegate.isDynamicWorkflow());
    }

    /** Test of applyDelegate method, of class DynamicWorkflowDelegate. */
    @Test
    @Disabled("Dynamic workflow not implemented")
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.setDynamicWorkflow(false);
        args = new String[1];
        args[0] = "-dynamic_workflow";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isDynamicWorkflow());
    }

    @Test
    @Disabled("Dynamic workflow not implemented")
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
