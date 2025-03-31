/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertFalse;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

class StartTLSActionTest {
    @Test
    public void testExecute() {
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        State state = new State(config);
        StartTLSAction action = new StartTLSAction();
        assert !state.getContext()
                .getLayerStack()
                .getLayersInStack()
                .contains(ImplementedLayers.MESSAGE);
        assert !state.getContext()
                .getLayerStack()
                .getLayersInStack()
                .contains(ImplementedLayers.RECORD);
        action.execute(state);
        assert state.getContext()
                .getLayerStack()
                .getLayersInStack()
                .contains(ImplementedLayers.MESSAGE);
        assert state.getContext()
                .getLayerStack()
                .getLayersInStack()
                .contains(ImplementedLayers.RECORD);
    }

    @Test
    public void testRepeatedExecute() {
        // multiple "starts" carry unclear semantics, so we disallow them
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        State state = new State(config);
        StartTLSAction action = new StartTLSAction();
        action.execute(state);
        StartTLSAction action2 = new StartTLSAction();
        assertFalse(action2.isExecuted());
    }

    @Test
    public void testPersistentContext() {
        // ensure that the TlsContext is preserved across multiple StartTLS/StopTLS cycles
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        State state = new State(config);

        StartTLSAction startAction = new StartTLSAction();
        startAction.execute(state);
        TlsContext originalTlsContext = state.getTlsContext();

        StopTLSAction stopAction = new StopTLSAction();
        stopAction.execute(state);

        startAction = new StartTLSAction();
        startAction.execute(state);
        TlsContext newTlsContext = state.getTlsContext();
        assert originalTlsContext == newTlsContext;
    }
}
