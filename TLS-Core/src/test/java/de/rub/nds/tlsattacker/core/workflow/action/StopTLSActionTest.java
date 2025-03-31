/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

class StopTLSActionTest {

    @Test
    public void testExecute() {
        Config config = new Config();
        // note this line is different from the StartTLS test
        config.setDefaultLayerConfiguration(StackConfiguration.SMTPS);
        State state = new State(config);
        StopTLSAction action = new StopTLSAction();
        assert state.getContext()
                .getLayerStack()
                .getLayersInStack()
                .contains(ImplementedLayers.MESSAGE);
        assert state.getContext()
                .getLayerStack()
                .getLayersInStack()
                .contains(ImplementedLayers.RECORD);
        action.execute(state);
        assert !state.getContext()
                .getLayerStack()
                .getLayersInStack()
                .contains(ImplementedLayers.MESSAGE);
        assert !state.getContext()
                .getLayerStack()
                .getLayersInStack()
                .contains(ImplementedLayers.RECORD);
    }

    @Test
    public void testRepeatedExecute() {
        // multiple "stops" are allowed, but do nothing
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTPS);
        State state = new State(config);
        StopTLSAction action = new StopTLSAction();
        action.execute(state);
        StopTLSAction action2 = new StopTLSAction();
        action2.execute(state);
        assert (action2.isExecuted());
    }
}
