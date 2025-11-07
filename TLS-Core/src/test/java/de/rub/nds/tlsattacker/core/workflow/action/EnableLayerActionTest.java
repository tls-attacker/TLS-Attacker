/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.impl.HttpLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EnableLayerActionTest {
    private Config config;
    private State state;

    @BeforeEach
    public void setUp() {
        config = new Config();
        state = new State(config);
    }

    @Test
    public void testDisabledLayer() {
        HttpLayer httpLayer = new HttpLayer(state.getContext());
        TcpLayer tcpLayer = new TcpLayer(state.getContext());
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        httpLayer,
                        tcpLayer

                );
        state.getContext().setLayerStack(layerStack);

        httpLayer.setEnabled(false);

        EnableLayerAction action = new EnableLayerAction(ImplementedLayers.HTTP);
        action.execute(state);

        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());

        assertTrue(httpLayer.isEnabled());
    }

    @Test
    public void testAlreadyEnabledLayer() {
        HttpLayer httpLayer = new HttpLayer(state.getContext());
        TcpLayer tcpLayer = new TcpLayer(state.getContext());
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        httpLayer,
                        tcpLayer

                );
        state.getContext().setLayerStack(layerStack);

        assertTrue(httpLayer.isEnabled());

        EnableLayerAction action = new EnableLayerAction(ImplementedLayers.HTTP);
        action.execute(state);

        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());

        assertTrue(httpLayer.isEnabled());
    }

    @Test
    public void testEnableLayerNotInStack() {
        HttpLayer httpLayer = new HttpLayer(state.getContext());
        TcpLayer tcpLayer = new TcpLayer(state.getContext());
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        httpLayer,
                        tcpLayer

                );
        state.getContext().setLayerStack(layerStack);
        EnableLayerAction action = new EnableLayerAction(ImplementedLayers.SMTP);
        action.execute(state);

        assertTrue(action.isExecuted());
        assertFalse(action.executedAsPlanned());
    }
}
