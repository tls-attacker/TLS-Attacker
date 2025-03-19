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
import de.rub.nds.tlsattacker.core.layer.impl.ToggleableLayerWrapper;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DisableLayerActionTest {
    private Config config;
    private State state;

    @BeforeEach
    public void setUp() {
        config = new Config();
        state = new State(config);
    }

    @Test
    public void testToggleDisabledLayer() {
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        new ToggleableLayerWrapper<>(
                                new HttpLayer(state.getContext().getHttpContext()), false),
                        new TcpLayer(state.getContext().getTcpContext()));
        state.getContext().setLayerStack(layerStack);
        ToggleableLayerWrapper wrapper =
                (ToggleableLayerWrapper)
                        state.getContext().getLayerStack().getLayer(HttpLayer.class);
        assert wrapper != null;

        DisableLayerAction action = new DisableLayerAction(ImplementedLayers.HTTP);
        assert !wrapper.isActive();
        action.execute(state);
        assert !wrapper.isActive();
        assert action.executedAsPlanned();
        assert action.isExecuted();
    }

    @Test
    public void testToggleAlreadyEnabledLayer() {
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        new ToggleableLayerWrapper<>(
                                new HttpLayer(state.getContext().getHttpContext())),
                        new TcpLayer(state.getContext().getTcpContext()));
        state.getContext().setLayerStack(layerStack);
        ToggleableLayerWrapper wrapper =
                (ToggleableLayerWrapper)
                        state.getContext().getLayerStack().getLayer(HttpLayer.class);
        assert wrapper != null;

        DisableLayerAction action = new DisableLayerAction(ImplementedLayers.HTTP);
        assert wrapper.isActive();
        action.execute(state);
        assert !wrapper.isActive();
        assert action.executedAsPlanned();
        assert action.isExecuted();
    }

    @Test
    public void testEnableLayerNotInStack() {
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        new ToggleableLayerWrapper<>(
                                new HttpLayer(state.getContext().getHttpContext())),
                        new TcpLayer(state.getContext().getTcpContext()));
        state.getContext().setLayerStack(layerStack);

        DisableLayerAction action = new DisableLayerAction(ImplementedLayers.SMTP);
        action.execute(state);
        Assertions.assertFalse(action.executedAsPlanned());
        assert action.isExecuted();
    }
}
