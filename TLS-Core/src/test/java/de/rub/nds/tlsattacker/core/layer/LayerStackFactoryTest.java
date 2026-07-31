/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class LayerStackFactoryTest {

    /**
     * The generic STARTTLS stack must contain TCP, RECORD and MESSAGE layers, with RECORD and
     * MESSAGE disabled so the plaintext upgrade exchange runs over TCP until an EnableLayerAction
     * turns them on.
     */
    @Test
    public void testStarttlsStackHasDisabledTlsLayers() {
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.GENERIC_OPPORTUNISTIC_TLS);
        State state = new State(config);

        LayerStack layerStack = state.getContext().getLayerStack();

        ProtocolLayer<?, ?, ?> tcp = layerStack.getLayer(ImplementedLayers.TCP);
        ProtocolLayer<?, ?, ?> record = layerStack.getLayer(ImplementedLayers.RECORD);
        ProtocolLayer<?, ?, ?> message = layerStack.getLayer(ImplementedLayers.MESSAGE);

        assertNotNull(tcp);
        assertNotNull(record);
        assertNotNull(message);
        assertTrue(tcp.isEnabled());
        assertFalse(record.isEnabled());
        assertFalse(message.isEnabled());
    }

    /**
     * getInitiallyDisabledLayers is what a STARTTLS upgrade targets, so it has to keep matching the
     * layers that createLayerStack actually creates in a disabled state. Checking every stack
     * configuration against a real stack keeps the two from drifting apart unnoticed.
     */
    @ParameterizedTest
    @EnumSource(StackConfiguration.class)
    public void testInitiallyDisabledLayersMatchesBuiltStack(
            StackConfiguration stackConfiguration) {
        // stacks that cannot be instantiated are out of scope
        assumeTrue(stackConfiguration != StackConfiguration.OPEN_VPN);

        Config config = new Config();
        config.setDefaultLayerConfiguration(stackConfiguration);
        LayerStack layerStack = new State(config).getContext().getLayerStack();

        Set<ImplementedLayers> disabledInStack =
                layerStack.getLayerList().stream()
                        .filter(layer -> !layer.isEnabled())
                        .map(layer -> (ImplementedLayers) layer.getLayerType())
                        .collect(Collectors.toSet());

        assertEquals(
                disabledInStack,
                Set.copyOf(LayerStackFactory.getInitiallyDisabledLayers(stackConfiguration)));
    }
}
