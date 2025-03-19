/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.ToggleLayerActionTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests the ToggleableLayerWrapper class. Some testing is also done in ToggleLayerActionTest which
 * actually uses it. Ideally, the tests should also cover the active case (to check that itself
 * wrapping doesn't change normal behavior), but that would require a lot of setup. For now, the
 * tests are limited to the inactive case.
 *
 * @see ToggleLayerActionTest
 */
class ToggleableLayerWrapperTest {
    private Config config;
    private State state;
    private FakeTransportHandler transportHandler;

    @BeforeEach
    public void setUp() {
        ProviderUtil.addBouncyCastleProvider();
        config = new Config();
        state = new State(config);
        transportHandler = new FakeTransportHandler(null);
        state.getContext().setTransportHandler(transportHandler);
    }

    /** Tests that sendData() of a inactive wrapped layer is just a pass-through. */
    @Test
    public void testSendDataWhenInactive() {
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        new SmtpLayer(state.getSmtpContext()),
                        // not the cleanest way, but it would be obvious if the MessageLayer was
                        // used
                        new ToggleableLayerWrapper<>(
                                new MessageLayer(state.getTlsContext()), false),
                        new TcpLayer(state.getTcpContext()));
        state.getContext().setLayerStack(layerStack);

        SmtpEHLOCommand command = new SmtpEHLOCommand();
        SendAction action = new SendAction(command);
        action.setConnectionAlias(state.getContext().getConnection().getAlias());

        action.execute(state);
        // passing through the layer should result in the same byte array
        byte[] layerStackSerializationResult = transportHandler.getSendByte();
        byte[] directSerializationResult =
                command.getSerializer(state.getSmtpContext()).serialize();

        Assertions.assertArrayEquals(layerStackSerializationResult, directSerializationResult);
    }

    /**
     * Tests that sendConfiguration() <b>fails</b> without sending anything, when
     * throwExceptionOnSendConfiguration is true.
     */
    @Test
    public void testSendConfigurationWhenInactive() {
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        // inactive smtp layer
                        new ToggleableLayerWrapper<>(
                                new SmtpLayer(state.getSmtpContext()), false, true),
                        new TcpLayer(state.getTcpContext()));
        state.getContext().setLayerStack(layerStack);

        SmtpEHLOCommand command = new SmtpEHLOCommand();
        SendAction action = new SendAction(command);
        action.setConnectionAlias(state.getContext().getConnection().getAlias());

        action.execute(state);
        Assertions.assertFalse(action.executedAsPlanned());
        Assertions.assertArrayEquals(new byte[0], transportHandler.getSendByte());
    }

    /**
     * Tests that sendConfiguration() <b>succeeds</b> without sending anything, when
     * throwExceptionOnSendConfiguration is false.
     */
    @Test
    public void testSendConfigurationWhenInactiveButNoThrowException() {
        LayerStack layerStack =
                new LayerStack(
                        state.getContext(),
                        // inactive smtp layer
                        new ToggleableLayerWrapper<>(
                                new SmtpLayer(state.getSmtpContext()), false, false),
                        new TcpLayer(state.getTcpContext()));
        state.getContext().setLayerStack(layerStack);

        SmtpEHLOCommand command = new SmtpEHLOCommand();
        SendAction action = new SendAction(command);
        action.setConnectionAlias(state.getContext().getConnection().getAlias());

        action.execute(state);
        Assertions.assertTrue(action.executedAsPlanned());
        Assertions.assertArrayEquals(new byte[0], transportHandler.getSendByte());
    }
}
