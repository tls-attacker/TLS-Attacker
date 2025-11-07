/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.impl.Pop3Layer;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3NOOPCommand;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3USERCommand;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3UnknownCommand;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3UnknownReply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3UnterminatedReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for the Pop3Layer where TLS-Attacker acts as a client, i.e. sends commands and receives
 * replies.
 */
public class Pop3LayerOutboundTest {

    private Config config;
    private Pop3Context context;
    private FakeTcpTransportHandler transportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.POP3);
        context = new Context(new State(config), new OutboundConnection()).getPop3Context();
        transportHandler = new FakeTcpTransportHandler(null);
        context.setTransportHandler(transportHandler);
        ProviderUtil.addBouncyCastleProvider();
    }

    @Test
    public void testReceivedUnterminatedReply() {
        transportHandler.setFetchableByte("+OK blah".getBytes());
        Pop3Layer smtpLayer = (Pop3Layer) context.getLayerStack().getLayer(Pop3Layer.class);
        context.setLastCommand(new Pop3UnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        assert (result.getUsedContainers().size() == 1)
                && (result.getUsedContainers().get(0) instanceof Pop3UnterminatedReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testParsingUnknownReply() {
        transportHandler.setFetchableByte("220 smtp.example.com ESMTP Postfix\r\n".getBytes());
        Pop3Layer smtpLayer = (Pop3Layer) context.getLayerStack().getLayer(Pop3Layer.class);
        context.setLastCommand(new Pop3UnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        assert (result.getUsedContainers().size() == 1)
                && (result.getUsedContainers().get(0) instanceof Pop3UnknownReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testParsingUnknownReplies() {
        transportHandler.setFetchableByte("220 a\r\n221 b\r\n".getBytes());
        Pop3Layer smtpLayer = (Pop3Layer) context.getLayerStack().getLayer(Pop3Layer.class);
        context.setLastCommand(new Pop3UnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        assert (result.getUsedContainers().size() == 2)
                && (result.getUsedContainers().get(0) instanceof Pop3UnknownReply)
                && (result.getUsedContainers().get(1) instanceof Pop3UnknownReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testSendData() {
        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        context.getLayerStack()
                                .getLayer(Pop3Layer.class)
                                .sendData(null, "Test".getBytes()));
    }

    @Test
    public void testSendConfiguration() throws IOException {
        List<Pop3Command> pop3Messages = new ArrayList<>();
        pop3Messages.add(new Pop3USERCommand());
        pop3Messages.add(new Pop3NOOPCommand());

        Pop3Layer smtpLayer = (Pop3Layer) context.getLayerStack().getLayer(Pop3Layer.class);
        SpecificSendLayerConfiguration<Pop3Command> layerConfiguration;

        layerConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.POP3, pop3Messages);
        smtpLayer.setLayerConfiguration(layerConfiguration);
        LayerProcessingResult result = smtpLayer.sendConfiguration();
        assertEquals(2, result.getUsedContainers().size());
        assert (result.getUsedContainers().get(0) instanceof Pop3USERCommand)
                && (result.getUsedContainers().get(1) instanceof Pop3NOOPCommand);
    }
}
