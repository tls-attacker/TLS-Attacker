/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.impl.SmtpLayer;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpNOOPCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpUnknownCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnknownReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnterminatedReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the SmtpLayer where TLS-Attacker acts as a client, i.e. sends commands and receives
 * replies.
 */
public class SmtpLayerOutboundTest {

    private Config config;
    private SmtpContext context;
    private FakeTcpTransportHandler transportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        context = new Context(new State(config), new OutboundConnection()).getSmtpContext();
        transportHandler = new FakeTcpTransportHandler(null);
        context.setTransportHandler(transportHandler);
        ProviderUtil.addBouncyCastleProvider();
    }

    @Test
    public void testReceivedUnterminatedReply() {
        transportHandler.setFetchableByte("220 smtp.example.com ESMTP Postfix".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpUnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        assert (result.getUsedContainers().size() == 1)
                && (result.getUsedContainers().get(0) instanceof SmtpUnterminatedReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testParsingUnknownReply() {
        transportHandler.setFetchableByte("220 smtp.example.com ESMTP Postfix\r\n".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpUnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        assert (result.getUsedContainers().size() == 1)
                && (result.getUsedContainers().get(0) instanceof SmtpUnknownReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testParsingUnknownReplies() {
        transportHandler.setFetchableByte("220 a\r\n221 b\r\n".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpUnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        assert (result.getUsedContainers().size() == 2)
                && (result.getUsedContainers().get(0) instanceof SmtpUnknownReply)
                && (result.getUsedContainers().get(1) instanceof SmtpUnknownReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    /**
     * Tests if the SmtpLayer still catches the reply as an unknown reply if the original parser
     * raises a ParserException. For replies this should only happen if a multiline reply is not
     * terminated correctly.
     */
    @Test
    public void testFallbackToUnknownReply() {
        transportHandler.setFetchableByte("250-example.org\r\nabc\r\n".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpEHLOCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        System.out.println(Arrays.toString(result.getUnreadBytes()));
        ;
        assert (result.getUsedContainers().size() == 1)
                && (result.getUsedContainers().get(0) instanceof SmtpUnknownReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testSendData() {
        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        context.getLayerStack()
                                .getLayer(SmtpLayer.class)
                                .sendData(null, "Test".getBytes()));
    }

    @Test
    public void testSendConfiguration() throws IOException {
        List<SmtpCommand> smtpMessages = new ArrayList<>();
        smtpMessages.add(new SmtpEHLOCommand());
        smtpMessages.add(new SmtpNOOPCommand());

        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        SpecificSendLayerConfiguration<SmtpCommand> layerConfiguration;

        layerConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.SMTP, smtpMessages);
        smtpLayer.setLayerConfiguration(layerConfiguration);
        LayerProcessingResult result = smtpLayer.sendConfiguration();
        assertEquals(2, result.getUsedContainers().size());
        assert (result.getUsedContainers().get(0) instanceof SmtpEHLOCommand)
                && (result.getUsedContainers().get(1) instanceof SmtpNOOPCommand);
    }
}
