/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.ftp.command.FtpAUTHCommand;
import de.rub.nds.tlsattacker.core.ftp.command.FtpCommand;
import de.rub.nds.tlsattacker.core.ftp.command.FtpUnknownCommand;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpAUTHReply;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpUnknownReply;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpUnterminatedReply;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;
import de.rub.nds.tlsattacker.core.layer.impl.FtpLayer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the FtpLayer where TLS-Attacker acts as a client, i.e. sends commands and receives
 * replies.
 */
public class FtpLayerOutboundTest {

    private Config config;
    private FtpContext context;
    private FakeTcpTransportHandler transportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.FTP);
        context = new Context(new State(config), new OutboundConnection()).getFtpContext();
        transportHandler = new FakeTcpTransportHandler(null);
        context.setTransportHandler(transportHandler);
        ProviderUtil.addBouncyCastleProvider();
    }

    @Test
    public void testReceiveAuthReply() {
        transportHandler.setFetchableByte(
                "234 AUTH command ok. Initializing TLS Connection.\r\n".getBytes());
        FtpLayer ftpLayer = (FtpLayer) context.getLayerStack().getLayer(FtpLayer.class);
        context.setLastCommand(new FtpAUTHCommand());
        LayerProcessingResult result = ftpLayer.receiveData();
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(FtpAUTHReply.class, result.getUsedContainers().get(0));
        assertEquals(234, ((FtpReply) result.getUsedContainers().get(0)).getReplyCode());
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testReceiveMultilineReply() {
        transportHandler.setFetchableByte("234-First line\r\n234 Last line\r\n".getBytes());
        FtpLayer ftpLayer = (FtpLayer) context.getLayerStack().getLayer(FtpLayer.class);
        context.setLastCommand(new FtpAUTHCommand());
        LayerProcessingResult result = ftpLayer.receiveData();
        assertEquals(1, result.getUsedContainers().size());
        FtpReply reply = (FtpReply) result.getUsedContainers().get(0);
        assertEquals(234, reply.getReplyCode());
        assertEquals(2, reply.getHumanReadableMessages().size());
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testReceivedUnterminatedReply() {
        transportHandler.setFetchableByte("234 blah".getBytes());
        FtpLayer ftpLayer = (FtpLayer) context.getLayerStack().getLayer(FtpLayer.class);
        context.setLastCommand(new FtpUnknownCommand());
        LayerProcessingResult result = ftpLayer.receiveData();
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(FtpUnterminatedReply.class, result.getUsedContainers().get(0));
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testParsingUnknownReply() {
        transportHandler.setFetchableByte("220 ftp.example.com FTP service ready\r\n".getBytes());
        FtpLayer ftpLayer = (FtpLayer) context.getLayerStack().getLayer(FtpLayer.class);
        context.setLastCommand(new FtpUnknownCommand());
        LayerProcessingResult result = ftpLayer.receiveData();
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(FtpUnknownReply.class, result.getUsedContainers().get(0));
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testSendData() {
        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        context.getLayerStack()
                                .getLayer(FtpLayer.class)
                                .sendData(null, "Test".getBytes()));
    }

    @Test
    public void testSendConfiguration() throws IOException {
        List<FtpCommand> ftpMessages = new ArrayList<>();
        ftpMessages.add(new FtpAUTHCommand());

        FtpLayer ftpLayer = (FtpLayer) context.getLayerStack().getLayer(FtpLayer.class);
        SpecificSendLayerConfiguration<FtpCommand> layerConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.FTP, ftpMessages);
        ftpLayer.setLayerConfiguration(layerConfiguration);
        LayerProcessingResult result = ftpLayer.sendConfiguration();
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(FtpAUTHCommand.class, result.getUsedContainers().get(0));
    }
}
