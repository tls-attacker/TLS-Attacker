/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.ftp.command.FtpAUTHCommand;
import de.rub.nds.tlsattacker.core.ftp.command.FtpCommand;
import de.rub.nds.tlsattacker.core.ftp.command.FtpUnknownCommand;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpAUTHReply;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
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
 * Tests for the FtpLayer where TLS-Attacker acts as a server, i.e. receiving commands and sending
 * replies.
 */
public class FtpLayerInboundTest {

    private Config config;
    private FtpContext context;
    private FakeTcpTransportHandler transportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.FTP);
        context = new Context(new State(config), new InboundConnection()).getFtpContext();
        transportHandler = new FakeTcpTransportHandler(null);
        context.setTransportHandler(transportHandler);
        ProviderUtil.addBouncyCastleProvider();
    }

    @Test
    public void testReceiveKnownCommand() {
        transportHandler.setFetchableByte("AUTH TLS\r\n".getBytes());
        FtpLayer ftpLayer = (FtpLayer) context.getLayerStack().getLayer(FtpLayer.class);
        LayerProcessingResult result = ftpLayer.receiveData();
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(FtpAUTHCommand.class, result.getUsedContainers().getFirst());
        assertEquals(
                FtpCommandType.AUTH,
                ((FtpCommand) result.getUsedContainers().getFirst()).getCommandType());
        assertEquals("TLS", ((FtpCommand) result.getUsedContainers().getFirst()).getArguments());
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testReceiveUnknownCommand() {
        transportHandler.setFetchableByte("UNKW xyz\r\n".getBytes());
        FtpLayer ftpLayer = (FtpLayer) context.getLayerStack().getLayer(FtpLayer.class);
        LayerProcessingResult result = ftpLayer.receiveData();
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(FtpUnknownCommand.class, result.getUsedContainers().getFirst());
        assertEquals(
                FtpCommandType.UNKNOWN,
                ((FtpCommand) result.getUsedContainers().getFirst()).getCommandType());
        assertEquals("xyz", ((FtpCommand) result.getUsedContainers().getFirst()).getArguments());
        assertEquals(
                "UNKW",
                ((FtpUnknownCommand) result.getUsedContainers().getFirst())
                        .getUnknownCommandVerb());
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
        List<FtpReply> ftpMessages = new ArrayList<>();
        ftpMessages.add(new FtpAUTHReply());

        FtpLayer ftpLayer = (FtpLayer) context.getLayerStack().getLayer(FtpLayer.class);
        SpecificSendLayerConfiguration<FtpReply> layerConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.FTP, ftpMessages);
        ftpLayer.setLayerConfiguration(layerConfiguration);
        LayerProcessingResult result = ftpLayer.sendConfiguration();
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(FtpAUTHReply.class, result.getUsedContainers().get(0));
    }
}
