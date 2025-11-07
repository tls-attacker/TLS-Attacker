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
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.impl.Pop3Layer;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3USERCommand;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3UnknownCommand;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3NOOPReply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3USERReply;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Pop3Layer where TLS-Attacker acts as a server, i.e. receiving commands and sending
 * replies. Warning: This was not the focus of the original project, so the tests are not as
 * comprehensive as the other tests. There are no according integration tests.
 */
public class Pop3LayerInboundTest {

    private Config config;
    private Pop3Context context;
    private FakeTcpTransportHandler transportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.POP3);
        context = new Context(new State(config), new InboundConnection()).getPop3Context();
        transportHandler = new FakeTcpTransportHandler(null);
        context.setTransportHandler(transportHandler);
        ProviderUtil.addBouncyCastleProvider();
    }

    @Test
    public void testReceiveKnownCommand() {
        transportHandler.setFetchableByte("USER xyz\r\n".getBytes());
        Pop3Layer smtpLayer = (Pop3Layer) context.getLayerStack().getLayer(Pop3Layer.class);
        LayerProcessingResult result = smtpLayer.receiveData();
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(Pop3USERCommand.class, result.getUsedContainers().getFirst());
        assertEquals(Pop3CommandType.USER, ((Pop3Command) result.getUsedContainers().getFirst())
                .getCommandType());
        assertEquals("xyz", ((Pop3Command) result.getUsedContainers().getFirst()).getArguments());
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testReceiveUnknownCommand() {
        transportHandler.setFetchableByte("UNKW xyz\r\n".getBytes());
        Pop3Layer smtpLayer = (Pop3Layer) context.getLayerStack().getLayer(Pop3Layer.class);
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(Pop3UnknownCommand.class, result.getUsedContainers().getFirst());
        assertEquals(Pop3CommandType.UNKNOWN, ((Pop3Command) result.getUsedContainers().getFirst())
                .getCommandType());
        assertEquals("xyz", ((Pop3Command) result.getUsedContainers().getFirst()).getArguments());
        assertEquals("UNKW", ((Pop3UnknownCommand) result.getUsedContainers().getFirst()).getUnknownCommandVerb());
        assertEquals(0, result.getUnreadBytes().length);
    }

    /**
     * Tests if the Pop3Layer still saves a command as an unknown command if the original parser
     * raises a ParserException.
     */
    @Test
    public void testFallbackToUnknownReply() {
        // The AUTH command requires parameters, so this should raise a ParserException.
        transportHandler.setFetchableByte("AUTH\r\n".getBytes());
        Pop3Layer smtpLayer = (Pop3Layer) context.getLayerStack().getLayer(Pop3Layer.class);
        context.setLastCommand(new Pop3USERCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        System.out.println(Arrays.toString(result.getUnreadBytes()));
        assertEquals(1, result.getUsedContainers().size());
        assertInstanceOf(Pop3UnknownCommand.class, result.getUsedContainers().getFirst());
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
        List<Pop3Reply> smtpMessages = new ArrayList<>();
        smtpMessages.add(new Pop3USERReply());
        smtpMessages.add(new Pop3NOOPReply());

        Pop3Layer smtpLayer = (Pop3Layer) context.getLayerStack().getLayer(Pop3Layer.class);
        SpecificSendLayerConfiguration<Pop3Reply> layerConfiguration;

        layerConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.POP3, smtpMessages);
        smtpLayer.setLayerConfiguration(layerConfiguration);
        LayerProcessingResult result = smtpLayer.sendConfiguration();
        assertEquals(2, result.getUsedContainers().size());
        assertInstanceOf(Pop3USERReply.class, result.getUsedContainers().get(0));
        assertInstanceOf(Pop3NOOPReply.class, result.getUsedContainers().get(1));
    }
}
