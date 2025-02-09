package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.impl.SSL2Layer;
import de.rub.nds.tlsattacker.core.layer.impl.SmtpLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpUnknownCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnknownReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnterminatedReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SmtpLayerTest {

    private Config config;
    private SmtpContext context;
    private FakeTransportHandler transportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        context = new Context(new State(config), new OutboundConnection()).getSmtpContext();
        transportHandler = new FakeTransportHandler(null);
        context.setTransportHandler(transportHandler);
        ProviderUtil.addBouncyCastleProvider();
    }

    @Test
    public void testUnterminatedParse() throws IOException {
        transportHandler.setFetchableByte("220 smtp.example.com ESMTP Postfix".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpUnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        assert (result.getUsedContainers().size() == 1) && (result.getUsedContainers().get(0) instanceof SmtpUnterminatedReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testParsingUnknownReply() {
        transportHandler.setFetchableByte("220 smtp.example.com ESMTP Postfix\r\n".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpUnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        assert (result.getUsedContainers().size() == 1) && (result.getUsedContainers().get(0) instanceof SmtpUnknownReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testParsingUnknownReplies() {
        transportHandler.setFetchableByte("220 a\r\n221 b\r\n".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpUnknownCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        assert (result.getUsedContainers().size() == 2) && (result.getUsedContainers().get(0) instanceof SmtpUnknownReply) && (result.getUsedContainers().get(1) instanceof SmtpUnknownReply);
        assertEquals(0, result.getUnreadBytes().length);
    }

    /**
     * Tests if the SmtpLayer still catches the reply as an unknown reply if the original parser raises a ParserException.
     * For replies this should only happen if a multiline reply is not terminated correctly.
     */
    @Test
    public void testFallbackToUnknownReply() {
        transportHandler.setFetchableByte("250-example.org\r\nabc".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpEHLOCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        System.out.println(Arrays.toString(result.getUnreadBytes()));;
        assert (result.getUsedContainers().size() == 1) && (result.getUsedContainers().get(0) instanceof SmtpUnknownReply);
    }
}
