package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.impl.SmtpLayer;
import de.rub.nds.tlsattacker.core.smtp.command.*;
import de.rub.nds.tlsattacker.core.smtp.reply.*;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for the SmtpLayer where TLS-Attacker acts as a server, i.e. receiving commands and sending replies.
 * Warning: This was not the focus of the original project, so the tests are not as comprehensive as the other tests. There are no according integration tests.
 */
public class SmtpLayerInboundTest {

    private Config config;
    private SmtpContext context;
    private FakeTransportHandler transportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        context = new Context(new State(config), new InboundConnection()).getSmtpContext();
        transportHandler = new FakeTransportHandler(null);
        context.setTransportHandler(transportHandler);
        ProviderUtil.addBouncyCastleProvider();
    }


    @Test
    public void testReceiveKnownCommand() {
        transportHandler.setFetchableByte("HELO xyz\r\n".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        assert (result.getUsedContainers().size() == 1) && (result.getUsedContainers().get(0) instanceof SmtpHELOCommand);
        assert ((SmtpCommand) result.getUsedContainers().get(0)).getVerb().equals("HELO");
        assert ((SmtpCommand) result.getUsedContainers().get(0)).getParameters().equals("xyz");
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testReceiveUnknownCommand() {
        transportHandler.setFetchableByte("UNKNOWNCOMMAND xyz\r\n".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        assert (result.getUsedContainers().size() == 1) && (result.getUsedContainers().get(0) instanceof SmtpUnknownCommand);
        assert ((SmtpCommand) result.getUsedContainers().get(0)).getVerb().equals("UNKNOWNCOMMAND");
        assert ((SmtpCommand) result.getUsedContainers().get(0)).getParameters().equals("xyz");
        assertEquals(0, result.getUnreadBytes().length);
    }

    /**
     * Tests if the SmtpLayer still saves a command as an unknown command if the original parser raises a ParserException.
     */
    @Test
    public void testFallbackToUnknownReply() {
        // The AUTH command requires parameters, so this should raise a ParserException.
        transportHandler.setFetchableByte("AUTH\r\n".getBytes());
        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        context.setLastCommand(new SmtpEHLOCommand());
        LayerProcessingResult result = smtpLayer.receiveData();
        System.out.println(result.getUsedContainers());
        System.out.println(Arrays.toString(result.getUnreadBytes()));;
        assert (result.getUsedContainers().size() == 1) && (result.getUsedContainers().get(0) instanceof SmtpUnknownCommand);
        assertEquals(0, result.getUnreadBytes().length);
    }

    @Test
    public void testSendData() {
        assertThrows(UnsupportedOperationException.class, () -> context.getLayerStack().getLayer(SmtpLayer.class).sendData(null, "Test".getBytes()));
    }

    @Test
    public void testSendConfiguration() throws IOException {
        List<SmtpReply> smtpMessages = new ArrayList<>();
        smtpMessages.add(new SmtpEHLOReply());
        smtpMessages.add(new SmtpNOOPReply());

        SmtpLayer smtpLayer = (SmtpLayer) context.getLayerStack().getLayer(SmtpLayer.class);
        SpecificSendLayerConfiguration<SmtpReply> layerConfiguration;

        layerConfiguration =
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.SMTP, smtpMessages);
        smtpLayer.setLayerConfiguration(layerConfiguration);
        LayerProcessingResult result = smtpLayer.sendConfiguration();
        assertEquals(2, result.getUsedContainers().size());
        assert (result.getUsedContainers().get(0) instanceof SmtpEHLOReply) && (result.getUsedContainers().get(1) instanceof SmtpNOOPReply);
    }
}
