package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.*;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.impl.SmtpLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests not to be included in the actual repo. Its just very convenient to run code this way from IntelliJ
 */
public class SMTPWorkflowTestBench {

    @Test
    public void testWorkFlow() throws IOException {
        Config config = new Config();
        AliasedConnection connection = new OutboundConnection(4443, "localhost");
        connection.setIp("127.0.0.1");
        connection.setConnectionTimeout(5);
        connection.setTimeout(5);
        connection.setUseIpv6(false);
        TransportHandler transportHandler = new ClientTcpTransportHandler(connection);
        transportHandler.initialize();
        State state = new State();
        Context context = new Context(state, connection);
        context.setTransportHandler(transportHandler);
        TcpLayer tcpLayer = new TcpLayer(new TcpContext(context));
        SmtpLayer smtpLayer = new SmtpLayer(new SmtpContext(context));
        LayerStack stack = new LayerStack(
               context,
                smtpLayer,
                tcpLayer
        );
        List<LayerConfiguration<?>> layerConfigurationList = new ArrayList<>();
        SmtpMessage m = new SmtpEHLOCommand("seal.upb.de");
        SmtpReply r = new SmtpReply();
        layerConfigurationList.add(new SpecificSendLayerConfiguration<>(ImplementedLayers.SMTP, List.of(m, r)));
        layerConfigurationList.add(null);
        try {
            stack.sendData(
                    layerConfigurationList
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
