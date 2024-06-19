package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.*;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.impl.SmtpLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests not to be included in the actual repo. Its just very convenient to run code this way from IntelliJ
 */
public class SMTPWorkflowTestBench {

    @Disabled
    @Test
    public void testWorkFlow() throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        Config config = Config.createConfig();
        config.setDefaultClientConnection(new OutboundConnection(4443, "localhost"));
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);

        WorkflowTrace trace = new WorkflowTrace();

        SmtpMessage m = new SmtpEHLOCommand("seal.upb.de");
        trace.addTlsAction(new SendAction(m));
        trace.addTlsAction(new SendAction(m));
        trace.addTlsAction(new SendAction(m));

        State state = new State(config, trace);

        //LayerStack stack = LayerStackFactory.createLayerStack(StackConfiguration.SMTP, state.getContext());
        //List<LayerConfiguration<?>> layerConfigurationList = new ArrayList<>();
        //SmtpReply r = new SmtpReply();
        //layerConfigurationList.add(new SpecificSendLayerConfiguration<>(ImplementedLayers.SMTP, List.of(m)));
        //layerConfigurationList.add(null);
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            System.out.println(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            System.out.println(ex);
        }
        //try {
        //    stack.sendData(
        //            layerConfigurationList
        //    );
        //} catch (IOException e) {
        //    throw new RuntimeException(e);
        //}
    }
}
