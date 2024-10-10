/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.quic.frame.NewConnectionIdFrame;
import de.rub.nds.tlsattacker.core.smtp.command.*;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline.*;
import de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.SmtpEHLOReply;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.WaitAction;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.security.Security;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Tests not to be included in the actual repo. Its just very convenient to run code this way from
 * IntelliJ
 */
public class SMTPWorkflowTestBench {

    @BeforeEach
    public void changeLoglevel() {
        Configurator.setAllLevels("de.rub.nds.tlsattacker", org.apache.logging.log4j.Level.ALL);
    }

    @Disabled
    @Test
    public void testWorkFlow() throws IOException, JAXBException {
        Security.addProvider(new BouncyCastleProvider());
        Config config = Config.createConfig();
        config.setDefaultClientConnection(new OutboundConnection(2525, "localhost"));
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);

        WorkflowTrace trace = new WorkflowTrace();

        trace.addTlsAction(new ReceiveAction(new SmtpInitialGreeting()));
        trace.addTlsAction(new SendAction(new SmtpEHLOCommand("seal.upb.de")));
        trace.addTlsAction(new ReceiveAction(new SmtpEHLOReply()));
        trace.addTlsAction(new SendAction(new SmtpAUTHCommand("PLAIN","dXNlcm5hbWU6cGFzc3dvcmQK" )));
        trace.addTlsAction(new ReceiveAction(new SmtpAUTHReply()));
        trace.addTlsAction(new SendAction(new SmtpNOOPCommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpNOOPReply()));
        trace.addTlsAction(new SendAction(new SmtpMAILCommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpMAILReply()));
        trace.addTlsAction(new SendAction(new SmtpRESETCommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpRESETReply()));
        trace.addTlsAction(new SendAction(new SmtpMAILCommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpMAILReply()));
        trace.addTlsAction(new SendAction(new SmtpQUITCommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpQUITReply()));

        State state = new State(config, trace);

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

//        System.out.println(state.getWorkflowTrace().executedAsPlanned());
//        String res = WorkflowTraceSerializer.write(state.getWorkflowTrace());
//        System.out.println(res);
        assert (state.getWorkflowTrace().executedAsPlanned());
    }
}
