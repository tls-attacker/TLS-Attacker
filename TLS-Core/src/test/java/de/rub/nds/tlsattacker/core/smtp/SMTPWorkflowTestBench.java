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
import de.rub.nds.tlsattacker.core.layer.*;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpInitialGreeting;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
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
        config.setDefaultClientConnection(new OutboundConnection(4443, "localhost"));
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);

        WorkflowTrace trace = new WorkflowTrace();

        SmtpReply initialGreeting = new SmtpInitialGreeting();
        SmtpMessage m = new SmtpEHLOCommand("seal.upb.de");
        trace.addTlsAction(new ReceiveAction(initialGreeting));
        trace.addTlsAction(new SendAction(m));
        trace.addTlsAction(new WaitAction(1000));
        trace.addTlsAction(new ReceiveAction(new SmtpEHLOReply()));
        trace.addTlsAction(new WaitAction(1000));
        trace.addTlsAction(new SendAction(m));

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

        System.out.println(state.getWorkflowTrace().executedAsPlanned());
        String res = WorkflowTraceSerializer.write(state.getWorkflowTrace());
        System.out.println(res);
    }
}
