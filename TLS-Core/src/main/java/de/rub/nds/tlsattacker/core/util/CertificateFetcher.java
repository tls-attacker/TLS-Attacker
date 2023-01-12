/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.certificate.CertificateAnalyzer;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.x509attacker.x509.base.X509CertificateChain;
import de.rub.nds.x509attacker.x509.base.publickey.X509PublicKeyContent;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateFetcher {

    private static final Logger LOGGER = LogManager.getLogger();

    public static X509PublicKeyContent fetchServerPublicKey(Config config)
            throws CertificateParsingException {

        X509CertificateChain fetchedServerCertificateChain = fetchServerCertificateChain(config);
        if (fetchedServerCertificateChain != null
                && fetchedServerCertificateChain.getCertificateList().isEmpty()) {
            return CertificateAnalyzer.getPublicKey(fetchedServerCertificateChain.getLeaf());
        }
        return null;
    }

    public static X509CertificateChain fetchServerCertificateChain(Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        if (config.getHighestProtocolVersion().isDTLS()) {
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
            trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        }
        trace.addTlsAction(new ReceiveTillAction(new CertificateMessage()));
        State state = new State(config, trace);

        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);
        try {
            workflowExecutor.executeWorkflow();

            if (!state.getContext().getTransportHandler().isClosed()) {
                state.getContext().getTransportHandler().closeConnection();
            }
        } catch (IOException | WorkflowExecutionException e) {
            LOGGER.warn("Could not fetch ServerCertificate", e);
        }
        return state.getTlsContext().getServerCertificateChain();
    }

    private CertificateFetcher() {}
}
