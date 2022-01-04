/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class CertificateFetcher {

    private static final Logger LOGGER = LogManager.getLogger();

    public static PublicKey fetchServerPublicKey(Config config) {
        X509CertificateObject cert;
        try {
            Certificate fetchedServerCertificate = fetchServerCertificate(config);
            if (fetchedServerCertificate != null && fetchedServerCertificate.getLength() > 0) {
                cert = new X509CertificateObject(fetchedServerCertificate.getCertificateAt(0));
                return cert.getPublicKey();
            }
        } catch (CertificateParsingException ex) {
            throw new WorkflowExecutionException("Could not get public key from server certificate", ex);
        }
        return null;
    }

    public static Certificate fetchServerCertificate(Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        if (config.getHighestProtocolVersion().isDTLS()) {
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
            trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        }
        trace.addTlsAction(new ReceiveTillAction(new CertificateMessage(config)));
        State state = new State(config, trace);

        WorkflowExecutor workflowExecutor =
            WorkflowExecutorFactory.createWorkflowExecutor(config.getWorkflowExecutorType(), state);
        try {
            workflowExecutor.executeWorkflow();

            if (!state.getTlsContext().getTransportHandler().isClosed()) {
                state.getTlsContext().getTransportHandler().closeConnection();
            }
        } catch (IOException | WorkflowExecutionException e) {
            LOGGER.warn("Could not fetch ServerCertificate");
            LOGGER.debug(e);
        }
        return state.getTlsContext().getServerCertificate();
    }

    private CertificateFetcher() {

    }
}
