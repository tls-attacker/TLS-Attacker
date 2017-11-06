/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class CertificateFetcher {

    private static final Logger LOGGER = LogManager.getLogger(CertificateFetcher.class.getName());

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
        State state = new State(config);
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                WorkflowExecutorType.DEFAULT, state);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
            LOGGER.warn("Could not fetch ServerCertificate");
            LOGGER.debug(E);
        }
        return state.getTlsContext().getServerCertificate();
    }

    private CertificateFetcher() {

    }
}
