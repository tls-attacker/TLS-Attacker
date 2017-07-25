/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateFetcher {

    private static final Logger LOGGER = LogManager.getLogger(CertificateFetcher.class.getName());

    public static PublicKey fetchServerPublicKey(TlsConfig config) {
        X509CertificateObject cert;
        try {
            cert = new X509CertificateObject(fetchServerCertificate(config).getCertificateAt(0));
        } catch (CertificateParsingException ex) {
            throw new WorkflowExecutionException("Could not get public key from server certificate", ex);
        }
        return cert.getPublicKey();
    }

    public static Certificate fetchServerCertificate(TlsConfig config) {
        TlsContext context = new TlsContext(config);
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);
        ExecutorType type = context.getConfig().getHighestProtocolVersion().isDTLS() ? ExecutorType.DTLS
                : ExecutorType.TLS;
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(type, context);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
            LOGGER.warn("Could not fetch ServerCertificate");
            LOGGER.debug(E);
        }
        return context.getServerCertificate();
    }

    private CertificateFetcher() {

    }
}
