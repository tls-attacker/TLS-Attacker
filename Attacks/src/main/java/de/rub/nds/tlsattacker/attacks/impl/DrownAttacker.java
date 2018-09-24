/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.DrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ClientMasterKeyPreparator;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 */
public class DrownAttacker extends Attacker<DrownCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void md5Update(MD5Digest md5, byte[] bytes) {
        md5.update(bytes, 0, bytes.length);
    }

    /**
     *
     * @param config
     * @param baseConfig
     */
    public DrownAttacker(DrownCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        DrownVulnerabilityType type = getDrownVulnerabilityType();
        switch (type) {
            case FULL:
                CONSOLE.error("Server is vulnerable to the full DROWN attack");
                return true;
            case NONE:
                return false;
            case SSL2:
                CONSOLE.warn("Server supports SSL2, but not any weak ciphersuites, " + "so is not vulnerable to DROWN");
                return false;
            case UNKNOWN:
                CONSOLE.info("Could not execute Workflow - something went wrong. Check the Debug output to be certain");
                return null;
        }
        return null;
    }

    /**
     *
     * @return
     */
    public DrownVulnerabilityType getDrownVulnerabilityType() {
        Config tlsConfig = getTlsConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(
                WorkflowTraceType.SSL2_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(new SSL2ClientMasterKeyMessage()));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerVerifyMessage()));
        State state = new State(tlsConfig, trace);
        try {
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                    tlsConfig.getWorkflowExecutorType(), state);
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex);
            return DrownVulnerabilityType.UNKNOWN;
        }

        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SSL2_SERVER_HELLO, trace)) {
            return DrownVulnerabilityType.NONE;
        }

        SSL2ServerHelloMessage serverHello = (SSL2ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(
                HandshakeMessageType.SSL2_SERVER_HELLO, trace);
        List<SSL2CipherSuite> serverCipherSuites = SSL2CipherSuite.getCiphersuites(serverHello.getCipherSuites()
                .getValue());
        for (SSL2CipherSuite cipherSuite : serverCipherSuites) {
            if (cipherSuite.isWeak()) {
                LOGGER.debug("Declaring host as vulnerable based on weak ciphersuite in ServerHello.");
                return DrownVulnerabilityType.FULL;
            }
        }
        SSL2ServerVerifyMessage message = (SSL2ServerVerifyMessage) WorkflowTraceUtil.getFirstReceivedMessage(
                HandshakeMessageType.SSL2_SERVER_VERIFY, trace);
        if (message != null && checkServerVerifyMessage(message, state.getTlsContext())) {
            LOGGER.debug("Declaring host as vulnerable based on ServerVerify.");
            return DrownVulnerabilityType.FULL;
        }
        return DrownVulnerabilityType.SSL2;
    }

    private boolean checkServerVerifyMessage(SSL2ServerVerifyMessage message, TlsContext context) {
        byte[] md5Output = getMD5Output(context);

        RC4Engine rc4 = new RC4Engine();
        rc4.init(false, new KeyParameter(md5Output));
        byte[] encrypted = message.getEncryptedPart().getValue();
        int len = encrypted.length;
        if (len < 16) {
            return false;
        }

        byte[] decrypted = new byte[len];
        rc4.processBytes(encrypted, 0, len, decrypted, 0);

        return Arrays.equals(Arrays.copyOfRange(decrypted, len - 16, len), context.getClientRandom());
    }

    private byte[] getMD5Output(TlsContext tlsContext) {
        MD5Digest md5 = new MD5Digest();
        byte[] clearKey = new byte[SSL2ClientMasterKeyPreparator.EXPORT_RC4_NUM_OF_CLEAR_KEY_BYTES];
        md5Update(md5, clearKey);
        md5Update(md5, tlsContext.getPreMasterSecret());
        md5.update((byte) '0');
        md5Update(md5, tlsContext.getClientRandom());
        md5Update(md5, tlsContext.getServerRandom());
        byte[] md5Output = new byte[md5.getDigestSize()];
        md5.doFinal(md5Output, 0);
        return md5Output;
    }

}
