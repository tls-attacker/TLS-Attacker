/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.attacks.config.DrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import static de.rub.nds.tlsattacker.attacks.impl.Attacker.LOGGER;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ClientMasterKeyPreparator;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.Arrays;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

public class DrownAttacker extends Attacker<DrownCommandConfig> {

    public DrownAttacker(DrownCommandConfig config) {
        super(config);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public Boolean isVulnerable() {
        DrownVulnerabilityType type = getDrownVulnerabilityType();
        switch (type) {
            case FULL:
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Server is vulnerable to the full DROWN attack");
                return true;
            case NONE:
                return false;
            case SSL2:
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Server is vulnerable to DROWN since it supports SSL2");
                return true;
            case UNKNOWN:
                LOGGER.warn("Could not execute Workflow - something went wrong. Check the Debug output to be certain");
                return null;
        }
        return null;
    }

    public DrownVulnerabilityType getDrownVulnerabilityType() {
        Config tlsConfig = config.createConfig();
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
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SSL2_SERVER_HELLO, trace)) {
            // The Server is definetly vulnerable
            SSL2ServerVerifyMessage message = (SSL2ServerVerifyMessage) WorkflowTraceUtil.getFirstReceivedMessage(
                    HandshakeMessageType.SSL2_SERVER_VERIFY, trace);
            if (message != null && checkAdvancedDrown(message, state.getTlsContext())) {
                return DrownVulnerabilityType.FULL;
            }
            return DrownVulnerabilityType.SSL2;
        } else {
            return DrownVulnerabilityType.NONE;
        }
    }

    private boolean checkAdvancedDrown(SSL2ServerVerifyMessage message, TlsContext context) {
        byte[] md5Output = getMD5Output(context);

        RC4Engine rc4 = new RC4Engine();
        rc4.init(false, new KeyParameter(md5Output));
        byte[] encrypted = message.getEncryptedPart().getValue();
        int len = encrypted.length;
        byte[] decrypted = new byte[len];
        rc4.processBytes(encrypted, 0, len, decrypted, 0);

        if (Arrays.equals(Arrays.copyOfRange(decrypted, len - 16, len), context.getClientRandom())) {
            return true;
        } else {
            return false;
        }
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

    private static void md5Update(MD5Digest md5, byte[] bytes) {
        md5.update(bytes, 0, bytes.length);
    }
}
