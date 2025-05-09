/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.integration.handshakes;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag(TestCategories.INTEGRATION_TEST)
public class ClientBrainpoolHanshakeIT extends AbstractHandshakeIT {

    public ClientBrainpoolHanshakeIT() {
        // run OpenSSL with dummy HTTP server to get a reply for app data
        super(
                TlsImplementationType.OPENSSL,
                ConnectionRole.SERVER,
                "3.4.0",
                "-early_data -tls1_3 -curves brainpoolP256r1tls13");
    }

    @Override
    protected boolean[] getCryptoExtensionsValues() {
        return new boolean[] {true};
    }

    @Override
    protected WorkflowTraceType[] getWorkflowTraceTypesToTest() {
        return new WorkflowTraceType[] {
            WorkflowTraceType.HANDSHAKE,
        };
    }

    @Override
    protected CipherSuite[] getCipherSuitesToTest() {
        return new CipherSuite[] {CipherSuite.TLS_CHACHA20_POLY1305_SHA256};
    }

    @Override
    protected ProtocolVersion[] getProtocolVersionsToTest() {
        return new ProtocolVersion[] {ProtocolVersion.TLS13};
    }

    @Override
    protected NamedGroup[] getNamedGroupsToTest() {
        return new NamedGroup[] {NamedGroup.BRAINPOOLP256R1TLS13};
    }

    @Test
    public void testHelloRetryFlow() throws InterruptedException {
        Config tlsConfig = new Config();
        prepareConfig(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.BRAINPOOLP256R1TLS13,
                tlsConfig,
                WorkflowTraceType.HANDSHAKE,
                false,
                false,
                ProtocolVersion.TLS13);

        State state = new State(tlsConfig);
        tlsConfig.setDefaultClientNamedGroups(getNamedGroupsToTest());
        tlsConfig.setDefaultClientKeyShareNamedGroups(getNamedGroupsToTest());
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        setCallbacks(executor);
        WorkflowTrace workflowTrace = state.getWorkflowTrace();
        ClientHelloMessage initialHello = new ClientHelloMessage(tlsConfig);
        KeyShareExtensionMessage keyShareExtension =
                initialHello.getExtension(KeyShareExtensionMessage.class);
        keyShareExtension.setKeyShareListBytes(Modifiable.explicit(new byte[0]));

        workflowTrace.addTlsAction(0, new SendAction("client", initialHello));
        ChangeCipherSpecMessage optionalCCS = new ChangeCipherSpecMessage();
        optionalCCS.setRequired(false);
        workflowTrace.addTlsAction(
                1, new ReceiveAction("client", new ServerHelloMessage(), optionalCCS));

        executeTest(
                tlsConfig,
                executor,
                state,
                ProtocolVersion.TLS13,
                NamedGroup.BRAINPOOLP256R1TLS13,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                WorkflowTraceType.HANDSHAKE,
                false,
                false);
    }
}
