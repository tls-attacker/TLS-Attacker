/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.AttackConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PoodleAttacker extends Attacker {

    public PoodleAttacker(PoodleCommandConfig config) {
        super(config, true);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Boolean isVulnerable() {
        Config tlsConfig = config.createConfig();
        TlsContext context = new TlsContext(tlsConfig);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.SSL3);
        context.getConfig().setDefaultClientSupportedCiphersuites(getCbcCiphers());
        context.getConfig().setWorkflowTraceType(WorkflowTraceType.HELLO);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(context);
        executor.executeWorkflow();
        return context.getWorkflowTrace().getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO)
                .size() > 0;
    }

    private List<CipherSuite> getCbcCiphers() {
        List<CipherSuite> cbcs = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isCBC()) {
                cbcs.add(suite);
            }
        }
        return cbcs;
    }

}
