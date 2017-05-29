/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.SniTestCommandConfig;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.ServerNamePair;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends different server names in the SNI extension in the ClientHello
 * messages.
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class SniAttacker extends Attacker<SniTestCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(SniAttacker.class);

    public SniAttacker(SniTestCommandConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Boolean isVulnerable() {
        TlsConfig tlsConfig = config.createConfig();
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);
        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        List<TLSAction> actions = trace.getTLSActions();
        ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
        ServerNamePair pair = new ServerNamePair();
        pair.setServerNameConfig(config.getServerName2().getBytes());
        pair.setServerNameTypeConfig(NameType.HOST_NAME.getValue());
        sni.getServerNameList().add(pair);
        throw new UnsupportedOperationException("Work in progress");
    }

}
