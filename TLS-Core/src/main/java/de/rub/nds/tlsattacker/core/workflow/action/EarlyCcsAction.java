/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This Action is used by the EarlyCcs Attack. It sends a ClientKeyExchange message and adjusts the
 * cryptographic material accordingly.
 */
public class EarlyCcsAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Boolean targetOpenssl100;

    private boolean executedAsPlanned = false;

    /**
     * Constructor for the Action. If the target is Openssl 1.0.0 the boolean value should be set to
     * true
     *
     * @param targetsOpenssl100 If the target is an openssl 1.0.0 server
     */
    public EarlyCcsAction(Boolean targetsOpenssl100) {
        this.targetOpenssl100 = targetsOpenssl100;
    }

    /**
     * Sends a ClientKeyExchange message depending on the currently selected cipher suite. Depending
     * on the target version cryptographic material is adjusted.
     *
     * @param state the State in which the action should be executed in
     */
    @Override
    public void execute(State state) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(state.getConfig());
        ClientKeyExchangeMessage message =
                factory.createClientKeyExchangeMessage(
                        AlgorithmResolver.getKeyExchangeAlgorithm(
                                state.getTlsContext().getChooser().getSelectedCipherSuite()));
        if (message == null) {
            // the factory will fail to provide a CKE message in some cases
            // e.g for TLS_CECPQ1 cipher suites
            message = new RSAClientKeyExchangeMessage();
        }
        if (!targetOpenssl100) {
            message.setIncludeInDigest(Modifiable.explicit(false));
        }
        message.setAdjustContext(Modifiable.explicit(false));
        ClientKeyExchangeHandler handler =
                (ClientKeyExchangeHandler) message.getHandler(state.getTlsContext());
        message.getPreparator(state.getTlsContext()).prepare();
        if (targetOpenssl100) {
            handler.adjustPremasterSecret(message);
            handler.adjustMasterSecret(message);
        }
        byte[] serialized = message.getSerializer(state.getTlsContext()).serialize();
        handler.adjustContextAfterSerialize(message);
        try {
            state.getTlsContext()
                    .getRecordLayer()
                    .sendData(new RecordLayerHint(ProtocolMessageType.HANDSHAKE), serialized);
            executedAsPlanned = true;
        } catch (IOException e) {
            LOGGER.debug("Could not write Data to stream", e);
            executedAsPlanned = false;
        }
        setExecuted(true);
    }

    /** Rests the executed state of the action */
    @Override
    public void reset() {
        setExecuted(false);
        executedAsPlanned = false;
    }

    @Override
    public boolean executedAsPlanned() {
        return executedAsPlanned;
    }
}
