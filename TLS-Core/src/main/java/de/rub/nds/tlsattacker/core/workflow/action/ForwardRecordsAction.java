/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@XmlRootElement(name = "ForwardRecords")
public class ForwardRecordsAction extends CommonForwardAction {

    @XmlElementWrapper @HoldsModifiableVariable @XmlElementRef
    protected List<Record> expectedRecords;

    public ForwardRecordsAction() {}

    public ForwardRecordsAction(
            String receiveFromAlias, String forwardToAlias, List<Record> expectedRecords) {
        super(receiveFromAlias, forwardToAlias);
        this.expectedRecords = expectedRecords;
    }

    public ForwardRecordsAction(
            String receiveFromAlias, String forwardToAlias, Record... expectedRecords) {
        this(receiveFromAlias, forwardToAlias, new ArrayList<>(Arrays.asList(expectedRecords)));
    }

    public List<Record> getExpectedRecords() {
        return expectedRecords;
    }

    public void setExpectedRecords(List<Record> expectedRecords) {
        this.expectedRecords = expectedRecords;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("Forward Records Action:\n");
        sb.append("Receive from alias: ").append(receiveFromAlias).append("\n");
        sb.append("\tExpected:");
        if ((expectedRecords != null)) {
            for (Record record : expectedRecords) {
                sb.append(", ");
                sb.append(record.toCompactString());
            }
        } else {
            sb.append(" (no records set)");
        }
        sb.append("\n\tActual:");
        if ((getReceivedRecords() != null) && (!getReceivedRecords().isEmpty())) {
            for (Record record : getReceivedRecords()) {
                sb.append(record.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no records set)");
        }
        sb.append("\n");
        sb.append("Forwarded to alias: ").append(forwardToAlias).append("\n");
        if (getSentRecords() != null) {
            sb.append("\t");
            for (Record record : getSentRecords()) {
                sb.append(record.toCompactString());
                sb.append(", ");
            }
            sb.append("\n");
        } else {
            sb.append("null (no records set)");
        }
        return sb.toString();
    }

    @Override
    protected List<LayerConfiguration<?>> createReceiveConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getReceiveFromAlias());
        return ActionHelperUtil.createReceiveLayerConfiguration(
                tlsContext, getActionOptions(), null, null, getExpectedRecords(), null, null, null, null);
    }

    @Override
    protected List<LayerConfiguration<?>> createSendConfiguration(
            State state, LayerStackProcessingResult receivedResult) {
        TlsContext tlsContext = state.getTlsContext(getForwardToAlias());
        List<Record> receivedRecords = getReceivedRecords();
        for (Record record : receivedRecords) {
            record.setShouldPrepare(false); // Do not recompute the messages on the message layer
        }

        return ActionHelperUtil.createSendConfiguration(
                tlsContext, null, null, getReceivedRecords(), null, null, null, null);
    }
}
