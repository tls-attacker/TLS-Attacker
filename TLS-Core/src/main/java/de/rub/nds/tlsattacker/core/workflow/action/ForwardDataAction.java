/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.GenericReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "ForwardData")
public class ForwardDataAction extends CommonForwardAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ForwardDataAction() {}

    public ForwardDataAction(String receiveFromAlias, String forwardToAlias) {
        super(receiveFromAlias, forwardToAlias);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("Forward Data Action:\n");
        sb.append("Receive from alias: ").append(receiveFromAlias).append("\n");

        sb.append("\n\tReceived:");
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
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(new GenericReceiveLayerConfiguration(ImplementedLayers.TCP));
        configurationList.add(new GenericReceiveLayerConfiguration(ImplementedLayers.UDP));
        return ActionHelperUtil.sortLayerConfigurations(
                tlsContext.getLayerStack(), false, configurationList);
    }

    @Override
    protected List<LayerConfiguration<?>> createSendConfiguration(
            State state, LayerStackProcessingResult receivedResult) {
        TlsContext tlsContext = state.getTlsContext(getForwardToAlias());
        List<Record> receivedRecords = getReceivedRecords();
        for (Record record : receivedRecords) {
            record.setShouldPrepare(false); // Do not recompute the messages on the message layer
        }
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new SpecificSendLayerConfiguration<>(ImplementedLayers.RECORD, receivedRecords));
        return ActionHelperUtil.sortLayerConfigurations(
                tlsContext.getLayerStack(), true, configurationList);
    }
}
