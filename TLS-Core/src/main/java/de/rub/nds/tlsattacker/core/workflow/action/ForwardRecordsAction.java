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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.ReceiveTillLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ForwardRecordsAction extends TlsAction implements ReceivingAction, SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "from")
    protected String receiveFromAlias = null;

    @XmlElement(name = "to")
    protected String forwardToAlias = null;

    @XmlTransient private Boolean executedAsPlanned = null;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = Record.class, name = "Record"))
    protected List<Record> receivedRecords;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(@XmlElement(type = Record.class, name = "Record"))
    protected List<Record> sendRecords;

    public ForwardRecordsAction() {}

    public ForwardRecordsAction(String receiveFromAlias, String forwardToAlias) {
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
    }

    public void setReceiveFromAlias(String receiveFromAlias) {
        this.receiveFromAlias = receiveFromAlias;
    }

    public void setForwardToAlias(String forwardToAlias) {
        this.forwardToAlias = forwardToAlias;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        assertAliasesSetProperly();

        TlsContext receiveFromCtx = state.getTlsContext(receiveFromAlias);
        TlsContext forwardToCtx = state.getTlsContext(forwardToAlias);

        receiveRecords(receiveFromCtx);
        forwardRecords(forwardToCtx);
    }

    private void receiveRecords(TlsContext receiveFromCtx) {
        LayerStack receivingLayerStack = receiveFromCtx.getLayerStack();
        LOGGER.debug("Receiving records...");
        LayerStackProcessingResult receiveResult =
                receivingLayerStack.receiveData(
                        buildLayerConfiguration(receivingLayerStack, false));
        receivedRecords =
                receiveResult.getResultForLayer(ImplementedLayers.RECORD).getUsedContainers();
        LOGGER.info("Records received (" + receiveFromAlias + "): " + receivedRecords.size());
        executedAsPlanned = true;
    }

    private List<LayerConfiguration> buildLayerConfiguration(
            LayerStack layerStack, boolean sending) {
        RecordLayer recordLayer = (RecordLayer) layerStack.getLayer(RecordLayer.class);
        List<ProtocolLayer> layerList = layerStack.getLayerList();
        List<LayerConfiguration> configList = new LinkedList<>();
        layerList.forEach(
                layer -> {
                    if (layer != recordLayer) {
                        configList.add(null);
                    } else {
                        if (sending) {
                            configList.add(
                                    new SpecificSendLayerConfiguration(
                                            ImplementedLayers.RECORD, receivedRecords));
                        } else {
                            configList.add(
                                    new ReceiveTillLayerConfiguration(
                                            ImplementedLayers.RECORD, new Record()));
                        }
                    }
                });
        return configList;
    }

    private void forwardRecords(TlsContext forwardToCtx) {
        LOGGER.info("Forwarding " + receivedRecords.size() + " records to " + forwardToAlias);
        try {
            LayerStack sendingLayerStack = forwardToCtx.getLayerStack();
            sendingLayerStack.sendData(buildLayerConfiguration(sendingLayerStack, true));
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            executedAsPlanned = false;
            setExecuted(false);
        }
    }

    public String getReceiveFromAlias() {
        return receiveFromAlias;
    }

    public String getForwardToAlias() {
        return forwardToAlias;
    }

    @Override
    public boolean executedAsPlanned() {
        return executedAsPlanned;
    }

    @Override
    public void reset() {
        receivedRecords = null;
        sendRecords = null;
        executedAsPlanned = false;
        setExecuted(null);
    }

    @Override
    public List<Record> getReceivedRecords() {
        return receivedRecords;
    }

    @Override
    public List<Record> getSendRecords() {
        return sendRecords;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 89 * hash + Objects.hashCode(this.receiveFromAlias);
        hash = 89 * hash + Objects.hashCode(this.forwardToAlias);
        hash = 89 * hash + Objects.hashCode(this.executedAsPlanned);
        hash = 89 * hash + Objects.hashCode(this.receivedRecords);
        hash = 89 * hash + Objects.hashCode(this.sendRecords);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ForwardRecordsAction other = (ForwardRecordsAction) obj;
        if (!Objects.equals(this.receiveFromAlias, other.receiveFromAlias)) {
            return false;
        }
        if (!Objects.equals(this.forwardToAlias, other.forwardToAlias)) {
            return false;
        }
        if (!Objects.equals(this.executedAsPlanned, other.executedAsPlanned)) {
            return false;
        }
        if (!Objects.equals(this.receivedRecords, other.receivedRecords)) {
            return false;
        }
        return Objects.equals(this.sendRecords, other.sendRecords);
    }

    @Override
    public Set<String> getAllAliases() {
        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(forwardToAlias);
        aliases.add(receiveFromAlias);
        return aliases;
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((receiveFromAlias == null) || (receiveFromAlias.isEmpty())) {
            throw new WorkflowExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty receive alias (if using XML: add <from/>)");
        }
        if ((forwardToAlias == null) || (forwardToAlias.isEmpty())) {
            throw new WorkflowExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty forward alis (if using XML: add <to/>)");
        }
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        // ForwardMessages should not interfere with messages above TLS
        return new LinkedList<>();
    }
}
