/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ForwardRecordsAction extends TlsAction implements ReceivingAction, SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "from")
    protected String receiveFromAlias = null;
    @XmlElement(name = "to")
    protected String forwardToAlias = null;

    @XmlTransient
    private Boolean executedAsPlanned = null;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
            @XmlElement(type = BlobRecord.class, name = "BlobRecord") })
    protected List<AbstractRecord> receivedRecords;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
            @XmlElement(type = BlobRecord.class, name = "BlobRecord") })
    protected List<AbstractRecord> sendRecords;
    private ReceiveMessageHelper receiveMessageHelper;
    private SendMessageHelper sendMessageHelper;

    public ForwardRecordsAction() {
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public ForwardRecordsAction(String receiveFromAlias, String forwardToAlias) {
        this(receiveFromAlias, forwardToAlias, new ReceiveMessageHelper());
    }

    /**
     * Allow to pass a fake ReceiveMessageHelper helper for testing.
     */
    protected ForwardRecordsAction(String receiveFromAlias, String forwardToAlias,
            ReceiveMessageHelper receiveMessageHelper) {
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
        this.receiveMessageHelper = receiveMessageHelper;
        sendMessageHelper = new SendMessageHelper();
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

    void receiveRecords(TlsContext receiveFromCtx) {
        LOGGER.debug("Receiving records...");
        receivedRecords = receiveMessageHelper.receiveRecords(receiveFromCtx);
        LOGGER.info("Records received (" + receiveFromAlias + "): " + receivedRecords.size());
        executedAsPlanned = true;
    }

    private void forwardRecords(TlsContext forwardToCtx) {
        LOGGER.info("Forwarding " + receivedRecords.size() + " records to " + forwardToAlias);
        try {
            sendMessageHelper.sendRecords(receivedRecords, forwardToCtx);
            setExecuted(true);
        } catch (IOException E) {
            LOGGER.debug(E);
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
    public List<AbstractRecord> getReceivedRecords() {
        return receivedRecords;
    }

    @Override
    public List<AbstractRecord> getSendRecords() {
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
            throw new WorkflowExecutionException("Can't execute " + this.getClass().getSimpleName()
                    + " with empty receive alias (if using XML: add <from/>)");
        }
        if ((forwardToAlias == null) || (forwardToAlias.isEmpty())) {
            throw new WorkflowExecutionException("Can't execute " + this.getClass().getSimpleName()
                    + " with empty forward alis (if using XML: add <to/>)");
        }
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        throw new UnsupportedOperationException("Not supported.");
    }

}
