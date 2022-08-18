/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class SendDynamicServerKeyExchangeAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendDynamicServerKeyExchangeAction() {
        super();
    }

    public SendDynamicServerKeyExchangeAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(connectionAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        messages = new LinkedList<>();
        CipherSuite selectedCipherSuite = tlsContext.getChooser().getSelectedCipherSuite();
        ServerKeyExchangeMessage serverKeyExchangeMessage = new WorkflowConfigurationFactory(state.getConfig())
            .createServerKeyExchangeMessage(AlgorithmResolver.getKeyExchangeAlgorithm(selectedCipherSuite));
        if (serverKeyExchangeMessage != null) {
            messages.add(serverKeyExchangeMessage);

            String sending = getReadableString(messages);
            if (hasDefaultAlias()) {
                LOGGER.info("Sending Dynamic Key Exchange: " + sending);
            } else {
                LOGGER.info("Sending Dynamic Key Exchange (" + connectionAlias + "): " + sending);
            }

            try {
                MessageActionResult result = sendMessageHelper.sendMessages(messages, fragments, records, tlsContext);
                messages = new ArrayList<>(result.getMessageList());
                records = new ArrayList<>(result.getRecordList());
                if (result.getMessageFragmentList() != null) {
                    fragments = new ArrayList<>(result.getMessageFragmentList());
                }
                setExecuted(true);
            } catch (IOException e) {
                tlsContext.setReceivedTransportHandlerException(true);
                LOGGER.debug(e);
                setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
            }
        } else {
            LOGGER.info("Sending Dynamic Key Exchange: none");
            setExecuted(true);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Send Action:\n");
        } else {
            sb = new StringBuilder("Send Action: (not executed)\n");
        }
        sb.append("\tMessages:");
        if (messages != null) {
            for (ProtocolMessage message : messages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
            sb.append("\n");
        } else {
            sb.append("null (no messages set)");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if ((messages != null) && (!messages.isEmpty())) {
            sb.append(" (");
            for (ProtocolMessage message : messages) {
                sb.append(message.toCompactString());
                sb.append(",");
            }
            sb.deleteCharAt(sb.lastIndexOf(",")).append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        if (messages != null) {
            for (ProtocolMessage message : messages) {
                holders.addAll(message.getAllModifiableVariableHolders());
            }
        }
        if (getRecords() != null) {
            for (AbstractRecord record : getRecords()) {
                holders.addAll(record.getAllModifiableVariableHolders());
            }
        }
        if (getFragments() != null) {
            for (DtlsHandshakeMessageFragment fragment : getFragments()) {
                holders.addAll(fragment.getAllModifiableVariableHolders());
            }
        }
        for (ModifiableVariableHolder holder : holders) {
            List<Field> fields = holder.getAllModifiableVariableFields();
            for (Field f : fields) {
                f.setAccessible(true);

                ModifiableVariable mv = null;
                try {
                    mv = (ModifiableVariable) f.get(holder);
                } catch (IllegalArgumentException | IllegalAccessException ex) {
                    LOGGER.warn("Could not retrieve ModifiableVariables");
                    LOGGER.debug(ex);
                }
                if (mv != null) {
                    if (mv.getModification() != null || mv.isCreateRandomModification()) {
                        mv.setOriginalValue(null);
                    } else {
                        try {
                            f.set(holder, null);
                        } catch (IllegalArgumentException | IllegalAccessException ex) {
                            LOGGER.warn("Could not strip ModifiableVariable without Modification");
                        }
                    }
                }
            }
        }
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        return messages;
    }

    @Override
    public List<AbstractRecord> getSendRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        return fragments;
    }

    @Override
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.SENDING;
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
        final SendDynamicClientKeyExchangeAction other = (SendDynamicClientKeyExchangeAction) obj;
        if (!Objects.equals(this.messages, other.messages)) {
            return false;
        }
        if (!Objects.equals(this.records, other.records)) {
            return false;
        }
        if (!Objects.equals(this.fragments, other.fragments)) {
            return false;
        }
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 67 * hash + Objects.hashCode(this.messages);
        hash = 67 * hash + Objects.hashCode(this.records);
        hash = 67 * hash + Objects.hashCode(this.fragments);
        return hash;
    }

    @Override
    public List<ProtocolMessageType> getGoingToSendProtocolMessageTypes() {
        return new ArrayList<ProtocolMessageType>() {
            {
                add(ProtocolMessageType.HANDSHAKE);
            }
        };
    }

    @Override
    public List<HandshakeMessageType> getGoingToSendHandshakeMessageTypes() {
        return new ArrayList<HandshakeMessageType>() {
            {
                add(HandshakeMessageType.SERVER_KEY_EXCHANGE);
            }
        };
    }

}
