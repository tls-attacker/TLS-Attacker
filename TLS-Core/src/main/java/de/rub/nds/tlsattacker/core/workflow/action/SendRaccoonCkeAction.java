/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class SendRaccoonCkeAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean withNullByte = true;

    private BigInteger initialSecret = new BigInteger("" + 5000);

    public SendRaccoonCkeAction() {
        super();
    }

    public SendRaccoonCkeAction(boolean withNullByte, BigInteger initialSecret) {
        super();
        this.withNullByte = withNullByte;
        this.initialSecret = initialSecret;
    }

    public SendRaccoonCkeAction(String connectionAlias) {
        super(connectionAlias);
    }

    public BigInteger getInitialSecret() {
        return initialSecret;
    }

    public void setInitialSecret(BigInteger initialSecret) {
        this.initialSecret = initialSecret;
    }

    public boolean isWithNullByte() {
        return withNullByte;
    }

    public void setWithNullByte(boolean withNullByte) {
        this.withNullByte = withNullByte;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(connectionAlias).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        messages = new LinkedList<>();
        messages.add(generateRaccoonDhClientKeyExchangeMessage(state, withNullByte));
        String sending = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info(
                    "Sending Raccoon Cke message "
                            + (withNullByte ? "(withNullByte)" : "(withoutNullByte)")
                            + ": "
                            + sending);
        } else {
            LOGGER.info(
                    "Sending Raccoon Cke message "
                            + (withNullByte ? "(withNullByte)" : "(withoutNullByte)")
                            + ": ("
                            + connectionAlias
                            + "): "
                            + sending);
        }

        try {
            send(tlsContext, messages, fragments, records, httpMessages);
            setExecuted(true);
        } catch (IOException e) {
            tlsContext.setReceivedTransportHandlerException(true);
            LOGGER.debug(e);
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
        }
    }

    private DHClientKeyExchangeMessage generateRaccoonDhClientKeyExchangeMessage(
            State state, boolean withNullByte) {

        DHClientKeyExchangeMessage cke = new DHClientKeyExchangeMessage();
        Chooser chooser = state.getContext().getChooser();
        byte[] clientPublicKey =
                getClientPublicKey(
                        chooser.getServerDhGenerator(),
                        chooser.getServerDhModulus(),
                        chooser.getServerDhPublicKey(),
                        initialSecret,
                        withNullByte);
        cke.setPublicKey(Modifiable.explicit(clientPublicKey));
        return cke;
    }

    private byte[] getClientPublicKey(
            BigInteger g,
            BigInteger m,
            BigInteger serverPublicKey,
            BigInteger initialClientDhSecret,
            boolean withNullByte) {
        int length = ArrayConverter.bigIntegerToByteArray(m).length;
        byte[] pms =
                ArrayConverter.bigIntegerToNullPaddedByteArray(
                        serverPublicKey.modPow(initialClientDhSecret, m), length);

        if (((withNullByte && pms[0] == 0) && pms[1] != 0) || (!withNullByte && pms[0] != 0)) {
            BigInteger clientPublicKey = g.modPow(initialClientDhSecret, m);
            byte[] cke = ArrayConverter.bigIntegerToByteArray(clientPublicKey);
            if (cke.length == length) {
                return cke;
            }
        }
        initialClientDhSecret = initialClientDhSecret.add(new BigInteger("1"));
        return getClientPublicKey(g, m, serverPublicKey, initialClientDhSecret, withNullByte);
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Send Dynamic Client Key Exchange Action:\n");
        } else {
            sb = new StringBuilder("Send Dynamic Client Key Exchange Action: (not executed)\n");
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
    public void setRecords(List<Record> records) {
        this.records = records;
    }

    @Override
    public void setFragments(List<DtlsHandshakeMessageFragment> fragments) {
        this.fragments = fragments;
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
            for (Record record : getRecords()) {
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
    public List<Record> getSendRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        return fragments;
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
}
