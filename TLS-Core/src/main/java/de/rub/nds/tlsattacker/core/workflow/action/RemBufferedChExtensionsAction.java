/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Remove extensions from extension list of a buffered ClientHello message.
 *
 * <p>This allows changing a ClientHello message in transit, i.e. in MiTM workflows that want to
 * remove proposed extensions.
 *
 * <p>This action assumes that the first message in the message buffer is a ClientHello.
 *
 * <p>Note: This action is currently needed because fresh (ClientHello) messages cannot be fully
 * prepared from context, but partially rely on config values. Thus preventing us to modify values
 * in context and re-creating a CH for forwarding.
 */
@XmlRootElement(name = "RemBufferedChExtensions")
public class RemBufferedChExtensionsAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElements(value = {@XmlElement(type = ExtensionType.class, name = "type")})
    private List<ExtensionType> removeExtensions = new ArrayList<>();

    public RemBufferedChExtensionsAction() {}

    public RemBufferedChExtensionsAction(String alias) {
        this.connectionAlias = alias;
    }

    public RemBufferedChExtensionsAction(List<ExtensionType> removeExtensions) {
        this.removeExtensions = removeExtensions;
    }

    public RemBufferedChExtensionsAction(ExtensionType... removeExtensions) {
        this(new ArrayList<>(Arrays.asList(removeExtensions)));
    }

    public RemBufferedChExtensionsAction(String alias, List<ExtensionType> removeExtensions) {
        super(alias);
        this.removeExtensions = removeExtensions;
    }

    public RemBufferedChExtensionsAction(String alias, ExtensionType... removeExtensions) {
        super(alias);
        this.removeExtensions = new ArrayList<>(Arrays.asList(removeExtensions));
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext ctx = state.getTlsContext(connectionAlias);
        ClientHelloMessage ch = (ClientHelloMessage) ctx.getMessageBuffer().getFirst();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        removeExtensions(ctx, ch);
        setExecuted(true);
    }

    private void removeExtensions(TlsContext ctx, ClientHelloMessage ch)
            throws ActionExecutionException {

        if (ch.getExtensions() == null) {
            return;
        }

        List<ExtensionMessage> extensions = ch.getExtensions();
        List<ExtensionMessage> markedForRemoval = new ArrayList<>();
        SilentByteArrayOutputStream newExtensionBytes = new SilentByteArrayOutputStream();
        String msgName = ch.toCompactString();

        int msgLength = ch.getLength().getValue();
        int origExtLength = ch.getExtensionBytes().getValue().length;

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Original extensions in {}:\n{}", msgName, summarizeExtensions(ch));
        }

        ExtensionType type;
        for (ExtensionMessage ext : extensions) {
            type = ext.getExtensionTypeConstant();
            if (removeExtensions.contains(type)) {
                LOGGER.debug("Removing {} extensions from {}", type, msgName);
                markedForRemoval.add(ext);
            } else {
                newExtensionBytes.write(ext.getExtensionBytes().getValue());
            }
        }
        ch.setExtensionBytes(newExtensionBytes.toByteArray());
        extensions.removeAll(markedForRemoval);
        int newExtLength = ch.getExtensionBytes().getValue().length;
        int diffExtLength = origExtLength - newExtLength;
        ch.setLength(msgLength - diffExtLength);
        ch.setExtensionsLength(newExtLength);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Modified extensions in {}:\n{}", msgName, summarizeExtensions(ch));
        }
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    public List<ExtensionType> getRemoveExtensions() {
        return removeExtensions;
    }

    public void setRemoveExtensions(List<ExtensionType> removeExtensions) {
        this.removeExtensions = removeExtensions;
    }

    public void setRemoveExtensions(ExtensionType... removeExtensions) {
        this.removeExtensions = new ArrayList<>(Arrays.asList(removeExtensions));
    }

    /**
     * Summarize the extension data for pretty printing.
     *
     * @return a summary of the extension information contained in the CH message
     */
    public String summarizeExtensions(ClientHelloMessage ch) {
        StringBuilder sb = new StringBuilder();
        sb.append("message length: ").append(ch.getLength().getValue());
        sb.append("\nextension bytes length: ").append(ch.getExtensionBytes().getValue().length);
        sb.append("\nextension bytes:");
        sb.append(DataConverter.bytesToRawHexString(ch.getExtensionBytes().getValue()));
        sb.append("\nreadable extension list:\n");
        for (ExtensionMessage ext : ch.getExtensions()) {
            sb.append(ext.getExtensionTypeConstant());
            sb.append(" (").append(ext.getExtensionBytes().toString()).append(")\n");
        }
        return sb.toString();
    }

    @Override
    public void normalize() {
        super.normalize();
        initEmptyLists();
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        super.normalize(defaultAction);
        initEmptyLists();
    }

    @Override
    public void filter() {
        super.filter();
        stripEmptyLists();
    }

    @Override
    public void filter(TlsAction defaultAction) {
        super.filter(defaultAction);
        stripEmptyLists();
    }

    private void stripEmptyLists() {
        if (removeExtensions == null || removeExtensions.isEmpty()) {
            removeExtensions = null;
        }
    }

    private void initEmptyLists() {
        if (removeExtensions == null) {
            removeExtensions = new ArrayList<>();
        }
        if (removeExtensions == null) {
            removeExtensions = new ArrayList<>();
        }
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 19 * hash + Objects.hashCode(this.removeExtensions);
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
        final RemBufferedChExtensionsAction other = (RemBufferedChExtensionsAction) obj;
        if (!Objects.equals(this.removeExtensions, other.removeExtensions)) {
            return false;
        }
        return super.equals(obj);
    }
}
