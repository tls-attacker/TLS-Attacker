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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
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
 * Remove cipher from cipher suite list of a buffered ClientHello message.
 *
 * <p>This allows changing a ClientHello message in transit, i.e. in MiTM workflows that want to
 * remove proposed cipher suites.
 *
 * <p>This action assumes that the first message in the message buffer is a ClientHello.
 *
 * <p>Note: This action is currently needed because fresh (ClientHello) messages cannot be fully
 * prepared from context, but partially rely on config values. Thus preventing us to modify values
 * in context and re-creating a CH for forwarding.
 */
@XmlRootElement(name = "RemBufferedChCiphers")
public class RemBufferedChCiphersAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElements(value = {@XmlElement(type = CipherSuite.class, name = "suite")})
    private List<CipherSuite> removeCiphers = new ArrayList<>();

    public RemBufferedChCiphersAction() {}

    public RemBufferedChCiphersAction(String alias) {
        this.connectionAlias = alias;
    }

    public RemBufferedChCiphersAction(List<CipherSuite> removeCiphers) {
        this.removeCiphers = removeCiphers;
    }

    public RemBufferedChCiphersAction(CipherSuite... removeCiphers) {
        this(new ArrayList<>(Arrays.asList(removeCiphers)));
    }

    public RemBufferedChCiphersAction(String alias, List<CipherSuite> removeCiphers) {
        super(alias);
        this.removeCiphers = removeCiphers;
    }

    public RemBufferedChCiphersAction(String alias, CipherSuite... removeCiphers) {
        super(alias);
        this.removeCiphers = new ArrayList<>(Arrays.asList(removeCiphers));
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext ctx = state.getTlsContext(connectionAlias);

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        ClientHelloMessage ch = (ClientHelloMessage) ctx.getMessageBuffer().getFirst();

        removeCiphers(ch);
        setExecuted(true);
    }

    private void removeCiphers(ClientHelloMessage ch) throws ActionExecutionException {
        String msgName = ch.toCompactString();

        if (ch.getCipherSuites() == null) {
            LOGGER.debug("No cipher suites found in {}. Nothing to do.", msgName);
            return;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Original cipher suites in {}:\n{}", msgName, summarizeCiphers(ch));
        }

        byte[] ciphersBytes = ch.getCipherSuites().getValue();
        List<CipherSuite> ciphers = CipherSuite.getCipherSuites(ciphersBytes);
        int origCiphersLength = ciphersBytes.length;
        SilentByteArrayOutputStream newCiphersBytes = new SilentByteArrayOutputStream();
        for (CipherSuite cs : ciphers) {
            LOGGER.debug("cipher.name, cipher.val = {}, {}", cs.name(), cs.getValue());
            if (!removeCiphers.contains(cs)) {
                newCiphersBytes.write(cs.getByteValue());
            }
        }
        ch.setCipherSuites(newCiphersBytes.toByteArray());
        int newSuitesLength = ch.getCipherSuites().getValue().length;
        int diffSuitesLength = origCiphersLength - newSuitesLength;
        int newMsgLength = ch.getLength().getValue() - diffSuitesLength;
        ch.setLength(newMsgLength);
        ch.setCipherSuiteLength(newSuitesLength);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Modified cipher suites in {}:\n{}", msgName, summarizeCiphers(ch));
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

    public List<CipherSuite> getRemoveCiphers() {
        return removeCiphers;
    }

    public void setRemoveCiphers(List<CipherSuite> removeCiphers) {
        this.removeCiphers = removeCiphers;
    }

    public void setRemoveCiphers(CipherSuite... removeCiphers) {
        this.removeCiphers = new ArrayList<>(Arrays.asList(removeCiphers));
    }

    /**
     * Summarize the extension data for pretty printing.
     *
     * @return a summary of the extension information contained in the CH message
     */
    public String summarizeCiphers(ClientHelloMessage ch) {
        StringBuilder sb = new StringBuilder();
        sb.append("cipher suite bytes length: ").append(ch.getCipherSuites().getValue().length);
        sb.append("\ncipher suite bytes:");
        sb.append(DataConverter.bytesToRawHexString(ch.getCipherSuites().getValue()));
        sb.append("\nreadable cipher suite list:\n");
        for (CipherSuite cs : CipherSuite.getCipherSuites(ch.getCipherSuites().getValue())) {
            sb.append(cs.name()).append("\n");
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
        if (removeCiphers == null || removeCiphers.isEmpty()) {
            removeCiphers = null;
        }
    }

    private void initEmptyLists() {
        if (removeCiphers == null) {
            removeCiphers = new ArrayList<>();
        }
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 19 * hash + Objects.hashCode(this.removeCiphers);
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
        final RemBufferedChCiphersAction other = (RemBufferedChCiphersAction) obj;
        if (!Objects.equals(this.removeCiphers, other.removeCiphers)) {
            return false;
        }
        return super.equals(obj);
    }
}
