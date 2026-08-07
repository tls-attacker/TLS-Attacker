/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.StarttlsNotSupportedException;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Asserts that a capability-discovery reply advertised the upgrade the workflow is about to
 * request.
 */
@XmlRootElement(name = "AssertStartTlsCapabilityAdvertised")
public class AssertStartTlsCapabilityAdvertisedAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String capability;

    private Boolean advertised;

    @SuppressWarnings("unused")
    AssertStartTlsCapabilityAdvertisedAction() {}

    public AssertStartTlsCapabilityAdvertisedAction(String capability) {
        this.capability = capability;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        String discoveryReply = findDiscoveryReply(state);
        if (discoveryReply == null) {
            throw new ActionExecutionException(
                    "No preceding text reply to read the capability list from. This action must "
                            + "follow the action that receives the discovery reply.");
        }

        advertised = containsCapability(discoveryReply);
        setExecuted(true);
        if (!advertised) {
            throw new StarttlsNotSupportedException(
                    "Capability \""
                            + capability
                            + "\" is not advertised in the discovery reply, not attempting the "
                            + "upgrade.");
        }
        LOGGER.debug("Capability \"{}\" is advertised", capability);
    }

    /** Returns the text received by the closest preceding text-receiving action. */
    private String findDiscoveryReply(State state) {
        List<TlsAction> actions = state.getWorkflowTrace().getTlsActions();
        for (int i = actions.indexOf(this) - 1; i >= 0; i--) {
            if (actions.get(i) instanceof ReceiveRegexTextAction) {
                return ((ReceiveRegexTextAction) actions.get(i)).getReceivedText();
            }
        }
        return null;
    }

    /**
     * Capability lists are line-based and case-insensitive in every protocol that uses them, and
     * the token is a whole entry rather than a substring: matching "STARTTLS" must not be satisfied
     * by an unrelated "NOSTARTTLS" feature line.
     */
    private boolean containsCapability(String discoveryReply) {
        return Pattern.compile(
                        "(?<![A-Z0-9-])" + Pattern.quote(capability) + "(?![A-Z0-9-])",
                        Pattern.CASE_INSENSITIVE)
                .matcher(discoveryReply)
                .find();
    }

    public String getCapability() {
        return capability;
    }

    public void setCapability(String capability) {
        this.capability = capability;
    }

    public Boolean isAdvertised() {
        return advertised;
    }

    @Override
    public void reset() {
        advertised = null;
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted() && Boolean.TRUE.equals(advertised);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AssertStartTlsCapabilityAdvertisedAction that =
                (AssertStartTlsCapabilityAdvertisedAction) o;
        return Objects.equals(capability, that.capability)
                && Objects.equals(advertised, that.advertised);
    }

    @Override
    public int hashCode() {
        return Objects.hash(capability, advertised);
    }
}
