/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;

/**
 * The application protocols that can be upgraded to TLS via a StartTLS handshake.
 *
 * <p>Each type carries the layer stack it needs. Protocols that negotiate the upgrade with plain
 * text actions (the lightweight approach) do not need a dedicated protocol layer and therefore use
 * the parameterless constructor, which selects the generic opportunistic stacks. Adding such a
 * protocol only requires a new constant here plus its message flow in {@code
 * WorkflowConfigurationFactory.addStartTlsActions}.
 */
public enum StarttlsType {
    NONE(null, null),
    FTP,
    IMAP,
    POP3(StackConfiguration.POP3, null),
    SMTP(StackConfiguration.SMTP, null);

    private final StackConfiguration stack;

    private final StackConfiguration ssl2Stack;

    StarttlsType() {
        this(
                StackConfiguration.GENERIC_OPPORTUNISTIC_TLS,
                StackConfiguration.GENERIC_OPPORTUNISTIC_SSL2);
    }

    StarttlsType(StackConfiguration stack, StackConfiguration ssl2Stack) {
        this.stack = stack;
        this.ssl2Stack = ssl2Stack;
    }

    /**
     * Returns the layer stack this type upgrades to, or null if the stack of the config should be
     * kept.
     *
     * @return the layer stack of this type
     */
    public StackConfiguration getStack() {
        return stack;
    }

    /**
     * Returns the layer stack this type upgrades to for a config that committed to SSL2, or null if
     * this type has no SSL2 variant.
     *
     * @return the SSL2 layer stack of this type
     */
    public StackConfiguration getSsl2Stack() {
        return ssl2Stack;
    }

    /**
     * Returns the layer stack to upgrade to, based on the stack the config currently holds.
     *
     * <p>A config that deliberately committed to SSL2 (e.g. the scanner's ssl2Only.config) must
     * keep an SSL2 layer, otherwise the SSL2 messages of the workflow have no layer to be handled
     * by. Only a config that did not choose SSL2, or a type without an SSL2 variant, gets the
     * regular stack.
     *
     * @param currentStack the layer stack currently configured
     * @return the layer stack to use, or null if the current stack should be kept
     */
    public StackConfiguration resolveStack(StackConfiguration currentStack) {
        if (currentStack == StackConfiguration.SSL2 && ssl2Stack != null) {
            return ssl2Stack;
        }
        return stack;
    }
}
