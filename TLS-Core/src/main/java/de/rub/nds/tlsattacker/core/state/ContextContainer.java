/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.core.connection.Aliasable;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.ContextHandlingException;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Manages contexts. */
public class ContextContainer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Set<String> knownAliases = new HashSet<>();

    private final Map<String, Context> contexts = new HashMap<>();

    /**
     * An inbound context is a context bound to an incoming connection. I.e. it represents a
     * connection that we accepted from a connecting client.
     */
    private final List<Context> inboundContexts = new ArrayList<>();

    /**
     * An outbound context is a context bound to an outgoing connection. I.e. it represents a
     * connection established by us to a remote server.
     */
    private final List<Context> outboundContexts = new ArrayList<>();

    /**
     * Get the only defined context.
     *
     * <p>Convenience method, useful when working with a single context only.
     *
     * @return the only known context
     * @throws ConfigurationException if there is more than one context in the container
     */
    public Context getContext() {
        if (contexts.isEmpty()) {
            throw new ConfigurationException("No context defined.");
        }
        if (contexts.size() > 1) {
            throw new ConfigurationException(
                    "getContext requires an alias if multiple contexts are defined");
        }
        return contexts.entrySet().iterator().next().getValue();
    }

    /**
     * Get context with the given alias.
     *
     * @param alias
     * @return the context with the given connection end alias
     * @throws ConfigurationException if there is no Context with the given alias
     */
    public Context getContext(String alias) {
        Context ctx = contexts.get(alias);
        if (ctx == null) {
            throw new ConfigurationException("No context defined with alias '" + alias + "'.");
        }
        return ctx;
    }

    public void addContext(Context context) {
        AliasedConnection con = context.getConnection();
        String alias = con.getAlias();
        if (alias == null) {
            throw new ContextHandlingException(
                    "Connection end alias not set (null). Can't add the Context.");
        }
        if (containsAlias(alias)) {
            throw new ConfigurationException("Connection end alias already in use: " + alias);
        }

        contexts.put(alias, context);
        knownAliases.add(alias);

        if (con.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
            LOGGER.debug("Adding context " + alias + " to inboundContexts");
            inboundContexts.add(context);
        } else {
            LOGGER.debug("Adding context " + alias + " to outboundContexts");
            outboundContexts.add(context);
        }
    }

    public List<Context> getAllContexts() {
        return new ArrayList<>(contexts.values());
    }

    public List<Context> getInboundContexts() {
        return inboundContexts;
    }

    public List<Context> getOutboundContexts() {
        return outboundContexts;
    }

    public boolean containsAlias(String alias) {
        return knownAliases.contains(alias);
    }

    public boolean containsAllAliases(Collection<? extends String> aliases) {
        return knownAliases.containsAll(aliases);
    }

    public boolean containsAllAliases(Aliasable aliasable) {
        return knownAliases.containsAll(aliasable.getAllAliases());
    }

    public boolean isEmpty() {
        return contexts.isEmpty();
    }

    public void clear() {
        contexts.clear();
        knownAliases.clear();
        inboundContexts.clear();
        outboundContexts.clear();
    }

    public void removeContext(String alias) {
        if (containsAlias(alias)) {
            Context removeMe = contexts.get(alias);
            inboundContexts.remove(removeMe);
            outboundContexts.remove(removeMe);
            contexts.remove(alias);
            knownAliases.remove(alias);
        } else {
            LOGGER.debug("No context with alias " + alias + " found, nothing to remove");
        }
    }

    /**
     * Replace existing Context with new Context.
     *
     * <p>The Context can only be replaced if the connection of both the new and the old Context
     * equal.
     *
     * @param newContext the new Context, not null
     * @throws ConfigurationException if the connections of new and old Context differ
     */
    public void replaceContext(Context newContext) {
        String alias = newContext.getConnection().getAlias();
        if (!containsAlias(alias)) {
            throw new ConfigurationException("No Context to replace for alias " + alias);
        }
        Context replaceMe = contexts.get(alias);
        if (!replaceMe.getConnection().equals(newContext.getConnection())) {
            throw new ContextHandlingException(
                    "Cannot replace Context because the new Context"
                            + " defines another connection.");
        }
        removeContext(alias);
        addContext(newContext);
    }
}
