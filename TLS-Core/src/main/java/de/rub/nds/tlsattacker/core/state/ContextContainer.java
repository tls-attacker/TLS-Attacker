/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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

/**
 * Manage TLS contexts.
 *
 */
public class ContextContainer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Set<String> knownAliases = new HashSet<>();

    private final Map<String, Context> contexts = new HashMap<>();

    /**
     * An inbound context is a context bound to an incoming connection. I.e. it represents a connection that we accepted
     * from a connecting client.
     */
    private final List<Context> inboundContexts = new ArrayList<>();

    /**
     * An outbound context is a context bound to an outgoing connection. I.e. it represents a connection established by
     * us to a remote server.
     */
    private final List<Context> outboundContexts = new ArrayList<>();

    /**
     * Get the only defined context.
     * <p>
     * </p>
     * Convenience method, useful when working with a single context only.
     *
     * @return                        the only known context
     * @throws ConfigurationException
     *                                if there is more than one context in the container
     *
     */
    public Context getContext() {
        if (contexts.isEmpty()) {
            throw new ConfigurationException("No context defined.");
        }
        if (contexts.size() > 1) {
            throw new ConfigurationException("getContext requires an alias if multiple contexts are defined");
        }
        return contexts.entrySet().iterator().next().getValue();
    }

    /**
     * Get context with the given alias.
     *
     * @param  alias
     * @return                        the context with the given connection end alias
     * @throws ConfigurationException
     *                                if there is no TLS context with the given alias
     *
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
            throw new ContextHandlingException("Connection end alias not set (null). Can't add the TLS context.");
        }
        if (containsAlias(alias)) {
            throw new ConfigurationException("Connection end alias already in use: " + alias);
        }

        contexts.put(alias, context);
        knownAliases.add(alias);

        if (con.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
            LOGGER.debug("Adding context " + alias + " to inboundTlsContexts");
            inboundContexts.add(context);
        } else {
            LOGGER.debug("Adding context " + alias + " to outboundTlsContexts");
            outboundContexts.add(context);
        }
    }

    public List<Context> getAllContexts() {
        return new ArrayList<>(contexts.values());
    }

    public List<Context> getInboundTlsContexts() {
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

    public void removeTlsContext(String alias) {
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
     * Replace existing TlsContext with new TlsContext.
     * <p>
     * </p>
     * The TlsContext can only be replaced if the connection of both the new and the old TlsContext equal.
     *
     * @param  newTlsContext
     *                                the new TlsContext, not null
     * @throws ConfigurationException
     *                                if the connections of new and old TlsContext differ
     */
    public void replaceTlsContext(Context newTlsContext) {
        String alias = newTlsContext.getConnection().getAlias();
        if (!containsAlias(alias)) {
            throw new ConfigurationException("No TlsContext to replace for alias " + alias);
        }
        Context replaceMe = contexts.get(alias);
        if (!replaceMe.getConnection().equals(newTlsContext.getConnection())) {
            throw new ContextHandlingException(
                "Cannot replace TlsContext because the new TlsContext" + " defines another connection.");
        }
        removeTlsContext(alias);
        addContext(newTlsContext);
    }
}
