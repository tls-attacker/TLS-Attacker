/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.core.connection.Aliasable;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.ContextHandlingException;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Manage TLS contexts.
 *
 */
public class ContextContainer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Set<String> knownAliases = new HashSet<>();

    private final Map<String, TlsContext> tlsContexts = new HashMap<>();

    /**
     * An inbound TLS context is a context bound to an incoming connection. I.e.
     * it represents a connection that we accepted from a connecting client.
     */
    private final List<TlsContext> inboundTlsContexts = new ArrayList<>();

    /**
     * An outbound TLS context is a context bound to an outgoing connection.
     * I.e. it represents a connection established by us to a remote server.
     */
    private final List<TlsContext> outboundTlsContexts = new ArrayList<>();

    /**
     * Get the only defined TLS context.
     * <p>
     * </p>
     * Convenience method, useful when working with a single context only.
     *
     * @return the only known TLS context
     * @throws ConfigurationException
     *             if there is more than one TLS context in the container
     *
     */
    public TlsContext getTlsContext() {
        if (tlsContexts.isEmpty()) {
            throw new ConfigurationException("No context defined.");
        }
        if (tlsContexts.size() > 1) {
            throw new ConfigurationException("getTlsContext requires an alias if multiple contexts are defined");
        }
        return tlsContexts.entrySet().iterator().next().getValue();
    }

    /**
     * Get TLS context with the given alias.
     *
     * @param alias
     * @return the context with the given connection end alias
     * @throws ConfigurationException
     *             if there is no TLS context with the given alias
     *
     */
    public TlsContext getTlsContext(String alias) {
        TlsContext ctx = tlsContexts.get(alias);
        if (ctx == null) {
            throw new ConfigurationException("No context defined with alias '" + alias + "'.");
        }
        return ctx;
    }

    public void addTlsContext(TlsContext context) {
        AliasedConnection con = context.getConnection();
        String alias = con.getAlias();
        if (alias == null) {
            throw new ContextHandlingException("Connection end alias not set (null). Can't add the TLS context.");
        }
        if (containsAlias(alias)) {
            throw new ConfigurationException("Connection end alias already in use: " + alias);
        }

        tlsContexts.put(alias, context);
        knownAliases.add(alias);

        if (con.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
            LOGGER.debug("Adding context " + alias + " to inboundTlsContexts");
            inboundTlsContexts.add(context);
        } else {
            LOGGER.debug("Adding context " + alias + " to outboundTlsContexts");
            outboundTlsContexts.add(context);
        }
    }

    public List<TlsContext> getAllContexts() {
        return new ArrayList<>(tlsContexts.values());
    }

    public List<TlsContext> getInboundTlsContexts() {
        return inboundTlsContexts;
    }

    public List<TlsContext> getOutboundTlsContexts() {
        return outboundTlsContexts;
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
        return tlsContexts.isEmpty();
    }

    public void clear() {
        tlsContexts.clear();
        knownAliases.clear();
        inboundTlsContexts.clear();
        outboundTlsContexts.clear();
    }

    public void removeTlsContext(String alias) {
        if (containsAlias(alias)) {
            TlsContext removeMe = tlsContexts.get(alias);
            inboundTlsContexts.remove(removeMe);
            outboundTlsContexts.remove(removeMe);
            tlsContexts.remove(alias);
            knownAliases.remove(alias);
        } else {
            LOGGER.debug("No context with alias " + alias + " found, nothing to remove");
        }
    }

    /**
     * Replace existing TlsContext with new TlsContext.
     * <p>
     * </p>
     * The TlsContext can only be replaced if the connection of both the new and
     * the old TlsContext equal.
     *
     * @param newTlsContext
     *            the new TlsContext, not null
     * @throws ConfigurationException
     *             if the connections of new and old TlsContext differ
     */
    public void replaceTlsContext(TlsContext newTlsContext) {
        String alias = newTlsContext.getConnection().getAlias();
        if (!containsAlias(alias)) {
            throw new ConfigurationException("No TlsContext to replace for alias " + alias);
        }
        TlsContext replaceMe = tlsContexts.get(alias);
        if (!replaceMe.getConnection().equals(newTlsContext.getConnection())) {
            throw new ContextHandlingException("Cannot replace TlsContext because the new TlsContext"
                    + " defines another connection.");
        }
        removeTlsContext(alias);
        addTlsContext(newTlsContext);
    }
}
