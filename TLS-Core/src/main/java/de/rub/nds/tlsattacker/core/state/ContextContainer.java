/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.socket.AliasedConnection;
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
 * Manage contexts needed for execution.
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ContextContainer {

    protected static final Logger LOGGER = LogManager.getLogger(ContextContainer.class);

    private final Set<String> knownAliases = new HashSet<>();

    private final Map<String, TlsContext> tlsContexts = new HashMap<>();

    /**
     * An inbound TLS context is a context bound to an incoming connection, i.e.
     * it represents a connection that we accepted from a connecting client.
     */
    private final List<TlsContext> inboundTlsContexts = new ArrayList<>();

    /**
     * An outbound TLS context is a context bound to an outgoing connection,
     * i.e. it represents a connection established by us to a remote server.
     */
    private final List<TlsContext> outboundTlsContexts = new ArrayList<>();

    /**
     * Use this convenience method when working with a single context only.
     *
     * @return the only context known to this container
     * @see this.getTlsContext(String)
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
     * @return the context with the given connection end alias
     * @see this.getTlsContext() convenience method for accessing single
     *      contexts
     */
    public TlsContext getTlsContext(String alias) {
        if (tlsContexts.get(alias) == null) {
            throw new ConfigurationException("No context defined with alias '" + alias + "'.");
        }
        return tlsContexts.get(alias);
    }

    public void addTlsContext(TlsContext context) {
        AliasedConnection con = context.getConnection();
        String alias = con.getAlias();
        if (alias == null) {
            throw new ConfigurationException("Connection end alias not set (null). Can't add the TLS context.");
        }
        if (tlsContexts.containsKey(alias)) {
            throw new ConfigurationException("Connection end alias already in use: " + alias);
        }

        LOGGER.info("Adding context " + alias);
        tlsContexts.put(alias, context);

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

    public boolean isValidAlias(String alias) {
        return false;
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
}
