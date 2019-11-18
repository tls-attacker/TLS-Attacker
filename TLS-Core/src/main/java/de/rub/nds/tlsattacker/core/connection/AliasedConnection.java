/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.connection;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import javax.xml.bind.annotation.XmlType;

@XmlType(propOrder = { "alias", "ip", "port", "hostname", "proxyDataPort", "proxyDataHostname", "proxyControlPort",
        "proxyControlHostname", "timeout", "transportHandlerType" })
public abstract class AliasedConnection extends Connection implements Aliasable {

    public static final String DEFAULT_CONNECTION_ALIAS = "defaultConnection";
    public static final TransportHandlerType DEFAULT_TRANSPORT_HANDLER_TYPE = TransportHandlerType.TCP;
    public static final Integer DEFAULT_TIMEOUT = 1000;
    public static final String DEFAULT_HOSTNAME = "localhost";
    public static final String DEFAULT_IP = "127.0.0.1";
    public static final Integer DEFAULT_PORT = 443;

    protected String alias = null;

    public AliasedConnection() {
    }

    public AliasedConnection(Integer port) {
        super(port);
    }

    public AliasedConnection(Integer port, String hostname) {
        super(port, hostname);
    }

    public AliasedConnection(String alias) {
        this.alias = alias;
    }

    public AliasedConnection(String alias, Integer port) {
        super(port);
        this.alias = alias;
    }

    public AliasedConnection(String alias, Integer port, String hostname) {
        super(port, hostname);
        this.alias = alias;
    }

    public AliasedConnection(AliasedConnection other) {
        super(other);
        alias = other.alias;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((alias == null) || (alias.isEmpty())) {
            throw new ConfigurationException("Empty or null alias in " + this.getClass().getSimpleName());
        }
    }

    public abstract String toCompactString();

    @Override
    public String aliasesToString() {
        return alias;
    }

    @Override
    public String getFirstAlias() {
        return alias;
    }

    @Override
    public Set<String> getAllAliases() {
        Set<String> set = new HashSet<>();
        set.add(alias);
        return set;
    }

    @Override
    public boolean containsAlias(String alias) {
        return this.alias.equals(alias);
    }

    @Override
    public boolean containsAllAliases(Collection<String> aliases) {
        if (aliases == null || aliases.isEmpty()) {
            return false;
        }
        if (aliases.size() == 1) {
            return this.alias.equals(aliases.iterator().next());
        }
        return false;
    }

    public String getDefaultConnectionAlias() {
        return DEFAULT_CONNECTION_ALIAS;
    }

    @Override
    public abstract ConnectionEndType getLocalConnectionEndType();

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 41 * hash + Objects.hashCode(this.alias);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (!super.equals(obj)) {
            return false;
        }
        final AliasedConnection other = (AliasedConnection) obj;
        return Objects.equals(this.alias, other.alias);
    }

    public void normalize(AliasedConnection defaultCon) {
        if ((alias == null) || alias.isEmpty()) {
            alias = defaultCon.getAlias();
            if (alias == null || alias.isEmpty()) {
                alias = getDefaultConnectionAlias();
            }
        }

        if (transportHandlerType == null) {
            transportHandlerType = defaultCon.getTransportHandlerType();
            if (transportHandlerType == null) {

                transportHandlerType = DEFAULT_TRANSPORT_HANDLER_TYPE;
            }
        }
        if (timeout == null) {
            timeout = defaultCon.getTimeout();
            if (timeout == null) {
                timeout = DEFAULT_TIMEOUT;
            }
        }
        if (hostname == null || hostname.isEmpty()) {
            hostname = defaultCon.getHostname();
            if (hostname == null || hostname.isEmpty()) {
                hostname = DEFAULT_HOSTNAME;
            }
        }
        if (ip == null || ip.isEmpty()) {
            ip = defaultCon.getHostname();
            if (ip == null || ip.isEmpty()) {
                ip = DEFAULT_IP;
            }
        }
        if (port == null) {
            port = defaultCon.getPort();
            if (port == null) {
                port = DEFAULT_PORT;
            }
            if (port < 0 || port > 65535) {
                throw new ConfigurationException("Attempt to set default port "
                        + "failed. Port must be in interval [0,65535], but is " + port);
            }
        }
    }

    public void filter(AliasedConnection defaultCon) {
        if (alias.equals(defaultCon.getAlias()) || alias.equals(getDefaultConnectionAlias())) {
            alias = null;
        }
        if (transportHandlerType == defaultCon.getTransportHandlerType()
                || transportHandlerType == DEFAULT_TRANSPORT_HANDLER_TYPE) {
            transportHandlerType = null;
        }
        if (Objects.equals(timeout, defaultCon.getTimeout()) || Objects.equals(timeout, DEFAULT_TIMEOUT)) {
            timeout = null;
        }
        if (hostname.equals(defaultCon.getHostname()) || Objects.equals(hostname, DEFAULT_HOSTNAME)) {
            hostname = null;
        }
        if (ip.equals(defaultCon.getHostname()) || Objects.equals(ip, DEFAULT_IP)) {
            ip = null;
        }
        if (Objects.equals(port, defaultCon.getPort()) || Objects.equals(port, DEFAULT_PORT)) {
            port = null;
        }
    }

    public abstract AliasedConnection getCopy();
}
