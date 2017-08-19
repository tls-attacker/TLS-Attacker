/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Objects;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ConnectionEnd {

    private String alias;
    private ConnectionEndType connectionEndType;
    private Integer port = null;
    private String hostname = null;

    public ConnectionEnd() {
    }

    public ConnectionEnd(String alias) {
        this.alias = alias;
    }

    public ConnectionEnd(ConnectionEnd other) {
        alias = other.alias;
        connectionEndType = other.connectionEndType;
        port = other.port;
        hostname = other.hostname;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public void setConnectionEndType(ConnectionEndType connectionEndType) {
        this.connectionEndType = connectionEndType;
    }

    public ConnectionEndType getConnectionEndType() {
        return connectionEndType;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    @Override
    public String toString() {
        return "ConnectionEnd{" + "alias=" + alias + ", connectionEndType=" + connectionEndType + ", port=" + port
                + ", hostname=" + hostname + '}';
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 89 * hash + Objects.hashCode(this.alias);
        hash = 89 * hash + Objects.hashCode(this.connectionEndType);
        hash = 89 * hash + Objects.hashCode(this.port);
        hash = 89 * hash + Objects.hashCode(this.hostname);
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
        final ConnectionEnd other = (ConnectionEnd) obj;
        if (!Objects.equals(this.alias, other.alias)) {
            return false;
        }
        if (!Objects.equals(this.hostname, other.hostname)) {
            return false;
        }
        if (this.connectionEndType != other.connectionEndType) {
            return false;
        }
        if (!Objects.equals(this.port, other.port)) {
            return false;
        }
        return true;
    }

}
