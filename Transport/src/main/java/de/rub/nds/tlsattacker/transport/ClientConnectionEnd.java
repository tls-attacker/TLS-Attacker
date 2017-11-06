/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import java.util.Objects;

/**
 *

 */
public class ClientConnectionEnd extends ConnectionEnd {

    private static final ConnectionEndType CONNECTION_END_TYPE = ConnectionEndType.CLIENT;
    private String hostname = null;

    public ClientConnectionEnd() {
    }

    public ClientConnectionEnd(String alias) {
        super(alias);
    }

    public ClientConnectionEnd(String alias, Integer port, String hostname) {
        super(alias, port);
        this.hostname = hostname;
    }

    @Override
    public String getHostname() {
        return hostname;
    }

    @Override
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    @Override
    public ConnectionEndType getConnectionEndType() {
        return CONNECTION_END_TYPE;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ClientConnectionEnd{");
        sb.append(" alias=").append(alias);
        sb.append(" port=").append(port);
        sb.append(" hostname=").append(hostname);
        sb.append(" type=").append(transportHandlerType);
        sb.append(" timeout=").append(timeout);
        sb.append("}");
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + Objects.hashCode(this.hostname);
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
        final ClientConnectionEnd other = (ClientConnectionEnd) obj;
        if (!(super.equals(other))) {
            return false;
        }
        if (!Objects.equals(this.hostname, other.hostname)) {
            return false;
        }
        return true;
    }

}
