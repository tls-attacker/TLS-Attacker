/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import javax.xml.bind.annotation.XmlTransient;

public class ServerConnectionEnd extends ConnectionEnd {

    private static final ConnectionEndType CONNECTION_END_TYPE = ConnectionEndType.SERVER;

    public ServerConnectionEnd() {
    }

    public ServerConnectionEnd(String alias) {
        super(alias);
    }

    public ServerConnectionEnd(String alias, Integer port) {
        super(alias, port);
    }

    @XmlTransient
    @Override
    public String getHostname() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public void setHostname(String hostname) {
        throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    public ConnectionEndType getConnectionEndType() {
        return CONNECTION_END_TYPE;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ServerConnectionEnd{");
        sb.append(" alias=").append(alias);
        sb.append(" port=").append(port);
        sb.append(" type=").append(transportHandlerType);
        sb.append(" timeout=").append(timeout);
        sb.append("}");
        return sb.toString();
    }

}
