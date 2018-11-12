/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.connection;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class OutboundConnection extends AliasedConnection {

    private static final ConnectionEndType LOCAL_CONNECTION_END_TYPE = ConnectionEndType.CLIENT;

    public OutboundConnection() {
    }

    public OutboundConnection(Integer port) {
        super(port);
    }

    public OutboundConnection(Integer port, String hostname) {
        super(port, hostname);
    }

    public OutboundConnection(String alias) {
        super(alias);
    }

    public OutboundConnection(String alias, Integer port) {
        super(alias, port);
    }

    public OutboundConnection(String alias, Integer port, String hostname) {
        super(alias, port, hostname);
    }

    public OutboundConnection(OutboundConnection other) {
        this.alias = other.alias;
        this.hostname = other.hostname;
        this.port = other.port;
        this.proxyDataHostname = other.proxyDataHostname;
        this.proxyDataPort = other.proxyDataPort;
        this.proxyControlHostname = other.proxyControlHostname;
        this.proxyControlPort = other.proxyControlPort;
        this.timeout = other.timeout;
        this.transportHandlerType = other.transportHandlerType;
    }

    @Override
    public ConnectionEndType getLocalConnectionEndType() {
        return LOCAL_CONNECTION_END_TYPE;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("OutboundConnection{");
        sb.append(" alias=").append(alias);
        sb.append(" host=").append(hostname);
        sb.append(" port=").append(port);
        sb.append(" proxyDataHost=").append(proxyDataHostname);
        sb.append(" proxyDataPort=").append(proxyDataPort);
        sb.append(" proxyControlHost=").append(proxyControlHostname);
        sb.append(" proxyControlPort=").append(proxyControlPort);
        sb.append(" type=").append(transportHandlerType);
        sb.append(" timeout=").append(timeout);
        sb.append("}");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder("OutboundConnection[");
        sb.append(alias);
        sb.append(":").append(hostname);
        sb.append(":").append(port).append("]");
        return sb.toString();
    }

    @Override
    public void normalize(AliasedConnection defaultCon) {
        if (defaultCon == null) {
            defaultCon = new OutboundConnection();
        }
        super.normalize(defaultCon);
    }

    @Override
    public void filter(AliasedConnection defaultCon) {
        if (defaultCon == null) {
            defaultCon = new OutboundConnection();
        }
        super.filter(defaultCon);
    }

    @Override
    public OutboundConnection getCopy() {
        return new OutboundConnection(this);
    }
}
