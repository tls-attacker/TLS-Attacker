/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.connection;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class OutboundConnection extends AliasedConnection {

    private static final ConnectionEndType LOCAL_CONNECTION_END_TYPE = ConnectionEndType.CLIENT;

    public OutboundConnection() {}

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
        super(other);
    }

    @Override
    public ConnectionEndType getLocalConnectionEndType() {
        return LOCAL_CONNECTION_END_TYPE;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("OutboundConnection{ ");
        addProperties(sb);
        sb.append(" }");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder("OutboundConnection[ ");
        addCompactProperties(sb);
        sb.append(" ]");
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
