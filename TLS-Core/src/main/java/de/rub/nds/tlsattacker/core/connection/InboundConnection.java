/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.connection;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class InboundConnection extends AliasedConnection {

    private static final ConnectionEndType LOCAL_CONNECTION_END_TYPE = ConnectionEndType.SERVER;

    public InboundConnection() {
    }

    public InboundConnection(Integer port) {
        super(port);
    }

    public InboundConnection(Integer port, String hostname) {
        super(port, hostname);
    }

    public InboundConnection(String alias) {
        super(alias);
    }

    public InboundConnection(String alias, Integer port) {
        super(alias, port);
    }

    public InboundConnection(String alias, Integer port, String hostname) {
        super(alias, port, hostname);
    }

    public InboundConnection(InboundConnection other) {
        super(other);
    }

    @Override
    public ConnectionEndType getLocalConnectionEndType() {
        return LOCAL_CONNECTION_END_TYPE;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("InboundConnection{ ");
        addProperties(sb);
        sb.append(" }");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder("InboundConnection[ ");
        addCompactProperties(sb);
        sb.append(" ]");
        return sb.toString();
    }

    @Override
    public void normalize(AliasedConnection defaultCon) {
        if (defaultCon == null) {
            defaultCon = new InboundConnection();
        }
        super.normalize(defaultCon);
    }

    @Override
    public void filter(AliasedConnection defaultCon) {
        if (defaultCon == null) {
            defaultCon = new InboundConnection();
        }
        super.filter(defaultCon);
    }

    @Override
    public InboundConnection getCopy() {
        return new InboundConnection(this);
    }
}
