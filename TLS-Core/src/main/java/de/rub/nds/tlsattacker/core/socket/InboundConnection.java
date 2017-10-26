/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
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

    @Override
    public ConnectionEndType getLocalConnectionEndType() {
        return LOCAL_CONNECTION_END_TYPE;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("InboundConnection{");
        sb.append(" alias=").append(alias);
        sb.append(" port=").append(port);
        sb.append(" type=").append(transportHandlerType);
        sb.append(" timeout=").append(timeout);
        sb.append("}");
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
}
