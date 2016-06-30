/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package WorkFlowType;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import java.util.Objects;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MessageFlow {
    private final Class<? extends Object> message;
    private final ConnectionEnd issuer;

    public MessageFlow(Class<? extends Object> message, ConnectionEnd issuer) {
        this.message = message;
        this.issuer = issuer;
    }

    public Class<?> getMessage() {
        return message;
    }

    public ConnectionEnd getIssuer() {
        return issuer;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 47 * hash + Objects.hashCode(this.message);
        hash = 47 * hash + Objects.hashCode(this.issuer);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final MessageFlow other = (MessageFlow) obj;
        if (!Objects.equals(this.message, other.message)) {
            return false;
        }
        if (this.issuer != other.issuer) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "MessageFlow{" + "message=" + message + ", issuer=" + issuer + '}';
    }
    
}
