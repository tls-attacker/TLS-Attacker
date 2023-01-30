/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ChangeConnectionIdAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private byte[] readConnectionId = null;
    private byte[] writeConnectionId = null;

    public ChangeConnectionIdAction(byte[] readConnectionId, byte[] writeConnectionId) {
        this.readConnectionId = readConnectionId;
        this.writeConnectionId = writeConnectionId;
    }

    public ChangeConnectionIdAction() {}

    public byte[] getReadConnectionId() {
        return readConnectionId;
    }

    public void setReadConnectionId(byte[] readConnectionId) {
        this.readConnectionId = readConnectionId;
    }

    public byte[] getWriteConnectionId() {
        return writeConnectionId;
    }

    public void setWriteConnectionId(byte[] writeConnectionId) {
        this.writeConnectionId = writeConnectionId;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (readConnectionId != null) {
            tlsContext.setReadConnectionId(readConnectionId);
            LOGGER.debug("Changed the read connection id");
        }
        if (writeConnectionId != null) {
            tlsContext.setWriteConnectionId(writeConnectionId);
            LOGGER.debug("Changed the write connection id");
        }

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        ChangeConnectionIdAction that = (ChangeConnectionIdAction) o;

        if (!Arrays.equals(readConnectionId, that.readConnectionId)) return false;
        return Arrays.equals(writeConnectionId, that.writeConnectionId);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(readConnectionId);
        result = 31 * result + Arrays.hashCode(writeConnectionId);
        return result;
    }
}
