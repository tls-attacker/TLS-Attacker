/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.socket.AliasedConnection;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.IOException;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class TlsAction implements Serializable {

    protected static final Logger LOGGER = LogManager.getLogger(TlsAction.class.getName());
    private static final boolean EXECUTED_DEFAULT = false;

    private Boolean executed = null;

    /**
     * Reference the TlsContext this action belongs to. Only needed if the state
     * holds multiple contexts to choose from (i.e. in MitM scenarios). A
     * contextAlias = null is treated as default context. Set to null here to
     * keep serialization output clean.
     */
    protected String contextAlias = null;

    public boolean isExecuted() {
        if (executed == null) {
            return EXECUTED_DEFAULT;
        }
        return executed;
    }

    public void setExecuted(Boolean executed) {
        this.executed = executed;
    }

    public String getContextAlias() {
        if (contextAlias == null) {
            return AliasedConnection.DEFAULT_CONNECTION_ALIAS;
        } else {
            return contextAlias;
        }
    }

    public void setContextAlias(String contextAlias) {
        this.contextAlias = contextAlias;
    }

    public abstract void execute(State state) throws WorkflowExecutionException, IOException;

    public boolean isMessageAction() {
        return this instanceof MessageAction;
    }

    /**
     * Checks that the Action got executed as planned
     * 
     * @return True if the Action got executed as planned
     */
    public abstract boolean executedAsPlanned();

    public abstract void reset();
}
