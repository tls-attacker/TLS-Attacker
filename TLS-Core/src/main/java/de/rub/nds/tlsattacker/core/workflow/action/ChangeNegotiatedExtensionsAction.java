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

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ChangeNegotiatedExtensionsAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<ExtensionType> added = null;
    private List<ExtensionType> removed = null;
    private List<ExtensionType> replaced = null;

    public ChangeNegotiatedExtensionsAction(
            List<ExtensionType> added, List<ExtensionType> removed) {
        super();
        this.added = added;
        this.removed = removed;
    }

    public ChangeNegotiatedExtensionsAction(List<ExtensionType> replaced) {
        super();
        this.replaced = replaced;
    }

    public ChangeNegotiatedExtensionsAction() {}

    public List<ExtensionType> getAdded() {
        return added;
    }

    public void setAdded(List<ExtensionType> added) {
        this.added = added;
    }

    public List<ExtensionType> getRemoved() {
        return removed;
    }

    public void setRemoved(List<ExtensionType> removed) {
        this.removed = removed;
    }

    public List<ExtensionType> getReplaced() {
        return replaced;
    }

    public void setReplaced(List<ExtensionType> replaced) {
        this.replaced = replaced;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (replaced != null) {
            tlsContext.getNegotiatedExtensionSet().clear();
            tlsContext.getNegotiatedExtensionSet().addAll(replaced);
        } else {
            tlsContext.getNegotiatedExtensionSet().removeAll(removed);
            tlsContext.getNegotiatedExtensionSet().addAll(added);
        }

        LOGGER.debug("Changed the negotiated extension set");

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

        ChangeNegotiatedExtensionsAction that = (ChangeNegotiatedExtensionsAction) o;

        if (!Objects.equals(added, that.added)) return false;
        if (!Objects.equals(removed, that.removed)) return false;
        return Objects.equals(replaced, that.replaced);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (added != null ? added.hashCode() : 0);
        result = 31 * result + (removed != null ? removed.hashCode() : 0);
        result = 31 * result + (replaced != null ? replaced.hashCode() : 0);
        return result;
    }
}
