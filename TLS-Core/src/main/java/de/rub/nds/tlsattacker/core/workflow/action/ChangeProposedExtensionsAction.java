/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ChangeProposedExtensionsAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<ExtensionType> added = new LinkedList<>();
    private List<ExtensionType> removed = new LinkedList<>();
    private List<ExtensionType> replaced = new LinkedList<>();

    private boolean replace;

    public ChangeProposedExtensionsAction(List<ExtensionType> added, List<ExtensionType> removed) {
        super();
        this.added = added;
        this.removed = removed;
        this.replace = false;
    }

    public ChangeProposedExtensionsAction(List<ExtensionType> replaced) {
        super();
        this.replaced = replaced;
        this.replace = true;
    }

    public ChangeProposedExtensionsAction() {}

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

    public boolean isReplace() {
        return replace;
    }

    public void setReplace(boolean replace) {
        this.replace = replace;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (replace) {
            tlsContext.getProposedExtensions().clear();
            tlsContext.getProposedExtensions().addAll(replaced);
        } else {
            tlsContext.getProposedExtensions().removeAll(removed);
            tlsContext.getProposedExtensions().addAll(added);
        }

        LOGGER.debug("Changed the proposed extension set");

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
}
