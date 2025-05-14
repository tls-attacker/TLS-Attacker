/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.EnumSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "ChangeNegotiatedExtensions")
public class ChangeNegotiatedExtensionsAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private EnumSet<ExtensionType> newList = null;
    private EnumSet<ExtensionType> oldList = null;

    public ChangeNegotiatedExtensionsAction(EnumSet<ExtensionType> newList) {
        super();
        this.newList = newList;
    }

    public ChangeNegotiatedExtensionsAction() {}

    public EnumSet<ExtensionType> getNewList() {
        return newList;
    }

    public void setNewList(EnumSet<ExtensionType> newList) {
        this.newList = newList;
    }

    public EnumSet<ExtensionType> getOldList() {
        return oldList;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        oldList = tlsContext.getNegotiatedExtensionSet();
        tlsContext.getNegotiatedExtensionSet().clear();
        tlsContext.getNegotiatedExtensionSet().addAll(newList);
        LOGGER.info("Changed negotiated extension set from {} to {}", oldList, newList);

        setExecuted(true);
    }

    @Override
    public void reset() {
        oldList = null;
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
