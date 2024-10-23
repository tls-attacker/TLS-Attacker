/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import de.rub.nds.tlsattacker.core.layer.*;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.List;

public class ReceiveTillHttpContentAction extends CommonReceiveAction {

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    protected String httpContent;

    public ReceiveTillHttpContentAction(String httpContent) {
        super();
        this.httpContent = httpContent;
    }

    public ReceiveTillHttpContentAction(String connectionAlias, String httpContent) {
        super(connectionAlias);
        this.httpContent = httpContent;
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext();
        return ActionHelperUtil.createReceiveTillHttpContentConfiguration(tlsContext, httpContent);
    }
}
