/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Copy client random from one context to another. */
@XmlRootElement
public class CopyServerRandomAction extends CopyContextFieldAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public CopyServerRandomAction() {}

    public CopyServerRandomAction(String srcContextAlias, String dstConnectionAlias) {
        super(srcContextAlias, dstConnectionAlias);
    }

    @Override
    protected void copyField(TlsContext src, TlsContext dst) {
        dst.setServerRandom(src.getServerRandom());
        LOGGER.debug("Copying server random from " + src + " to " + dst);
        LOGGER.debug("Copied server random is: {}", dst.getServerRandom());
        setExecuted(true);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
