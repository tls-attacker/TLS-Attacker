/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Copy client random from one context to another.
 *
 */
public class CopyClientRandomAction extends CopyContextFieldAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public CopyClientRandomAction() {
    }

    public CopyClientRandomAction(String srcContextAlias, String dstConnectionAlias) {
        super(srcContextAlias, dstConnectionAlias);
    }

    @Override
    protected void copyField(TlsContext src, TlsContext dst) {
        dst.setClientRandom(src.getClientRandom());
        LOGGER.debug("Copying client random from " + src + " to " + dst);
        LOGGER.debug("Copied client random is: " + ArrayConverter.bytesToHexString(dst.getClientRandom(), true, true));
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
