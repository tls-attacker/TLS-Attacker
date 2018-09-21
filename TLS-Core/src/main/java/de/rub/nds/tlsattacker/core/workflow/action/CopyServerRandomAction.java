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
 */
public class CopyServerRandomAction extends CopyContextFieldAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public CopyServerRandomAction() {
    }

    public CopyServerRandomAction(String srcContextAlias, String dstConnectionAlias) {
        super(srcContextAlias, dstConnectionAlias);
    }

    @Override
    protected void copyField(TlsContext src, TlsContext dst) {
        dst.setServerRandom(src.getServerRandom());
        LOGGER.debug("Copying server random from " + src + " to " + dst);
        LOGGER.debug("Copied server random is: " + ArrayConverter.bytesToHexString(dst.getServerRandom(), true, true));

    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
