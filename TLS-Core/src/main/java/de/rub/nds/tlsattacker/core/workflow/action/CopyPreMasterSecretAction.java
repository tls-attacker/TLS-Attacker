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
 * Copy the PreMasterSecret from srcContext, to dstContext.
 *
 */
public class CopyPreMasterSecretAction extends CopyContextFieldAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public CopyPreMasterSecretAction() {
    }

    public CopyPreMasterSecretAction(String srcConnectionAlias, String dstConnectionAlias) {
        super(srcConnectionAlias, dstConnectionAlias);
    }

    @Override
    protected void copyField(TlsContext src, TlsContext dst) {
        dst.setPreMasterSecret(src.getPreMasterSecret());
        LOGGER.debug("Copying PreMasterSecret from " + src + " to " + dst);
        LOGGER.debug("Copied PreMasterSecret is: "
                + ArrayConverter.bytesToHexString(dst.getPreMasterSecret(), true, true));
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
