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

/** Copy the PreMasterSecret from srcContext, to dstContext. */
@XmlRootElement
public class CopyPreMasterSecretAction extends CopyContextFieldAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public CopyPreMasterSecretAction() {}

    public CopyPreMasterSecretAction(String srcConnectionAlias, String dstConnectionAlias) {
        super(srcConnectionAlias, dstConnectionAlias);
    }

    @Override
    protected void copyField(TlsContext src, TlsContext dst) {
        dst.setPreMasterSecret(src.getPreMasterSecret());
        LOGGER.debug("Copying PreMasterSecret from " + src + " to " + dst);
        LOGGER.debug("Copied PreMasterSecret is: {}", dst.getPreMasterSecret());
        setExecuted(true);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
