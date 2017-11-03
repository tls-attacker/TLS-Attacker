/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static de.rub.nds.tlsattacker.core.workflow.action.TlsAction.LOGGER;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CopyBufferedMessagesAction extends CopyContextFieldAction {

    public CopyBufferedMessagesAction(String srconnectionAlias, String dstConnectionAlias) {
        super(srconnectionAlias, dstConnectionAlias);
    }

    @Override
    protected void copyField(TlsContext src, TlsContext dst) {
        dst.setMessageBuffer(src.getMessageBuffer());
        LOGGER.debug("Src:" + ArrayConverter.bytesToHexString(src.getServerRandom(), true, true));
        LOGGER.debug("Dst:" + ArrayConverter.bytesToHexString(dst.getServerRandom(), true, true));

    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

}
