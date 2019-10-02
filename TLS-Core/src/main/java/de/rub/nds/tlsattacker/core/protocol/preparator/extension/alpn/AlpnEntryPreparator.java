/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension.alpn;

import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class AlpnEntryPreparator extends Preparator<AlpnEntry> {

    private final AlpnEntry entry;

    public AlpnEntryPreparator(Chooser chooser, AlpnEntry entry) {
        super(chooser, entry);
        this.entry = entry;
    }

    @Override
    public void prepare() {
        entry.setAlpnEntryBytes(entry.getAlpnEntryConfig());
        entry.setAlpnEntryLength(entry.getAlpnEntryBytes().getValue().length);
    }

}
