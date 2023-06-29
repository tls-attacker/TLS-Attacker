/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension.alpn;

import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class AlpnEntryPreparator extends Preparator<AlpnEntry> {

    private final AlpnEntry entry;

    public AlpnEntryPreparator(Chooser chooser, AlpnEntry entry) {
        super(chooser, entry);
        this.entry = entry;
    }

    @Override
    public void prepare() {
        entry.setAlpnEntry(entry.getAlpnEntryConfig());
        entry.setAlpnEntryLength(
                entry.getAlpnEntry().getValue().getBytes(StandardCharsets.ISO_8859_1).length);
    }
}
