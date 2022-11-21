/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.layer;

import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RecordLayerFactory {

    public static RecordLayer getRecordLayer(RecordLayerType type, TlsContext context) {
        switch (type) {
            case BLOB:
                return new BlobRecordLayer(context);
            case RECORD:
                return new TlsRecordLayer(context);
            default:
                throw new UnsupportedOperationException("RecordLayerType: " + type.name() + " not supported!");
        }
    }

    private RecordLayerFactory() {
    }
}
