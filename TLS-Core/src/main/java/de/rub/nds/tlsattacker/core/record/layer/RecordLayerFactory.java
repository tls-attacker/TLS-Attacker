/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
