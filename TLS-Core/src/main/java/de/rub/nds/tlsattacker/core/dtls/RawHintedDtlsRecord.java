/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import org.checkerframework.checker.nullness.qual.NonNull;

public class RawHintedDtlsRecord {

    private final RecordLayerHint recordLayerHint;
    private final byte[] protocolMessageBytes;

    public RawHintedDtlsRecord(
            @NonNull RecordLayerHint recordLayerHint, byte @NonNull [] protocolMessageBytes) {

        if (recordLayerHint.getEpoch() == null || recordLayerHint.getSequenceNumber() == null) {
            throw new IllegalArgumentException(
                    "Epoch and SequenceNumber must be set in RecordLayerHint");
        }

        this.recordLayerHint = recordLayerHint;
        this.protocolMessageBytes = protocolMessageBytes;
    }

    public RecordLayerHint getRecordLayerHint() {
        return recordLayerHint;
    }

    public byte[] getProtocolMessageBytes() {
        return protocolMessageBytes;
    }
}
