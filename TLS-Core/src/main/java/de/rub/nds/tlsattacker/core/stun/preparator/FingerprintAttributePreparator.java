/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.zip.CRC32;

public class FingerprintAttributePreparator extends StunAttributePreparator<FingerprintAttribute> {

    public FingerprintAttributePreparator(Chooser chooser, FingerprintAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {

        getObject().setCrcChecksum(computeCrc32Checksum());
    }

    public byte[] computeCrc32Checksum() {
        byte[] transcript = chooser.getContext().getIceContext().getMessageTranscript();
        CRC32 crc32 = new CRC32();
        crc32.update(transcript);
        return ArrayConverter.longToBytes(
                crc32.getValue(), IceByteLengths.STUN_FINGERPRINT_CRC_CHECKSUM);
    }
}
