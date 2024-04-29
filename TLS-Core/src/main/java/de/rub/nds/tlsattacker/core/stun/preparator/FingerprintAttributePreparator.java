/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.preparator;

import java.util.zip.CRC32;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class FingerprintAttributePreparator extends StunAttributePreparator<FingerprintAttribute> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final byte[] XOR_MASK = new byte[] { (byte) 0x53, (byte) 0x54, (byte) 0x55, (byte) 0x4e };

    public FingerprintAttributePreparator(Chooser chooser, FingerprintAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {

        getObject().setCrcChecksum(xorChecksumWithMask(computeCrc32Checksum()));
    }

    public byte[] computeCrc32Checksum() {
        byte[] transcript = chooser.getContext().getIceContext().getMessageTranscript();
        CRC32 crc32 = new CRC32();
        crc32.update(transcript);
        LOGGER.debug("Transcript: {}", ArrayConverter.bytesToHexString(transcript));
        LOGGER.debug("CRC32: {}", crc32.getValue());
        return ArrayConverter.longToBytes(
                crc32.getValue(), IceByteLengths.STUN_FINGERPRINT_CRC_CHECKSUM);
    }

    private byte[] xorChecksumWithMask(byte[] checksum) {
        byte[] xoredChecksum = new byte[checksum.length];
        for (int i = 0; i < checksum.length; i++) {
            xoredChecksum[i] = (byte) (checksum[i] ^ XOR_MASK[i]);
        }
        return xoredChecksum;
    }
}
