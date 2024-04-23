package de.rub.nds.tlsattacker.core.stun.preparator;

import java.util.zip.CRC32;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class FingerprintAttributePreparator extends StunAttributePreparator<FingerprintAttribute>{

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
        return ArrayConverter.longToBytes(crc32.getValue(), IceByteLengths.STUN_FINGERPRINT_CRC_CHECKSUM);
    }
    
}
