package de.rub.nds.tlsattacker.core.stun.parser;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;

public class FingerprintAttributeParser extends StunAttributeParser<FingerprintAttribute> {

    public FingerprintAttributeParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(FingerprintAttribute attribute) {
        byte[] crcChecksum = parseByteArrayField(IceByteLengths.STUN_FINGERPRINT_CRC_CHECKSUM);
        attribute.setCrcChecksum(crcChecksum);
    }
    
}
