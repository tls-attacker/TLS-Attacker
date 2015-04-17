package de.rub.nds.tlsattacker.util;

import java.math.BigInteger;
import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ByteArrayAdapter extends XmlAdapter<String, byte[]> {

    @Override
    public byte[] unmarshal(String value) {
	value = value.replaceAll("\\s", "");
	BigInteger i = new BigInteger(value, 16);
	return i.toByteArray();
    }

    @Override
    public String marshal(byte[] value) {
	return ArrayConverter.bytesToHexString(value);
    }

}
