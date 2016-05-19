/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ByteArrayAdapter extends XmlAdapter<String, byte[]> {

    @Override
    public byte[] unmarshal(String value) {
	value = value.replaceAll("\\s", "");
	return ArrayConverter.hexStringToByteArray(value);
    }

    @Override
    public String marshal(byte[] value) {
	return ArrayConverter.bytesToHexString(value);
    }

}
