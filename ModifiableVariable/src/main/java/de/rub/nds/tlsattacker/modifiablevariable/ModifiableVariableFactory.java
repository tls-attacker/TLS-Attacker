/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable;

import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.modifiablevariable.mlong.ModifiableLong;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ModifiableVariableFactory {

    private ModifiableVariableFactory() {

    }

    public static ModifiableBigInteger createBigIntegerModifiableVariable() {
	return new ModifiableBigInteger();
    }

    public static ModifiableInteger createIntegerModifiableVariable() {
	return new ModifiableInteger();
    }

    public static ModifiableByte createByteModifiableVariable() {
	return new ModifiableByte();
    }

    public static ModifiableByteArray createByteArrayModifiableVariable() {
	return new ModifiableByteArray();
    }
    
    public static ModifiableLong createLongModifiableVariable() {
	return new ModifiableLong();
    }

    public static ModifiableBigInteger safelySetValue(ModifiableBigInteger mv, BigInteger value) {
	if (mv == null) {
	    mv = new ModifiableBigInteger();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableInteger safelySetValue(ModifiableInteger mv, Integer value) {
	if (mv == null) {
	    mv = new ModifiableInteger();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableByte safelySetValue(ModifiableByte mv, Byte value) {
	if (mv == null) {
	    mv = new ModifiableByte();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableByteArray safelySetValue(ModifiableByteArray mv, byte[] value) {
	if (mv == null) {
	    mv = new ModifiableByteArray();
	}
	mv.setOriginalValue(value);
	return mv;
    }
    
    public static ModifiableLong safelySetValue(ModifiableLong mv, Long value) {
	if (mv == null) {
	    mv = new ModifiableLong();
        }
	mv.setOriginalValue(value);
	return mv;
    }
}
