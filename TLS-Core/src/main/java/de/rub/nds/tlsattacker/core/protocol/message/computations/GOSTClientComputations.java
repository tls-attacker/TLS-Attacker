/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class GOSTClientComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray ukm;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray cekEnc;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray cekMac;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray kek;

    private ModifiableString encryptionAlgOid;

    private ModifiableBigInteger publicKeyX;

    private ModifiableBigInteger publicKeyY;

    @Override
    public void setSecretsInConfig(Config config) {

    }

    public byte[] getUkm() {
        return ukm.getValue();
    }

    public void setUkm(byte[] ukm) {
        this.ukm = ModifiableVariableFactory.safelySetValue(this.ukm, ukm);
    }

    public void setEncryptionAlgOid(ASN1ObjectIdentifier oid) {
        this.encryptionAlgOid = ModifiableVariableFactory.safelySetValue(this.encryptionAlgOid, oid.getId());
    }

    public ASN1ObjectIdentifier getEncryptionAlgOid() {
        return new ASN1ObjectIdentifier(encryptionAlgOid.getValue());
    }

    public byte[] getCekEnc() {
        return cekEnc.getValue();
    }

    public void setCekEnc(byte[] cekEnc) {
        this.cekEnc = ModifiableVariableFactory.safelySetValue(this.cekEnc, cekEnc);
    }

    public byte[] getCekMac() {
        return cekMac.getValue();
    }

    public void setCekMac(byte[] cekMac) {
        this.cekMac = ModifiableVariableFactory.safelySetValue(this.cekMac, cekMac);
    }

    public byte[] getKek() {
        return kek.getValue();
    }

    public void setKek(byte[] kek) {
        this.kek = ModifiableVariableFactory.safelySetValue(this.kek, kek);
    }

    public CustomECPoint getPublicKey() {
        if (publicKeyX != null && publicKeyY != null) {
            return new CustomECPoint(publicKeyX.getValue(), publicKeyY.getValue());
        } else {
            return null;
        }
    }

    public void setPublicKey(CustomECPoint point) {
        this.publicKeyX = ModifiableVariableFactory.safelySetValue(this.publicKeyX, point.getX());
        this.publicKeyY = ModifiableVariableFactory.safelySetValue(this.publicKeyY, point.getY());
    }

}
