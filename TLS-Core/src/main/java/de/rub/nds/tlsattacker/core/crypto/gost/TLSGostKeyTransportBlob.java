/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.gost;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;

public class TLSGostKeyTransportBlob extends ASN1Object {

    private final GostR3410KeyTransport keyBlob;
    private final DERSequence proxyKeyBlobs;

    private TLSGostKeyTransportBlob(ASN1Sequence seq) {
        this.keyBlob = GostR3410KeyTransport.getInstance(seq.getObjectAt(0));
        this.proxyKeyBlobs = seq.size() > 1 ? (DERSequence) DERSequence.getInstance(seq.getObjectAt(1)) : null;
    }

    public TLSGostKeyTransportBlob(GostR3410KeyTransport keyBlob) {
        this(keyBlob, null);
    }

    public TLSGostKeyTransportBlob(GostR3410KeyTransport keyBlob, DERSequence proxyKeyBlobs) {
        this.keyBlob = keyBlob;
        this.proxyKeyBlobs = proxyKeyBlobs;
    }

    public static TLSGostKeyTransportBlob getInstance(Object obj) {
        if (obj instanceof TLSGostKeyTransportBlob) {
            return (TLSGostKeyTransportBlob) obj;
        }

        if (obj != null) {
            return new TLSGostKeyTransportBlob(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public GostR3410KeyTransport getKeyBlob() {
        return keyBlob;
    }

    public DERSequence getProxyKeyBlobs() {
        return proxyKeyBlobs;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(keyBlob);
        if (proxyKeyBlobs != null) {
            v.add(proxyKeyBlobs);
        }

        return new DERSequence(v);
    }

}
