/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.cipher;

import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordAEADCipher extends RecordCipher {

    private final TlsContext context;
    
    public RecordAEADCipher(TlsContext context) {
        super(0, true, true);
        this.context = context;
    }

    @Override
    public byte[] encrypt(byte[] data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] decrypt(byte[] data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void init() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getMacLength() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] calculateMac(byte[] data) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] calculatePadding(int paddingLength) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getPaddingLength(int dataLength) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    

}
