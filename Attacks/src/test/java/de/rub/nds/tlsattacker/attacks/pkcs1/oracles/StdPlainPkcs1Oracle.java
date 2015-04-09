package de.rub.nds.tlsattacker.attacks.pkcs1.oracles;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class StdPlainPkcs1Oracle extends TestPkcs1Oracle {

    public StdPlainPkcs1Oracle(final PublicKey pubKey, final TestPkcs1Oracle.OracleType oracleType, final int blockSize) {
	this.publicKey = (RSAPublicKey) pubKey;
	this.oracleType = oracleType;
	this.isPlaintextOracle = true;
	this.blockSize = blockSize;
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
	numberOfQueries++;
	return checkDecryptedBytes(msg);
    }
}
