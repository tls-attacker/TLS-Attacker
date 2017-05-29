/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsDHUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

/**
 * @author Nurullah Erinola
 */
public class KeyShareExtensionHandler extends ExtensionHandler<KeyShareExtensionMessage> {

    public KeyShareExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public KeyShareExtensionParser getParser(byte[] message, int pointer) {
        return new KeyShareExtensionParser(pointer, message);
    }

    @Override
    public KeyShareExtensionPreparator getPreparator(KeyShareExtensionMessage message) {
        return new KeyShareExtensionPreparator(context, message);
    }

    @Override
    public KeyShareExtensionSerializer getSerializer(KeyShareExtensionMessage message) {
        return new KeyShareExtensionSerializer(message, context.getConfig().getConnectionEnd());
    }

    @Override
    public void adjustTLSContext(KeyShareExtensionMessage message) {
        List<KSEntry> ksEntryList = new LinkedList<>();
        for (KeySharePair pair : message.getKeyShareList()) {
            NamedCurve type = NamedCurve.getNamedCurve(pair.getKeyShareType().getValue());
            if (type != null) {
                ksEntryList.add(new KSEntry(type, pair.getKeyShare().getValue()));
            } else {
                LOGGER.warn("Unknown KS Type:" + ArrayConverter.bytesToHexString(pair.getKeyShareType().getValue()));
            }
        }
        if (context.getTalkingConnectionEnd() == ConnectionEnd.SERVER) {
            // The server has only one key
            context.setServerKSEntry(ksEntryList.get(0));
            adjustHandshakeTrafficSecrets();
        } else {
            context.setClientKSEntryList(ksEntryList);
        }
    }

    private void adjustHandshakeTrafficSecrets() {
        MacAlgorithm macAlg = AlgorithmResolver.getHKDFAlgorithm(context.getSelectedCipherSuite()).getMacAlgorithm();
        // PSK = null
        byte[] earlySecret = HKDFunction.extract(macAlg.getJavaName(), new byte[] {}, new byte[32]);
        byte[] saltHandshakeSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), earlySecret, HKDFunction.DERIVED,
                new byte[] {});
        byte[] sharedSecret;
        if (context.getServerKSEntry().getGroup() == NamedCurve.FFDHE2048) {
            sharedSecret = computeSharedSecretDH();
        } else if (context.getServerKSEntry().getGroup() == NamedCurve.ECDH_X25519) {
            sharedSecret = computeSharedSecretECDH();
        } else {
            throw new PreparationException("Support only the key exchange group FFDHE2048");
        }
        byte[] handshakeSecret = HKDFunction.extract(macAlg.getJavaName(), saltHandshakeSecret, sharedSecret);
        // TODO with new TLS Digset
        byte[] clientHandshakeTrafficSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), handshakeSecret,
                HKDFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                context.getDigest().digest(context.getSelectedProtocolVersion(), context.getSelectedCipherSuite()));
        context.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);
        LOGGER.debug("Set clientHandshakeTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(clientHandshakeTrafficSecret));
        byte[] serverHandshakeTrafficSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), handshakeSecret,
                HKDFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET,
                context.getDigest().digest(context.getSelectedProtocolVersion(), context.getSelectedCipherSuite()));
        context.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);
        LOGGER.debug("Set serverHandshakeTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(serverHandshakeTrafficSecret));
    }

    public byte[] computeSharedSecretDH() {
        KSEntry serverKeySahre = context.getServerKSEntry();
        DHParameters dhParams = new DHParameters(new BigInteger(1, context.getConfig().getFixedDHModulus()),
                new BigInteger(1, context.getConfig().getFixedDHg()));
        DHPrivateKeyParameters dhPrivateClient = new DHPrivateKeyParameters(new BigInteger(1, context.getConfig()
                .getKeyShareExponent()), dhParams);
        DHPublicKeyParameters dhPublicServer = new DHPublicKeyParameters(new BigInteger(1,
                serverKeySahre.getSerializedPublicKey()), dhParams);
        try {
            byte[] sharedSecret = TlsDHUtils.calculateDHBasicAgreement(dhPublicServer, dhPrivateClient);
            if (sharedSecret.length != context.getConfig().getFixedDHModulus().length) {
                return ArrayConverter.bigIntegerToNullPaddedByteArray(new BigInteger(1, sharedSecret), context
                        .getConfig().getFixedDHModulus().length);
            } else {
                return sharedSecret;
            }
        } catch (IllegalArgumentException e) {
            throw new PreparationException("Could not calculate shared secret");
        }
    }

    // TODO
    public byte[] computeSharedSecretECDH() {
        KSEntry serverKeySahre = context.getServerKSEntry();
        byte[] clientPrivateKey = context.getConfig().getKeyShare();
        byte[] serverPublicKey = serverKeySahre.getSerializedPublicKey();
        try {
            return doECDH(clientPrivateKey, serverPublicKey);
        } catch (InvalidKeyException ex) {
            throw new PreparationException("Could not calculate shared secret");
        }
    }
    
    // Geladener Code
    public PublicKey loadPublicKeyEC(byte[] data) {
        try {
            ECNamedCurveParameterSpec params1 = ECNamedCurveTable.getParameterSpec("curve25519");
            ECParameterSpec params = new ECParameterSpec(params1.getCurve(), params1.getG(), params1.getH(),
                    params1.getH(), params1.getSeed());
            
            ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
            KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
            return kf.generatePublic(pubKey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
            throw new PreparationException("Could not load the public key");
        }
    }

    public byte [] savePublicKey (PublicKey key) throws Exception
    {
	ECPublicKey eckey = (ECPublicKey)key;
	return eckey.getQ().getEncoded(true);
    }
    
    public PrivateKey loadPrivateKeyEC(byte[] data) {
        try {
            ECNamedCurveParameterSpec params1 = ECNamedCurveTable.getParameterSpec("curve25519");
            ECParameterSpec params = new ECParameterSpec(params1.getCurve(), params1.getG(), params1.getH(),
                    params1.getH(), params1.getSeed());
            
            ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
            KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
            return kf.generatePrivate(prvkey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
             throw new PreparationException("Could not load the private key");
        }
    }
 
    public byte [] savePrivateKey (PrivateKey key) throws Exception
    {
    	ECPrivateKey eckey = (ECPrivateKey)key;
	return eckey.getD().toByteArray();
    }
       
    public byte[] doECDH(byte[] dataPrv, byte[] dataPub) throws InvalidKeyException {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
            ka.init(loadPrivateKeyEC(dataPrv));
            ka.doPhase(loadPublicKeyEC(dataPub), true);
            return ka.generateSecret();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
             throw new PreparationException("Could not calculate shared secret");
        }
    }

}
