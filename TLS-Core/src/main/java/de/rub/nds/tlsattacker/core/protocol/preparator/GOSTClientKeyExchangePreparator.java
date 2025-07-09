/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP256R1;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.gost.GOST28147WrapEngine;
import de.rub.nds.tlsattacker.core.crypto.gost.TLSGostKeyTransportBlob;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.util.GOSTUtils;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
import org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;
import org.bouncycastle.asn1.cryptopro.GostR3410TransportParameters;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;

public abstract class GOSTClientKeyExchangePreparator
        extends ClientKeyExchangePreparator<GOSTClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static Map<ASN1ObjectIdentifier, String> oidMappings = new HashMap<>();

    static {
        oidMappings.put(
                CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_TestParamSet, "E-TEST");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet, "E-A");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_B_ParamSet, "E-B");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_C_ParamSet, "E-C");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_D_ParamSet, "E-D");
        oidMappings.put(RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z, "Param-Z");
    }

    private final GOSTClientKeyExchangeMessage msg;

    public GOSTClientKeyExchangePreparator(Chooser chooser, GOSTClientKeyExchangeMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        prepareAfterParse();
    }

    @Override
    public void prepareAfterParse() {
        try {
            LOGGER.debug("Preparing GOST EC VKO.");
            LOGGER.warn(
                    "You ran into old buggy code of TLS-Attacker - this is likely not functional");
            if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                msg.prepareComputations();
                prepareClientServerRandom();
                prepareUkm();

                preparePms();
                msg.getComputations().setPrivateKey(chooser.getClientEphemeralEcPrivateKey());
                prepareEphemeralKey();
                prepareKek(
                        msg.getComputations().getPrivateKey().getValue(),
                        chooser.getServerEphemeralEcPublicKey());
                prepareEncryptionParams();
                prepareCek();
                prepareKeyBlob();
            } else {
                TLSGostKeyTransportBlob transportBlob =
                        TLSGostKeyTransportBlob.getInstance(msg.getKeyTransportBlob().getValue());
                LOGGER.debug(
                        "Received GOST key blob: {}", ASN1Dump.dumpAsString(transportBlob, true));
                TLSGostKeyTransportBlob.getInstance(msg.getKeyTransportBlob().getValue());
                LOGGER.debug(
                        "Received GOST key blob: {}", ASN1Dump.dumpAsString(transportBlob, true));

                GostR3410KeyTransport keyBlob = transportBlob.getKeyBlob();
                if (!Arrays.equals(
                        keyBlob.getTransportParameters().getUkm(),
                        msg.getComputations().getUkm().getValue())) {
                    LOGGER.warn("Client UKM != Server UKM");
                }

                Point publicKey = chooser.getClientEphemeralEcPublicKey();

                prepareKek(chooser.getServerEphemeralEcPrivateKey(), publicKey);

                byte[] wrapped =
                        DataConverter.concatenate(
                                keyBlob.getSessionEncryptedKey().getEncryptedKey(),
                                keyBlob.getSessionEncryptedKey().getMacKey());

                String sboxName =
                        oidMappings.get(keyBlob.getTransportParameters().getEncryptionParamSet());
                byte[] pms = wrap(false, wrapped, sboxName);
                msg.getComputations().setPremasterSecret(pms);
            }
        } catch (Exception e) {
            throw new UnsupportedOperationException("Could not prepare the key agreement!", e);
        }
    }

    private void prepareClientServerRandom() {
        byte[] random =
                DataConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        LOGGER.debug(
                "ClientServerRandom: {}", msg.getComputations().getClientServerRandom().getValue());
    }

    private void prepareUkm() throws NoSuchAlgorithmException {
        DigestAlgorithm digestAlgorithm =
                AlgorithmResolver.getDigestAlgorithm(
                        chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite());
        MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getJavaName());
        byte[] hash = digest.digest(msg.getComputations().getClientServerRandom().getValue());

        byte[] ukm = new byte[8];
        System.arraycopy(hash, 0, ukm, 0, ukm.length);
        msg.getComputations().setUkm(ukm);
        LOGGER.debug("UKM: {}", msg.getComputations().getUkm());
    }

    private void prepareKek(BigInteger privateKey, Point publicKey)
            throws GeneralSecurityException {
        CyclicGroup<?> group = chooser.getSelectedGostCurve().getGroupParameters().getGroup();
        EllipticCurve curve;
        if (group instanceof EllipticCurve) {
            curve = (EllipticCurve) group;
        } else {
            LOGGER.warn("Selected group is not an EllipticCurve. Using SECP256R1");
            curve = new EllipticCurveSECP256R1();
        }

        Point sharedPoint = curve.mult(privateKey, publicKey);
        if (sharedPoint == null) {
            LOGGER.warn("GOST shared point is null - using base point instead");
            sharedPoint = curve.getBasePoint();
        }
        byte[] pms = PointFormatter.toRawFormat(sharedPoint);
        Digest digest = getKeyAgreementDigestAlgorithm();
        digest.update(pms, 0, pms.length);
        byte[] kek = new byte[digest.getDigestSize()];
        digest.doFinal(kek, 0);
        msg.getComputations().setKeyEncryptionKey(kek);
        LOGGER.debug("KEK: {}", msg.getComputations().getKeyEncryptionKey());
    }

    private void preparePms() {
        byte[] pms = chooser.getContext().getTlsContext().getPreMasterSecret();
        if (pms != null) {
            LOGGER.debug("Using preset PreMasterSecret from context");
        } else {
            LOGGER.debug("Generating random PreMasterSecret");
            pms = new byte[32];
            chooser.getContext().getTlsContext().getRandom().nextBytes(pms);
        }

        msg.getComputations().setPremasterSecret(pms);
    }

    private void prepareEphemeralKey() {
        CyclicGroup<?> group = chooser.getSelectedGostCurve().getGroupParameters().getGroup();
        EllipticCurve curve;
        if (group instanceof EllipticCurve) {
            curve = (EllipticCurve) group;
        } else {
            LOGGER.warn("Selected group is not an EllipticCurve. Using SECP256R1");
            curve = new EllipticCurveSECP256R1();
        }
        LOGGER.debug("Using key from context");
        msg.getComputations().setPrivateKey(chooser.getClientEphemeralEcPrivateKey());
        Point publicKey =
                curve.mult(msg.getComputations().getPrivateKey().getValue(), curve.getBasePoint());
        if (publicKey == null) {
            LOGGER.warn("Failed to generate ephemeral public key - using base point");
            publicKey = curve.getBasePoint();
        }
        msg.getComputations().setClientPublicKey(publicKey);
    }

    private byte[] wrap(boolean wrap, byte[] bytes, String sboxName) {
        try {
            byte[] sbox = GOST28147Engine.getSBox(sboxName);
            KeyParameter keySpec =
                    new KeyParameter(msg.getComputations().getKeyEncryptionKey().getValue());
            ParametersWithSBox withSBox = new ParametersWithSBox(keySpec, sbox);
            ParametersWithUKM withIV =
                    new ParametersWithUKM(withSBox, msg.getComputations().getUkm().getValue());

            GOST28147WrapEngine cipher = new GOST28147WrapEngine();
            cipher.init(wrap, withIV);
            byte[] result;
            try {
                if (wrap) {
                    LOGGER.debug("Wrapping GOST PMS: {}", bytes);
                    result = cipher.wrap(bytes, 0, bytes.length);
                } else {
                    LOGGER.debug("Unwrapping GOST PMS: {}", bytes);
                    result = cipher.unwrap(bytes, 0, bytes.length);
                }
            } catch (IndexOutOfBoundsException ex) {
                // TODO this is not so nice, but its honestly not worth fixing as gost is not used
                // and this can only
                // happen
                // during fuzzing
                LOGGER.warn(
                        "IndexOutOfBounds within GOST code. We catch this and return an empty byte array");
                result = new byte[0];
            }
            LOGGER.debug("Wrap result: {}", result);
            return result;
        } catch (Exception E) {
            if (E instanceof UnsupportedOperationException) {
                throw E;
            }
            LOGGER.warn("Could not wrap. Using byte[0]");
            return new byte[0];
        }
    }

    private void prepareCek() {
        ASN1ObjectIdentifier param =
                new ASN1ObjectIdentifier(msg.getComputations().getEncryptionParamSet().getValue());
        String sboxName = oidMappings.get(param);
        byte[] wrapped =
                wrap(true, msg.getComputations().getPremasterSecret().getValue(), sboxName);

        byte[] cek = new byte[32];
        try {
            if (wrapped.length <= cek.length) {
                System.arraycopy(wrapped, 0, cek, 0, cek.length);
            } else {
                // This case is for fuzzing purposes only.
                System.arraycopy(wrapped, 0, cek, 0, wrapped.length - 1);
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            LOGGER.warn("Something going wrong here...");
        }
        msg.getComputations().setEncryptedKey(cek);
        byte[] mac;
        if (wrapped.length - cek.length < 0) {
            mac = new byte[0];
        } else {
            mac = new byte[wrapped.length - cek.length];
            System.arraycopy(wrapped, cek.length, mac, 0, mac.length);
        }
        msg.getComputations().setMacKey(mac);
    }

    private void prepareEncryptionParams() {
        msg.getComputations().setEncryptionParamSet(getEncryptionParameters());
    }

    private void prepareKeyBlob() throws IOException {
        try {
            if (msg.getComputations().getClientPublicKeyX() == null
                    || msg.getComputations().getClientPublicKeyY() == null
                    || msg.getComputations().getClientPublicKeyX().getValue() == null
                    || msg.getComputations().getClientPublicKeyY().getValue() == null) {
                LOGGER.warn(
                        "Client public key coordinates are not properly initialized - cannot create GOST key blob");
                msg.setKeyTransportBlob(new byte[0]);
                return;
            }

            Point ecPoint =
                    Point.createPoint(
                            msg.getComputations().getClientPublicKeyX().getValue(),
                            msg.getComputations().getClientPublicKeyY().getValue(),
                            chooser.getSelectedGostCurve().getGroupParameters());

            if (ecPoint == null) {
                LOGGER.warn("Failed to create EC point from coordinates");
                msg.setKeyTransportBlob(new byte[0]);
                return;
            }

            PublicKey generatedKey =
                    GOSTUtils.generatePublicKey(chooser.getSelectedGostCurve(), ecPoint);
            if (generatedKey == null) {
                LOGGER.warn("Failed to generate public key from EC point");
                msg.setKeyTransportBlob(new byte[0]);
                return;
            }

            SubjectPublicKeyInfo ephemeralKey =
                    SubjectPublicKeyInfo.getInstance(generatedKey.getEncoded());

            Gost2814789EncryptedKey encryptedKey =
                    new Gost2814789EncryptedKey(
                            msg.getComputations().getEncryptedKey().getValue(),
                            getMaskKey(),
                            msg.getComputations().getMacKey().getValue());
            ASN1ObjectIdentifier paramSet =
                    new ASN1ObjectIdentifier(
                            msg.getComputations().getEncryptionParamSet().getValue());
            GostR3410TransportParameters params =
                    new GostR3410TransportParameters(
                            paramSet, ephemeralKey, msg.getComputations().getUkm().getValue());
            GostR3410KeyTransport transport = new GostR3410KeyTransport(encryptedKey, params);
            DERSequence proxyKeyBlobs = (DERSequence) DERSequence.getInstance(getProxyKeyBlobs());
            TLSGostKeyTransportBlob blob = new TLSGostKeyTransportBlob(transport, proxyKeyBlobs);
            msg.setKeyTransportBlob(blob.getEncoded());
            LOGGER.debug("GOST key blob: {}", ASN1Dump.dumpAsString(blob, true));
        } catch (Exception e) {
            msg.setKeyTransportBlob(new byte[0]);
            LOGGER.warn("Could not compute correct GOST key blob: using byte[0]", e);
        }
    }

    private byte[] getProxyKeyBlobs() {
        if (msg.getComputations().getProxyKeyBlobs() != null) {
            return msg.getComputations().getProxyKeyBlobs().getValue();
        } else {
            return null;
        }
    }

    private byte[] getMaskKey() {
        if (msg.getComputations().getMaskKey() != null) {
            return msg.getComputations().getMaskKey().getValue();
        } else {
            return null;
        }
    }

    protected abstract ASN1ObjectIdentifier getEncryptionParameters();

    protected abstract Digest getKeyAgreementDigestAlgorithm();

    protected abstract String getKeyPairGeneratorAlgorithm();
}
