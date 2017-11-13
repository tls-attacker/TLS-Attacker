/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PreSharedKeyExtensionSerializer extends ExtensionSerializer<PreSharedKeyExtensionMessage> {

    private final PreSharedKeyExtensionMessage msg;
    private final ConnectionEndType connectionType;
    private final TlsContext context;
    
    public PreSharedKeyExtensionSerializer(PreSharedKeyExtensionMessage message, ConnectionEndType connectionType, TlsContext context) {
        super(message);
        msg = message;
        this.connectionType = connectionType;
        this.context = context;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing PreSharedKeyExtensionMessage");
        if(connectionType == ConnectionEndType.CLIENT)
        {
            appendInt(msg.getIdentityListLength(), ExtensionByteLength.PSK_IDENTITY_LIST_LENGTH);
            LOGGER.debug("PreSharedKeyIdentityListLength: " + msg.getIdentityListLength());
            writeIdentities();
        
            appendInt(msg.getBinderListLength(), ExtensionByteLength.PSK_BINDER_LIST_LENGTH);
            LOGGER.debug("PreSharedKeyBinderListLength: " + msg.getBinderListLength());
            writeBinders(); //At this point, we're only writing dummy bytes
        }
        else
        {
            writeSelectedIdentity();
        }       
        
        return getAlreadySerialized();
    }
    
    public void writeIdentities()
    {
        for(PSKIdentity pskIdentity : msg.getIdentities())
        {
            appendInt(pskIdentity.getIdentityLength(), ExtensionByteLength.PSK_IDENTITY_LENGTH);
            appendBytes(pskIdentity.getIdentity());
            appendBytes(pskIdentity.getObfuscatedTicketAge());
        }
    }
    
    public void writeBinders()
    {
        for(PSKBinder pskBinder : msg.getBinders())
        {
            appendInt(pskBinder.getBinderEntryLength(), ExtensionByteLength.PSK_BINDER_LENGTH);
            appendBytes(pskBinder.getBinderEntry());
        }
    }
    
    public void writeSelectedIdentity()
    {
        appendInt(msg.getSelectedIdentity().getValue(), ExtensionByteLength.PSK_SELECTED_IDENTITY_LENGTH);
    }
    
    
    
    public void updateBinders(byte[] clientHelloBytes)
    {
        LOGGER.debug("Calculating actual binder values to replace dummy bytes");
        
        byte[] relevantBytes = getRelevantBytes(clientHelloBytes, msg);
        calculateBinders(relevantBytes, msg);
        replaceBinders(clientHelloBytes, relevantBytes);
        calculateClientEarlyTrafficSecret(clientHelloBytes);
        
        LOGGER.debug("Updated ClientHelloBytes:" + ArrayConverter.bytesToHexString(clientHelloBytes));
    }
    
    private byte[] getRelevantBytes(byte[] clientHelloBytes, PreSharedKeyExtensionMessage msg)
    {
        int remainingBytes = clientHelloBytes.length - ExtensionByteLength.PSK_BINDER_LIST_LENGTH;
        for(PSKBinder pskBinder : msg.getBinders())
        {
            remainingBytes = remainingBytes - ExtensionByteLength.PSK_BINDER_LENGTH - pskBinder.getBinderEntryLength();
        }
        
        byte[] relevantBytes = new byte[remainingBytes];
        
        for(int x = 0; x < remainingBytes; x++)
        {
            relevantBytes[x] = clientHelloBytes[x];
        }
        
        LOGGER.debug("Relevant Bytes:" + ArrayConverter.bytesToHexString(relevantBytes));
        return relevantBytes;
    }
    
    private void calculateBinders(byte[] relevantBytes, PreSharedKeyExtensionMessage msg)
    {   
        for(int x = 0; x < msg.getBinders().size(); x++)
        {
            try {
                HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(context.getConfig().getPskCipherSuites().get(x));
                Mac mac = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName());
                DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13, context.getConfig().getPskCipherSuites().get(x));
                      
                byte[] psk = context.getConfig().getPreSharedKeys()[x];
                byte[] earlySecret = HKDFunction.extract(hkdfAlgortihm, new byte[0], psk);
                byte[] binderKey = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(), earlySecret, HKDFunction.BINDER_KEY_RES, ArrayConverter.hexStringToByteArray(""));
                byte[] binderFinKey = HKDFunction.expandLabel(hkdfAlgortihm, binderKey, HKDFunction.FINISHED, new byte[0], mac.getMacLength());           
                
                context.getDigest().setRawBytes(relevantBytes);
                SecretKeySpec keySpec = new SecretKeySpec(binderFinKey, mac.getAlgorithm());
                mac.init(keySpec);
                mac.update(context.getDigest().digest(ProtocolVersion.TLS13, context.getConfig().getPskCipherSuites().get(x)));
                byte[] binderVal = mac.doFinal();
                context.getDigest().setRawBytes(new byte[0]);
            
                LOGGER.debug("Using PSK:" + ArrayConverter.bytesToHexString(psk));
                LOGGER.debug("Calculated Binder:" + ArrayConverter.bytesToHexString(binderVal));
                
                msg.getBinders().get(x).setBinderEntry(binderVal);
                if(x == 0) //First entry = PSK for early Data
                {
                    context.setEarlySecret(earlySecret);
                }    
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PreSharedKeyExtensionSerializer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(PreSharedKeyExtensionSerializer.class.getName()).log(Level.SEVERE, null, ex);
        }
        }
    }
    
    private void replaceBinders(byte[] clientHelloBytes, byte[] relevantBytes)
    {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(relevantBytes);
            stream.write(ArrayConverter.intToBytes(msg.getBinderListLength(), ExtensionByteLength.PSK_BINDER_LIST_LENGTH));
            
            for(PSKBinder binder : msg.getBinders())
            {
                byte[] binderLen = ArrayConverter.intToBytes(binder.getBinderEntryLength(), ExtensionByteLength.PSK_BINDER_LENGTH);
                stream.write(binderLen);
                stream.write(binder.getBinderEntry());
            }
            
            System.arraycopy(stream.toByteArray(), 0, clientHelloBytes, 0, stream.toByteArray().length);
        } catch (IOException ex) {
            Logger.getLogger(PreSharedKeyExtensionSerializer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void calculateClientEarlyTrafficSecret(byte[] clientHelloBytes)
    {
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(context.getEarlyDataCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13, context.getEarlyDataCipherSuite());
            
        byte[] earlyTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(), context.getEarlySecret(), HKDFunction.CLIENT_EARLY_TRAFFIC_SECRET, clientHelloBytes);            
        context.setClientEarlyTrafficSecret(earlyTrafficSecret);        
        context.setUseEarlyTrafficSecret(true);
    }
}
