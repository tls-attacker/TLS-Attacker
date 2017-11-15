/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PskSet;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKBinderSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKIdentitySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PreSharedKeyExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PreSharedKeyExtensionPreparator extends ExtensionPreparator<PreSharedKeyExtensionMessage> {

    private final PreSharedKeyExtensionMessage msg;
    private ClientHelloMessage clientHello;
    
    public PreSharedKeyExtensionPreparator(Chooser chooser, PreSharedKeyExtensionMessage message,
            ExtensionSerializer<PreSharedKeyExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing PreSharedKeyExtensionMessage");
        if(chooser.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT)
        {
            prepareLists();
            prepareIdentityListBytes();
            prepareBinderListBytes(); //we're only preparing dummy bytes here
        }
        else
        {
            prepareSelectedIdentity();
        }  
    }
    
    private void prepareLists()
    {
        List<PSKIdentity> identities = new LinkedList<>();
        List<PSKBinder> binders = new LinkedList<>();
        List<PskSet> pskSets = chooser.getConfig().getPskSets();
        
        for(int x = 0; x < pskSets.size(); x++)
        {
            PSKIdentity pskIdentity = new PSKIdentity();
            new PSKIdentityPreparator(chooser, pskIdentity, pskSets.get(x)).prepare();
            PSKBinder pskBinder = new PSKBinder();
            new PSKBinderPreparator(chooser, pskBinder, pskSets.get(x)).prepare();
            identities.add(pskIdentity);
            binders.add(pskBinder);
            
            if(x == 0) //First identity of the list = PSK for 0-RTT data
            {
                chooser.getContext().setEarlyDataPSKIdentity(pskSets.get(x).getPreSharedKeyIdentity());
                chooser.getContext().setEarlyDataCipherSuite(pskSets.get(x).getCipherSuite());
            }       
        }
        msg.setIdentities(identities);
        msg.setBinders(binders);
    }

    private void prepareSelectedIdentity()
    {
        LOGGER.debug("Preparing selected identity");
        msg.setSelectedIdentity(chooser.getContext().getSelectedIdentityIndex());
    }
    
    
    private void prepareIdentityListBytes()
    {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (PSKIdentity pskIdentity : msg.getIdentities()) 
        {
            PSKIdentitySerializer serializer = new PSKIdentitySerializer(pskIdentity);
            try 
            {
                outputStream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] from PSKIdentity", ex);
            }
        }
        
        msg.setIdentityListBytes(outputStream.toByteArray());
        msg.setIdentityListLength(msg.getIdentityListBytes().getValue().length);
    }
    
    private void prepareBinderListBytes()
    {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (PSKBinder pskBinder : msg.getBinders()) 
        {
            PSKBinderSerializer serializer = new PSKBinderSerializer(pskBinder);
            try 
            {
                outputStream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] from PSKIdentity", ex);
            }
        }
        
        msg.setBinderListBytes(outputStream.toByteArray());
        msg.setBinderListLength(msg.getBinderListBytes().getValue().length);
    }
    
    @Override
    public void afterPrepareExtensionContent()
    {
        if(chooser.getContext().getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT)
        {
            prepareActualBinders();
        }
    }
    
    private void prepareActualBinders()
    {
        LOGGER.debug("Preparing binder values to replace dummy bytes");
        ClientHelloSerializer clientHelloSerializer = new ClientHelloSerializer(clientHello, chooser.getSelectedProtocolVersion());
        byte[] clientHelloBytes = clientHelloSerializer.serialize();
        byte[] relevantBytes = getRelevantBytes(clientHelloBytes);
        calculateBinders(relevantBytes, msg);
        prepareBinderListBytes(); //Re-write list using actual values
        chooser.getContext().setUseEarlyTrafficSecret(true); //MOVE SOMEWHERE ELSE!
        LOGGER.debug("Our work is done here! Full Bytes:" + ArrayConverter.bytesToHexString(msg.getBinderListBytes().getValue()));
    }
    
    private byte[] getRelevantBytes(byte[] clientHelloBytes)
    {
        int remainingBytes = clientHelloBytes.length - ExtensionByteLength.PSK_BINDER_LIST_LENGTH;
        for(PSKBinder pskBinder : msg.getBinders())
        {
            remainingBytes = remainingBytes - ExtensionByteLength.PSK_BINDER_LENGTH - pskBinder.getBinderEntryLength().getValue();
        }
        
        byte[] relevantBytes = new byte[remainingBytes];
        
        System.arraycopy(clientHelloBytes, 0, relevantBytes, 0, remainingBytes);
        
        LOGGER.debug("Relevant Bytes:" + ArrayConverter.bytesToHexString(relevantBytes));
        return relevantBytes;
    }
    
    private void calculateBinders(byte[] relevantBytes, PreSharedKeyExtensionMessage msg)
    {   
        List<PskSet> pskSets = chooser.getContext().getConfig().getPskSets();
        for(int x = 0; x < msg.getBinders().size(); x++)
        {
            try {
                HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(pskSets.get(x).getCipherSuite());
                Mac mac = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName());
                DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13, pskSets.get(x).getCipherSuite());
                int macLength = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();
                      
                byte[] resumpMasterSec = pskSets.get(x).getPreSharedKey(); //This is for testing and should replace the part after byte[] psk =
            
                byte[] psk = HKDFunction.expandLabel(hkdfAlgortihm, resumpMasterSec, "resumption", ArrayConverter.hexStringToByteArray("00"), macLength);
                byte[] earlySecret = HKDFunction.extract(hkdfAlgortihm, new byte[0], psk);
                byte[] binderKey = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(), earlySecret, HKDFunction.BINDER_KEY_RES, ArrayConverter.hexStringToByteArray(""));
                byte[] binderFinKey = HKDFunction.expandLabel(hkdfAlgortihm, binderKey, HKDFunction.FINISHED, new byte[0], mac.getMacLength());           
                
                pskSets.get(x).setPreSharedKey(psk); // Testing
                
                chooser.getContext().getDigest().setRawBytes(relevantBytes);
                SecretKeySpec keySpec = new SecretKeySpec(binderFinKey, mac.getAlgorithm());
                mac.init(keySpec);
                mac.update(chooser.getContext().getDigest().digest(ProtocolVersion.TLS13, pskSets.get(x).getCipherSuite()));
                byte[] binderVal = mac.doFinal();
                chooser.getContext().getDigest().setRawBytes(new byte[0]);
            
                LOGGER.debug("Using PSK:" + ArrayConverter.bytesToHexString(psk));
                LOGGER.debug("Calculated Binder:" + ArrayConverter.bytesToHexString(binderVal));
                
                msg.getBinders().get(x).setBinderEntry(binderVal);
                if(x == 0) //First entry = PSK for early Data
                {
                    chooser.getContext().setEarlySecret(earlySecret);
                }    
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PreSharedKeyExtensionSerializer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(PreSharedKeyExtensionSerializer.class.getName()).log(Level.SEVERE, null, ex);
        }
        }
    }

    /**
     * @return the clientHello
     */
    public ClientHelloMessage getClientHello() {
        return clientHello;
    }

    /**
     * @param clientHello the clientHello to set
     */
    public void setClientHello(ClientHelloMessage clientHello) {
        this.clientHello = clientHello;
    }
}
