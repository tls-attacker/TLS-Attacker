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
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PreSharedKeyExtensionPreparator extends ExtensionPreparator<PreSharedKeyExtensionMessage> {

    private final PreSharedKeyExtensionMessage msg;
    
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
            msg.calcIdentityListLength();
            msg.calcBinderListLength();
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
        
        for(int x = 0; x < chooser.getConfig().getPreSharedKeyIdentities().length; x++)
        {
           if(x >= chooser.getConfig().getTicketAgeAdds().length || x >= chooser.getConfig().getTicketAges().size() || x >= chooser.getConfig().getPskCipherSuites().size())
           {
               LOGGER.warn("A given PSK-Identity is missing required information (skipping)");
           }
           else
           {
               try {
                   HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(chooser.getConfig().getPskCipherSuites().get(x));
                   int macLen = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();
                   
                   byte[] obfuscatedTicketAge = getObfuscatedTicketAge(chooser.getConfig().getTicketAgeAdds()[x], chooser.getConfig().getTicketAges().get(x));
                   PSKIdentity pskIdentity = new PSKIdentity(chooser.getConfig().getPreSharedKeyIdentities()[x], obfuscatedTicketAge);
                   PSKBinder pskBinder = new PSKBinder(new byte[macLen]);
                   
                   identities.add(pskIdentity);
                   binders.add(pskBinder);
                   
                   if(x == 0) //First identity of the list = PSK for 0-RTT data
                   {
                       chooser.getContext().setEarlyDataPSKIdentity(chooser.getConfig().getPreSharedKeyIdentities()[x]);
                       chooser.getContext().setEarlyDataCipherSuite(chooser.getConfig().getPskCipherSuites().get(x));
                   }
                       
               } catch (NoSuchAlgorithmException ex) {
                   Logger.getLogger(PreSharedKeyExtensionPreparator.class.getName()).log(Level.SEVERE, null, ex);
               }
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
    
    private byte[] getObfuscatedTicketAge(byte[] ticketAgeAdd, String ticketAge)
    {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
        LocalDateTime ticketDate = LocalDateTime.parse(ticketAge, dateTimeFormatter);
        BigInteger difference = BigInteger.valueOf(Duration.between(ticketDate, LocalDateTime.now()).toMillis());
        BigInteger addValue = BigInteger.valueOf(ArrayConverter.bytesToLong(ticketAgeAdd));
        BigInteger mod = BigInteger.valueOf(2).pow(32);
        difference = difference.add(addValue);
        difference = difference.mod(mod);
        byte[] obfTicketAge = ArrayConverter.longToBytes(difference.longValue(), ExtensionByteLength.TICKET_AGE_LENGTH);
        
        LOGGER.debug("Calculated ObfuscatedTicketAge: " + ArrayConverter.bytesToHexString(obfTicketAge));
        return obfTicketAge;
    }
}
