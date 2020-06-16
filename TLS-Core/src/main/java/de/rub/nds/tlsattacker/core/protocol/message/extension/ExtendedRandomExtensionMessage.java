package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

public class ExtendedRandomExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray extendedRandom;

    public ExtendedRandomExtensionMessage(){ super(ExtensionType.EXTENDED_RANDOM); }

    public ExtendedRandomExtensionMessage(Config tlsConfig){
        super(ExtensionType.EXTENDED_RANDOM);
        //TODO: Disable ExtendedRandomExtension for TLS 1.3 Drafts older than 23 (Old Key share extension)
    }

    public void setExtendedRandom(ModifiableByteArray extendedRandom){
        this.extendedRandom = extendedRandom;
    }

    public void setExtendedRandom(byte[] extendedRandomBytes){
        this.extendedRandom = ModifiableVariableFactory.safelySetValue(extendedRandom, extendedRandomBytes);
    }

    public ModifiableByteArray getExtendedRandom(){
        return extendedRandom;
    }

}
