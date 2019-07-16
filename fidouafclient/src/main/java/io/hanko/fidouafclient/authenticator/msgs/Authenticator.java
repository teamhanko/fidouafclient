package io.hanko.fidouafclient.authenticator.msgs;


import io.hanko.fidouafclient.client.msg.DisplayPNGCharacteristicsDescriptor;
import io.hanko.fidouafclient.client.msg.Version;

public class Authenticator {
    public String title;
    public String aaid;
    public String description;
    public Version[] supportedUAFVersions;
    public String assertionScheme;
    public short authenticationAlgorithm;
    public short[] attestationTypes;
    public long userVerification;
    public short keyProtection;
    public short matcherProtection;
    public long attachmentHint;
    public boolean isSecondFactorOnly;
    public short tcDisplay;
    public String tcDisplayContentType;
    public DisplayPNGCharacteristicsDescriptor tcDisplayPNGCharacteristics;
    public String icon;
    public String[] supportedExtensionIDs;
    
    public Authenticator(
            final String title,
            final String aaid,
            final String description,
            final Version[] supportedUAFVersions,
            final String assertionScheme,
            final short authenticationAlgorithm,
            final short[] attestationTypes,
            final long userVerification,
            final short keyProtection,
            final short matcherProtection,
            final long attachmentHint,
            final boolean isSecondFactorOnly,
            final short tcDisplay,
            final String tcDisplayContentType,
            final DisplayPNGCharacteristicsDescriptor tcDisplayPNGCharacteristics,
            final String icon,
            final String[] supportedExtensionIDs
    ) {
        this.title = title;
        this.aaid = aaid;
        this.description = description;
        this.supportedUAFVersions = supportedUAFVersions;
        this.assertionScheme = assertionScheme;
        this.authenticationAlgorithm = authenticationAlgorithm;
        this.attestationTypes = attestationTypes;
        this.userVerification = userVerification;
        this.keyProtection = keyProtection;
        this.matcherProtection = matcherProtection;
        this.attachmentHint = attachmentHint;
        this.isSecondFactorOnly = isSecondFactorOnly;
        this.tcDisplay = tcDisplay;
        this.tcDisplayContentType = tcDisplayContentType;
        this.tcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
        this.icon = icon;
        this.supportedExtensionIDs = supportedExtensionIDs;
    }
}
