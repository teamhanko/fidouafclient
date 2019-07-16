package io.hanko.fidouafclient.asm.msgs.response;

import io.hanko.fidouafclient.client.msg.DisplayPNGCharacteristicsDescriptor;
import io.hanko.fidouafclient.client.msg.Version;

public class AuthenticatorInfo {
    public short authenticatorIndex;
    public Version[] asmVersions;
    public boolean isUserEnrolled;
    public boolean hasSettings;
    public String aaid;
    public String assertionScheme;
    public short authenticationAlgorithm;
    public short[] attestationTypes;
    public long userVerification;
    public short keyProtection;
    public short matcherProtection;
    public long attachmentHint;
    public boolean isSecondFactorOnly;
    public boolean isRoamingAuthenticator;
    public String[] supportedExtensionIDs;
    public short tcDisplay;
    public String tcDisplayContentType;
    public DisplayPNGCharacteristicsDescriptor[] tcDisplayPNGCharacteristics;
    public String title;
    public String description;
    public String icon;
}
