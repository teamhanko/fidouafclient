package io.hanko.fidouafclient.client.msg.client;

import io.hanko.fidouafclient.authenticator.msgs.Authenticator;
import io.hanko.fidouafclient.client.msg.Version;

public class DiscoveryData {
    public Version[] supportedUAFVersions;
    public String clientVendor;
    public Version clientVersion;
    public Authenticator[] availableAuthenticators;
}
