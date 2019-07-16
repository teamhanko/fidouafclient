package io.hanko.fidouafclient.asm.msgs.request;

import io.hanko.fidouafclient.client.msg.Transaction;

public class AuthenticateIn {
    public String appID;
    public String[] keyIDs;
    public String finalChallenge;
    public Transaction transaction;
}
