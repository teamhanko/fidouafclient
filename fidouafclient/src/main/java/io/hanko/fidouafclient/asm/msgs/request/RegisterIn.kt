package io.hanko.fidouafclient.asm.msgs.request;

class RegisterIn (
    val appID: String,
    val username: String,
    val finalChallenge: String,
    val attestationType: Short
)
