package io.hanko.fidouafclient.asm.msgs.request

import io.hanko.fidouafclient.client.msg.Transaction

data class AuthenticateIn (
    val appID: String,
    val keyIDs: List<String>,
    val finalChallenge: String,
    val transaction: Transaction?
)
