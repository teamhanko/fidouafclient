package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
open class UafRequest(open val header: OperationHeader)

@JsonClass(generateAdapter = true)
class UafRegistrationRequest(
        override val header: OperationHeader,
        val challenge: String,
        val username: String,
        val policy: Policy
) : UafRequest(header)

@JsonClass(generateAdapter = true)
class UafAuthenticationRequest(override val header: OperationHeader, val challenge: String, val transaction: List<Transaction>?, val policy: Policy) : UafRequest(header)

@JsonClass(generateAdapter = true)
class UafDeregistrationRequest(override val header: OperationHeader, val authenticators: List<DeregisterAuthenticator>) : UafRequest(header)