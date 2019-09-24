package io.hanko.fidouafclient.client.msg

import com.fasterxml.jackson.annotation.JsonIgnoreProperties

@JsonIgnoreProperties(ignoreUnknown = true)
open class UafRequest(open val header: OperationHeader)

@JsonIgnoreProperties(ignoreUnknown = true)
class UafRegistrationRequest(override val header: OperationHeader, val challenge: String, val username: String, val policy: Policy): UafRequest(header)

@JsonIgnoreProperties(ignoreUnknown = true)
class UafAuthenticationRequest(override val header: OperationHeader, val challenge: String, val transaction: List<Transaction>, val policy: Policy): UafRequest(header)

@JsonIgnoreProperties(ignoreUnknown = true)
class UafDeregistrationRequest(override val header: OperationHeader, val authenticators: List<DeregisterAuthenticator>): UafRequest(header)