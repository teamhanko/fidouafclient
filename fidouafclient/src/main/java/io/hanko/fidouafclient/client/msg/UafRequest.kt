package io.hanko.fidouafclient.client.msg

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty

@JsonIgnoreProperties(ignoreUnknown = true)
open class UafRequest(open val header: OperationHeader)

@JsonIgnoreProperties(ignoreUnknown = true)
class UafRegistrationRequest(
        @JsonProperty(required = true) override val header: OperationHeader,
        @JsonProperty(required = true) val challenge: String,
        @JsonProperty(required = true) val username: String,
        @JsonProperty(required = true) val policy: Policy
): UafRequest(header)

@JsonIgnoreProperties(ignoreUnknown = true)
class UafAuthenticationRequest(override val header: OperationHeader, val challenge: String, val transaction: List<Transaction>, val policy: Policy): UafRequest(header)

@JsonIgnoreProperties(ignoreUnknown = true)
class UafDeregistrationRequest(override val header: OperationHeader, val authenticators: List<DeregisterAuthenticator>): UafRequest(header)