package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class RegistrationResponse (
	val header: OperationHeader,
	val fcParams: String,
	val assertions: List<AuthenticatorRegistrationAssertion>
)
