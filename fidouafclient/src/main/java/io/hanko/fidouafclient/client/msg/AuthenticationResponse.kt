package io.hanko.fidouafclient.client.msg;

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class AuthenticationResponse (
	val header: OperationHeader,
	val fcParams: String,
	val assertions: List<AuthenticatorSignAssertion>
)
