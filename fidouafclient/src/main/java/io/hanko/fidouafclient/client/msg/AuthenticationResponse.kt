package io.hanko.fidouafclient.client.msg;

class AuthenticationResponse (
	val header: OperationHeader,
	val fcParams: String,
	val assertions: List<AuthenticatorSignAssertion>
)
