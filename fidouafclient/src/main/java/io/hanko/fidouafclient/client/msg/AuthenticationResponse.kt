package io.hanko.fidouafclient.client.msg;

class AuthenticationResponse (
	val header: OperationHeader,
	val fcParam: String,
	val assertions: List<AuthenticatorSignAssertion>
)
