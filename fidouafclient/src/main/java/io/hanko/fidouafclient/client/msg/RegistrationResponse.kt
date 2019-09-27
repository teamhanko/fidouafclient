package io.hanko.fidouafclient.client.msg

class RegistrationResponse (
	val header: OperationHeader,
	val fcParams: String,
	val assertions: List<AuthenticatorRegistrationAssertion>
)
