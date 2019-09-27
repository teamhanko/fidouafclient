package io.hanko.fidouafclient.client.msg

class AuthenticatorSignAssertion (
	val assertionScheme: String,
	val assertion: String,
	val exts: List<Extension>?
)
