package io.hanko.fidouafclient.client.msg

class OperationHeader (
	val upv: Version,
	val op: Operation,
	val appID: String? = null,
	val serverData: String? = null,
	val exts: List<Extension>? = null
)
