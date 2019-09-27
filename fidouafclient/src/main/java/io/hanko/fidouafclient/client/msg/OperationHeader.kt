package io.hanko.fidouafclient.client.msg

class OperationHeader (
	val upv: Version,
	val op: Operation,
	val appID: String?,
	val serverData: String?,
	val exts: List<Extension>?
)
