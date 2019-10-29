package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class ChannelBinding (
	val serverEndPoint: String?,
	val tlsServerCertificate: String?,
	val tlsUnique: String?,
	val cid_pubkey: String?
)
