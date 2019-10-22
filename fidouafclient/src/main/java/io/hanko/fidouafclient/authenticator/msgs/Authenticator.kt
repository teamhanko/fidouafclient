package io.hanko.fidouafclient.authenticator.msgs;


import com.fasterxml.jackson.annotation.JsonProperty
import io.hanko.fidouafclient.client.msg.DisplayPNGCharacteristicsDescriptor;
import io.hanko.fidouafclient.client.msg.Version;

class Authenticator (
        val title: String,
        val aaid: String,
        val description: String,
        val supportedUAFVersions: List<Version>,
        val assertionScheme: String,
        val authenticationAlgorithm: Short,
        val attestationTypes: List<Short>,
        val userVerification: Long,
        val keyProtection: Short,
        val matcherProtection: Short,
        val attachmentHint: Long,
        @get:JsonProperty("isSecondFactorOnly") val isSecondFactorOnly: Boolean,
        val tcDisplay: Short,
        val tcDisplayContentType: String,
        val tcDisplayPNGCharacteristics: DisplayPNGCharacteristicsDescriptor?,
        val icon: String,
        val supportedExtensionIDs: List<String>
)
