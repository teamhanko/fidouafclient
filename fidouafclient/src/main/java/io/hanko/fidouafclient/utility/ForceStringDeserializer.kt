package io.hanko.fidouafclient.utility

import android.util.Base64
import android.util.Log
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.databind.*
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import io.hanko.fidouafclient.client.msg.Extension
import io.hanko.fidouafclient.client.msg.MatchCriteria
import java.lang.Exception

class ForceStringDeserializer : JsonDeserializer<String>() {
    override fun deserialize(jsonParser: JsonParser?, ctxt: DeserializationContext?): String {
        Log.w("StringDeserializer", "Name: ${jsonParser?.currentName} - ValueType: ${jsonParser?.currentToken} - Value: ${jsonParser?.valueAsString}")
        if (jsonParser?.currentToken == JsonToken.VALUE_NUMBER_INT ||
            jsonParser?.currentToken == JsonToken.VALUE_NULL ||
            jsonParser?.currentToken == JsonToken.VALUE_NUMBER_FLOAT ||
            jsonParser?.currentToken == JsonToken.VALUE_FALSE ||
            jsonParser?.currentToken == JsonToken.VALUE_TRUE ||
            jsonParser?.currentToken == JsonToken.VALUE_EMBEDDED_OBJECT) {
            throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_STRING, "Attempt to parse a different type to string.")
        }

        return jsonParser!!.valueAsString
    }
}

class ForceIntDeserializer : JsonDeserializer<Int>() {
    override fun deserialize(jsonParser: JsonParser?, ctxt: DeserializationContext?): Int {
        Log.w("IntDeserializer", "Name: ${jsonParser?.currentName} - ValueType: ${jsonParser?.currentToken} - Value: ${jsonParser?.valueAsString}")
        if (jsonParser?.currentToken == JsonToken.VALUE_STRING ||
            jsonParser?.currentToken == JsonToken.VALUE_EMBEDDED_OBJECT ||
            jsonParser?.currentToken == JsonToken.VALUE_TRUE ||
            jsonParser?.currentToken == JsonToken.VALUE_FALSE ||
            jsonParser?.currentToken == JsonToken.VALUE_NUMBER_FLOAT) {
            throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_NUMBER_INT, "Attempt to parse a different type to integer.")
        }

        return jsonParser!!.valueAsInt
    }
}

class ForceLongDeserializer : JsonDeserializer<Long>() {
    override fun deserialize(jsonParser: JsonParser?, ctxt: DeserializationContext?): Long {
        Log.w("LongDeserializer", "Name: ${jsonParser?.currentName} - ValueType: ${jsonParser?.currentToken} - Value: ${jsonParser?.valueAsString}")
        if (jsonParser?.currentToken == JsonToken.VALUE_STRING ||
                jsonParser?.currentToken == JsonToken.VALUE_EMBEDDED_OBJECT ||
                jsonParser?.currentToken == JsonToken.VALUE_TRUE ||
                jsonParser?.currentToken == JsonToken.VALUE_FALSE ||
                jsonParser?.currentToken == JsonToken.VALUE_NUMBER_FLOAT) {
            throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_NUMBER_INT, "Attempt to parse a different type to integer.")
        }

        return jsonParser!!.valueAsLong
    }
}

class MatchCriteriaDeserializer: JsonDeserializer<MatchCriteria>() {
    private val objectMapper = ObjectMapper()
            .registerKotlinModule()
            .registerKotlinModule()
            .registerModule(
                    SimpleModule()
                            .addDeserializer(String::class.java, ForceStringDeserializer())
                            .addDeserializer(Int::class.java, ForceIntDeserializer())
                            .addDeserializer(Long::class.java, ForceLongDeserializer())
            )
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

    override fun deserialize(jsonParser: JsonParser?, ctxt: DeserializationContext?): MatchCriteria {
        fun getException(type: JsonToken): JsonMappingException {
            return ctxt!!.wrongTokenException(jsonParser, type, "Attempt to parse a different type to MatchCriteria.")
        }
        Log.w("MatchCriteriaDeserializ", "Name: ${jsonParser?.currentName} - ValueType: ${jsonParser?.currentToken} - Value: ${jsonParser?.valueAsString}")
        if (jsonParser?.currentToken == JsonToken.START_OBJECT) {
            val jsonNode: JsonNode = jsonParser.codec.readTree(jsonParser)

            val aaids = getStringArray(jsonParser, jsonNode, ctxt, "aaid")
            val vendorIDs = getStringArray(jsonParser, jsonNode, ctxt, "vendorID")
            val keyIds = getStringArray(jsonParser, jsonNode, ctxt, "keyIDs")?.map { if (isBase64UrlEncoded(it)) it else throw getException(JsonToken.VALUE_STRING) }
            val userVerification = getLong(jsonParser, jsonNode, ctxt, "userVerification")
            val keyProtection = getInt(jsonParser, jsonNode, ctxt, "keyProtection")
            val matcherProtection = getInt(jsonParser, jsonNode, ctxt, "matcherProtection")
            val attachmentHint = getLong(jsonParser, jsonNode, ctxt, "attachmentHint")
            val tcDisplay = getInt(jsonParser, jsonNode, ctxt, "tcDisplay")
            val authenticationAlgorithms = getIntArray(jsonParser, jsonNode, ctxt, "authenticationAlgorithms")
            val assertionSchemes = getStringArray(jsonParser, jsonNode, ctxt, "assertionSchemes")
            val attestationTypes = getIntArray(jsonParser, jsonNode, ctxt, "attestationTypes")
            val authenticatorVersion = getInt(jsonParser, jsonNode, ctxt, "authenticatorVersion")
            val extsNode = jsonNode.get("exts")
            val exts = if (extsNode != null && extsNode.isArray)
                extsNode.map { if (it.isObject) objectMapper.treeToValue(it, Extension::class.java) else throw getException(JsonToken.START_OBJECT) }
            else if (extsNode != null) throw getException(JsonToken.START_ARRAY)
            else null

            return MatchCriteria(
                    aaids,
                    vendorIDs,
                    keyIds,
                    userVerification,
                    keyProtection,
                    matcherProtection,
                    attachmentHint,
                    tcDisplay,
                    authenticationAlgorithms,
                    assertionSchemes,
                    attestationTypes,
                    authenticatorVersion,
                    exts
            )
        } else {
            throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_EMBEDDED_OBJECT, "Attempt to parse a different type to MatchCriteria.")
        }
    }

    private fun getStringArray(jsonParser: JsonParser?, jsonNode: JsonNode, ctxt: DeserializationContext?, name: String): List<String>? {
        val arrayNode: JsonNode? = jsonNode.get(name)
        return when {
            arrayNode == null -> null
            arrayNode.isArray -> arrayNode.map { if (it.isTextual) it.textValue() else throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_EMBEDDED_OBJECT, "Attempt to parse a different type to MatchCriteria.") }
            else -> throw ctxt!!.wrongTokenException(jsonParser, JsonToken.START_ARRAY, "Attempt to parse a different type to Array<String>.")
        }
    }

    private fun getIntArray(jsonParser: JsonParser?, jsonNode: JsonNode, ctxt: DeserializationContext?, name: String): List<Int>? {
        val arrayNode: JsonNode? = jsonNode.get(name)
        return when {
            arrayNode == null -> null
            arrayNode.isArray -> arrayNode.map { if (it.isInt) it.intValue() else throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_EMBEDDED_OBJECT, "Attempt to parse a different type to MatchCriteria.") }
            else -> throw ctxt!!.wrongTokenException(jsonParser, JsonToken.START_ARRAY, "Attempt to parse a different type to Array<Int>.")
        }
    }

    private fun getInt(jsonParser: JsonParser?, jsonNode: JsonNode, ctxt: DeserializationContext?, name: String): Int? {
        val node: JsonNode? = jsonNode.get(name)

        return when {
            node == null -> null
            node.isInt -> node.intValue()
            else -> throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_NUMBER_INT, "Attempt to parse a different type to Int.")
        }
    }

    private fun getLong(jsonParser: JsonParser?, jsonNode: JsonNode, ctxt: DeserializationContext?, name: String): Long? {
        val node: JsonNode? = jsonNode.get(name)

        return when {
            node == null -> null
            node.isInt -> node.longValue()
            else -> throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_NUMBER_INT, "Attempt to parse a different type to Int.")
        }
    }

    private fun isBase64UrlEncoded(string: String): Boolean {
        return try {
            Base64.decode(string, Base64.URL_SAFE or Base64.NO_WRAP)
            true
        } catch (ex: Exception) {
            false
        }
    }
}