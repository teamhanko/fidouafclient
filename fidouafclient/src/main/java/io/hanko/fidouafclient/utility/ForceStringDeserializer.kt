package io.hanko.fidouafclient.utility

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer

class ForceStringDeserializer : JsonDeserializer<String>() {
    override fun deserialize(jsonParser: JsonParser?, ctxt: DeserializationContext?): String {
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
        if (jsonParser?.currentToken == JsonToken.VALUE_STRING ||
            jsonParser?.currentToken == JsonToken.VALUE_EMBEDDED_OBJECT ||
            jsonParser?.currentToken == JsonToken.VALUE_NULL ||
            jsonParser?.currentToken == JsonToken.VALUE_TRUE ||
            jsonParser?.currentToken == JsonToken.VALUE_FALSE ||
            jsonParser?.currentToken == JsonToken.VALUE_NUMBER_FLOAT) {
            throw ctxt!!.wrongTokenException(jsonParser, JsonToken.VALUE_NUMBER_INT, "Attempt to parse a different type to integer.")
        }

        return jsonParser!!.valueAsInt
    }

}