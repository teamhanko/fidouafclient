package io.hanko.fidouafclient.util


import com.squareup.moshi.FromJson
import com.squareup.moshi.JsonReader

class StringJsonAdapter {
    @FromJson
    fun fromJson(reader: JsonReader): String {
        val type = reader.peek()
        if (type == JsonReader.Token.STRING) {
            return reader.nextString()
        } else {
            throw IllegalArgumentException("Attempt to parse $type to String.class")
        }
    }
}

class IntJsonAdapter {
    @FromJson
    fun fromJson(reader: JsonReader): Int {
        val type = reader.peek()
        if (type == JsonReader.Token.NUMBER) {
            return reader.nextInt()
        } else {
            throw IllegalArgumentException("Attempt to parse $type to Int.class")
        }
    }
}

class LongJsonAdapter {
    @FromJson
    fun fromJson(reader: JsonReader): Long {
        val type = reader.peek()
        if (type == JsonReader.Token.NUMBER) {
            return reader.nextLong()
        } else {
            throw IllegalArgumentException("Attempt to parse $type to Long.class")
        }
    }
}

class OptionalStringJsonAdapter {
    @FromJson
    fun fromJson(reader: JsonReader): String? {
        return when (val type = reader.peek()) {
            JsonReader.Token.STRING -> reader.nextString()
            JsonReader.Token.NULL -> reader.nextNull()
            else -> throw IllegalArgumentException("Attempt to parse $type to String?.class")
        }
    }
}

class OptionalLongJsonAdapter {
    @FromJson
    fun fromJson(reader: JsonReader): Long? {
        return when (val type = reader.peek()) {
            JsonReader.Token.NUMBER -> reader.nextLong()
            JsonReader.Token.NULL -> reader.nextNull()
            else -> throw IllegalArgumentException("Attempt to parse $type to Long?.class")
        }
    }
}

class OptionalIntJsonAdapter {
    @FromJson
    fun fromJson(reader: JsonReader): Int? {
        return when (val type = reader.peek()) {
            JsonReader.Token.NUMBER -> reader.nextInt()
            JsonReader.Token.NULL -> reader.nextNull()
            else -> throw IllegalArgumentException("Attempt to parse $type to Long?.class")
        }
    }
}
