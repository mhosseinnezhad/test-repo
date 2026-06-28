package com.modernisc.security.keycloak.iam.util;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;


public class IsoInstantLocalDateTimeSerializer extends JsonSerializer<LocalDateTime> {
    private static final DateTimeFormatter ISO_INSTANT =
            DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.of("UTC"));

    @Override
    public void serialize(LocalDateTime value, JsonGenerator gen,
                          SerializerProvider serializers) throws IOException {
        gen.writeString(value.atZone(ZoneId.of("UTC")).format(ISO_INSTANT));
    }
}