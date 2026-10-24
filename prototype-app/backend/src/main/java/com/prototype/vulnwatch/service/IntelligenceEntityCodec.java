package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Transient;
import java.lang.reflect.Modifier;
import java.util.LinkedHashMap;
import java.util.Map;

/** Scalar PostgreSQL row images, including reference IDs; never serializes entity graphs. */
public final class IntelligenceEntityCodec {
    private IntelligenceEntityCodec() { }
    public static Map<String,Object> row(Object entity) {
        Map<String,Object> row=new LinkedHashMap<>();
        for(var field:entity.getClass().getDeclaredFields()) {
            if(Modifier.isStatic(field.getModifiers()) || field.isAnnotationPresent(Transient.class)) continue;
            try {
                field.setAccessible(true);
                Object value=field.get(entity);
                String name;
                if(field.isAnnotationPresent(ManyToOne.class)) {
                    name=field.getAnnotation(JoinColumn.class).name();
                    value=value==null ? null : value.getClass().getMethod("getId").invoke(value);
                } else {
                    Column column=field.getAnnotation(Column.class);
                    name=column!=null && !column.name().isBlank() ? column.name() : field.getName().replaceAll("([a-z0-9])([A-Z])","$1_$2").toLowerCase(java.util.Locale.ROOT);
                }
                row.put(name,value instanceof Enum<?> enumeration ? enumeration.name() : value);
            } catch(ReflectiveOperationException failure) { throw new IllegalStateException("Cannot encode intelligence row",failure); }
        }
        return row;
    }
}
