package me.xethh.libs.encryptDecryptLib;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtils {
    public static <O> O asClass(String dataIn, ObjectMapper mapper, Class<O> outType){
        try{
            O data = mapper.readValue(dataIn, outType);
            return data;
        } catch (Throwable ex){
            throw new RuntimeException(ex);
        }
    }

    public static <O> O asTypeReference(String dataIn, ObjectMapper mapper, TypeReference<O> outType){
        try{
            O data = mapper.readValue(dataIn, outType);
            return data;
        } catch (Throwable ex){
            throw new RuntimeException(ex);
        }
    }

    public static <O> O asJavaType(String dataIn, ObjectMapper mapper, JavaType outType){
        try{
            O data = mapper.readValue(dataIn, outType);
            return data;
        } catch (Throwable ex){
            throw new RuntimeException(ex);
        }
    }
}
