package me.xethh.libs.encryptDecryptLib;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import me.xethh.libs.encryptDecryptLib.dataModel.DataContainer;
import me.xethh.libs.encryptDecryptLib.exceptions.SerializationException;

public class DeEnUtils {

    public static String dataContainerAsString(ObjectMapper om, DataContainer envelope){
        try{
            return om.writeValueAsString(envelope);
        } catch (JsonProcessingException ex){
            throw new SerializationException(ex);
        }
    }
}
