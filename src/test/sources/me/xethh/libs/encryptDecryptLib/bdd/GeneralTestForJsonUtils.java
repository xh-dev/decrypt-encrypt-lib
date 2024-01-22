package me.xethh.libs.encryptDecryptLib.bdd;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.*;
import me.xethh.libs.encryptDecryptLib.JsonUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GeneralTestForJsonUtils {
    @When("cast the object back to list of object through TypeReference")
    @SneakyThrows
    public void castTheObjectBackToListOfObjectThroughTypeReference() {
        listOfO = JsonUtils.asTypeReference(listOfOStr, new ObjectMapper(), new TypeReference<List<O>>(){});
    }

    @Then("item count and item value should be correct as targeted object")
    public void itemCountAndItemValueShouldBeCorrectAsTargetedObject() {
        assertEquals(2, listOfO.size());
        assertDoesNotThrow(()->{
            for(var item : listOfO) {
                if(!(item instanceof O)) {
                    throw new RuntimeException("Not expected type");
                }
            }
        });
        assertEquals(Integer.valueOf(1), ((O)listOfO.get(0)).value);
        assertEquals(Integer.valueOf(3), ((O)listOfO.get(1)).value);
    }

    @When("cast the object back to list of object through JavaType")
    public void castTheObjectBackToListOfObjectThroughJavaType() {
        val jType = om.getTypeFactory().constructCollectionType(List.class, O.class);
        listOfO = JsonUtils.asJavaType(listOfOStr, new ObjectMapper(), jType);
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class O {
        private int value;
    }

    ObjectMapper om = new ObjectMapper();
    List listOfO;
    String listOfOStr;
    @Given("we have list of simple java object")
    @SneakyThrows
    public void weHaveListOfSimpleJavaObject() {
        listOfOStr = om.writeValueAsString(Arrays.asList(new O(1), new O(3)));
    }

    @When("cast the object back to list of object")
    @SneakyThrows
    public void castTheObjectBackToListOfObject() {
        listOfO = om.readValue(listOfOStr, List.class);
    }

    @Then("item count and item value should be correct")
    public void itemCountAndItemValueShouldBeCorrect() {
        assertEquals(2, listOfO.size());
        assertDoesNotThrow(()->{
            for(var item : listOfO) {
                if(!(item instanceof HashMap)) {
                    throw new RuntimeException("Not expected type");
                }
            }
        });
        assertEquals(Integer.valueOf(1), ((HashMap<String, Integer>)listOfO.get(0)).get("value"));
        assertEquals(Integer.valueOf(3), ((HashMap<String, Integer>)listOfO.get(1)).get("value"));

    }
}
