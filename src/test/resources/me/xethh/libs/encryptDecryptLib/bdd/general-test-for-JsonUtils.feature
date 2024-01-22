Feature: test JsonUtils functions
  Scenario: cast json by class
    Given we have list of simple java object
    When cast the object back to list of object
    Then item count and item value should be correct

  Scenario: cast json by TypeRefrence
    Given we have list of simple java object
    When cast the object back to list of object through TypeReference
    Then item count and item value should be correct as targeted object

  Scenario: cast json by JavaType
    Given we have list of simple java object
    When cast the object back to list of object through JavaType
    Then item count and item value should be correct as targeted object
