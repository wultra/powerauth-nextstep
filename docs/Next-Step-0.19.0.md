# Migration from 0.18.0 to 0.19.0

### Operation form data change

Operation form data has changed to reflect the need to separate operation summary from greeting message. Previously only a 'message' attribute was used for both purposes. This attribute is now split into 'greeting' and 'summary'.

The 'greeting' is displayed in the web user interface above payment data. The 'summary' text is sent in the push messages and contains all operation data and it is also displayed in offline mode for Mobile Token.

Previous form data structure:
```json
{
  "formData" : {
    "title" : {
      "id" : "operation.title",
      "value" : "Confirm Payment"
    },
    "message" : {
      "id" : "operation.greeting",
      "value" : "Hello,\n please confirm following payment:"
    }
  }
}
```

New form data structure:
```json
{
  "formData" : {
    "title" : {
      "id" : "operation.title",
      "value" : "Confirm Payment"
    },
    "greeting" : {
      "id" : "operation.greeting",
      "value" : "Hello,\n please confirm following payment:"
    },
    "summary" : {
      "id" : "operation.summary",
      "value" : "Hello, please confirm payment 100 CZK to account 238400856/0300."
    }
  }
}
```

Following messages are required in resources for all locales:

```
login.greeting=Dobrý den,\n přihlaste se, prosím.
login.summary=Potvrďte prosím přihlášení uživatele.
operation.greeting=Hello,\n please confirm following payment:
operation.summary=Hello, please confirm payment {operation.amount} {operation.currency} to account {operation.account}.
```

The previously used messages 'login.message' and 'operation.message' are obsolete.

For clients using the API, the change is also reflected in the client API.

Previously used 'message' attribute:
```java
        OperationFormData formData = new OperationFormData();
        formData.addMessage("operation.message");
```

New 'greeting' and 'summary' attributes:
```java
        OperationFormData formData = new OperationFormData();
        formData.addGreeting("operation.greeting");
        formData.addSummary("operation.summary");
```

### Form data value formatting

Web Flow now supports value formatting. Following formats can be specified when creating operation for individual fields:
  - TEXT - value is not formatted
  - LOCALIZED_TEXT - value is localized using localization key from message resources
  - DATE - value is formatted as date using current locale
  - NUMBER - value is formatted as number using current locale
  - AMOUNT - value is formatted as amount with currency using current locale
  - ACCOUNT - value is not formatted (reserved for future use)

Previous initialization of operation form data (still supported):
```java
formData.addKeyValue("operation.dueDate", paymentForm.getDueDate());
```

New initialization of operation form data:
```java
formData.addKeyValue("operation.dueDate", paymentForm.getDueDate(), OperationFormFieldAttributeFormatted.ValueFormatType.DATE);
```

### Bank account choice attribute configuration

Bank account choice field attribute can be configured when creating the operation:
* `ID` - identified of the form field, label is localized based on this ID
* `enabled` - true = value can be changed, false = value is not changeable
* `defaultValue` - default account ID value (preselected value)

```java
OperationFormFieldConfig bankAccountConfig = new OperationFormFieldConfig();
bankAccountConfig.setId("operation.bankAccountChoice");
bankAccountConfig.setEnabled(true);
bankAccountConfig.setDefaultValue("CZ4043210000000087654321");
formData.getConfig().add(bankAccountConfig);
```
