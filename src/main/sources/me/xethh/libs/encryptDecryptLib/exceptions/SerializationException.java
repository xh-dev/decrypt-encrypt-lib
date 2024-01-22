package me.xethh.libs.encryptDecryptLib.exceptions;

public class SerializationException extends RuntimeException{
    public SerializationException() {
    }

    public SerializationException(Throwable cause) {
        super(cause);
    }

    public SerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
