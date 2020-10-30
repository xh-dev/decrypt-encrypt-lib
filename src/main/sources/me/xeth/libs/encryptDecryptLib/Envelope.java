package me.xeth.libs.encryptDecryptLib;

public class Envelope {
    private String data;
    public Envelope(){
    }
    public Envelope(String data){
        this.data = data;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
