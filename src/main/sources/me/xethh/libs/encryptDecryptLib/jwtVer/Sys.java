package me.xethh.libs.encryptDecryptLib.jwtVer;

public class Sys {
    private final String sysId;
    public String name(){
        return sysId;
    }

    private Sys(String sysId) {
        this.sysId = sysId;
    }

    public static Sys of(String sysId){
        return new Sys(sysId);
    }

    public SystemResource resource(String resource){
        return new SystemResource(sysId, resource);
    }

    public SystemResource resource(String resource, String key){
        return new SystemResource(sysId, String.format("%s/%s", resource, key));
    }

}
