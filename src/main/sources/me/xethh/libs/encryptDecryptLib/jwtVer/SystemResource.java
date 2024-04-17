package me.xethh.libs.encryptDecryptLib.jwtVer;

import lombok.*;
import me.xethh.utils.wrapper.Tuple2;

import java.util.Objects;
import java.util.Optional;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@With
public class SystemResource {
    private String sysId;
    private String resource;

    public String name(){
        return String.format("%s::%s", sysId, resource);
    }

    public static SystemResource fromName(String name){
        return Optional.of(name.split("::"))
                .map(it-> Tuple2.of(it[0], it[1]))
                .map(it->SystemResource.builder()
                        .sysId(it.getV1())
                        .resource(it.getV2())
                        .build()
                ).orElseThrow(()->new RuntimeException("Fail to extract the System resource"))
                ;

    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SystemResource that = (SystemResource) o;
        return Objects.equals(sysId, that.sysId) && Objects.equals(resource, that.resource);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sysId, resource);
    }
}
