package me.xethh.libs.encryptDecryptLib;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@With
public class SignedData {
    private String signature;
    private String data;
}
