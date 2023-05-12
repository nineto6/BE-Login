package hello.Login.controller.response;

import lombok.Builder;
import lombok.Getter;

@Getter
public class ObjectApiResponse {
    Object result;
    int resultCode;
    String resultMsg;

    @Builder
    public ObjectApiResponse(Object result, int resultCode, String resultMsg) {
        this.result = result;
        this.resultCode = resultCode;
        this.resultMsg = resultMsg;
    }
}
