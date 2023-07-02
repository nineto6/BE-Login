package hello.Login.controller.response;

import lombok.Builder;
import lombok.Getter;

@Getter
public class ApiResponse {
    Object result;
    int resultCode;
    String resultMsg;

    @Builder
    public ApiResponse(Object result, int resultCode, String resultMsg) {
        this.result = result;
        this.resultCode = resultCode;
        this.resultMsg = resultMsg;
    }
}
