package hello.Login.controller.response;

import lombok.Builder;
import lombok.Getter;

@Getter
public class ErrorResponse {
    String result;
    int resultCode;
    String resultMsg;
    String reason;

    @Builder
    public ErrorResponse(String result, int resultCode, String resultMsg, String reason) {
        this.result = result;
        this.resultCode = resultCode;
        this.resultMsg = resultMsg;
        this.reason = reason;
    }
}
