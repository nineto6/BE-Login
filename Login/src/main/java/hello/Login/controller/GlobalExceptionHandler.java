package hello.Login.controller;

import hello.Login.common.codes.ErrorCode;
import hello.Login.config.exception.BusinessExceptionHandler;
import hello.Login.controller.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    /**
     * BusinessException 에서 발생한 에러
     * @param ex
     * @return ResponseEntity
     */
    @ExceptionHandler(BusinessExceptionHandler.class)
    public ResponseEntity<ErrorResponse> businessExHandler(BusinessExceptionHandler ex) {
        log.error("[exceptionHandler] ex", ex);

        ErrorResponse er = ErrorResponse.builder()
                .result(ErrorCode.BUSINESS_EXCEPTION_ERROR.getDivisionCode())
                .resultCode(ErrorCode.BUSINESS_EXCEPTION_ERROR.getStatus())
                .resultMsg(ErrorCode.BUSINESS_EXCEPTION_ERROR.getMessage())
                .reason(ex.getMessage())
                .build();

        return new ResponseEntity<>(er, HttpStatus.OK);
    }
}
