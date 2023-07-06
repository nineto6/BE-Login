package hello.Login.model.codes;

import lombok.Getter;

@Getter
public enum Account {
    /**
     * 휴면 계정
     */
    SLEEPER("Y"),
    /**
     *  일반 계정
     */
    UNSLEEPER("N");

    private final String state;

    Account(String state){
        this.state = state;
    }
}
