package hello.Login.model;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class BoardDto {
    private int boardSq;
    private String userNm;
    private String boardTitle;
    private String boardContent;

    @Builder
    public BoardDto(int boardSq, String userNm, String boardTitle, String boardContent) {
        this.boardSq = boardSq;
        this.userNm = userNm;
        this.boardTitle = boardTitle;
        this.boardContent = boardContent;
    }
}
