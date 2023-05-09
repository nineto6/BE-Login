drop table tb_board cascade;

create table tb_board(
   board_sq int auto_increment primary key,
   user_nm varchar(20) not null,
   board_title varchar(30) not null,
   board_content varchar(1000) not null
);