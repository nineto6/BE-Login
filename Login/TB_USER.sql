drop table tb_user cascade;

create table tb_user(
   user_sq        int auto_increment primary key,
   user_id         varchar(20) not null,
   user_pw       varchar(60) not null,
   user_nm       varchar(20) not null,
   user_st         varchar(1) not null
);