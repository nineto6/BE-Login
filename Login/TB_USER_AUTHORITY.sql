drop table tb_user_authority cascade;

create table tb_user_authority(
   user_auth_sq        INT AUTO_INCREMENT PRIMARY KEY,
   user_sq             INT NOT NULL,
   user_id             VARCHAR(20) NOT NULL,
   user_authority      VARCHAR(20) NOT NULL,
   FOREIGN KEY (user_sq) REFERENCES TB_USER(user_sq) ON DELETE CASCADE
);