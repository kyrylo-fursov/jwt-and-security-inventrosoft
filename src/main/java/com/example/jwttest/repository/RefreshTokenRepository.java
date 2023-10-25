package com.example.jwttest.repository;

import com.example.jwttest.entity.RefreshTokenEntity;
import com.example.jwttest.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    RefreshTokenEntity findByToken(String token);

    @Query(value="SELECT u.* FROM USER_INFO u INNER JOIN REFRESH_TOKEN_ENTITY r ON u.ID = r.USER_ID WHERE r.TOKEN = :token", nativeQuery=true)
    List<Object[]> findUserByTokenRaw(@Param("token") String token);

    default UserInfo findUserByToken(String token) {
        List<Object[]> rows = findUserByTokenRaw(token);
        if (rows.isEmpty()) {
            return null;
        }
        Object[] row = rows.get(0);
        UserInfo user = new UserInfo();
        user.setId((int) row[0]);
        user.setEmail((String) row[1]);
        user.setName((String) row[2]);
        user.setPassword((String) row[3]);
        user.setRoles((String) row[4]);

        return user;
    }

    @Modifying
    @Transactional
    void deleteByToken(String token);

    @Modifying
    @Transactional
    void deleteByUser(UserInfo user);

    default boolean validateAndRemove(String token) {
        RefreshTokenEntity refreshTokenEntity = findByToken(token);
        if (refreshTokenEntity != null) {
            deleteByToken(token);
            return true;
        }
        return false;
    }
}