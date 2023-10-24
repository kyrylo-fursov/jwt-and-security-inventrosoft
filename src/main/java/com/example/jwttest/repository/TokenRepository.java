package com.example.jwttest.repository;

import com.example.jwttest.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface TokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    RefreshTokenEntity findByToken(String token);

    // Delete a RefreshTokenEntity by the token string.
    @Modifying
    @Transactional
    void deleteByToken(String token);

    // Validate and remove the token
    default boolean validateAndRemove(String token) {
        RefreshTokenEntity refreshTokenEntity = findByToken(token);
        if (refreshTokenEntity != null) {
            deleteByToken(token);
            return true;
        }
        return false;
    }
}