package com.modernisc.security.keycloak.iam.dto.mapper;

import com.modernisc.security.keycloak.iam.dto.UserInfo;
import com.modernisc.security.keycloak.iam.kc.CustomUser;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class UserMapper {

    private static final ZoneId DEFAULT_ZONE = ZoneId.systemDefault();

    /**
     * تبدیل UserInfo (با Date) به UserIDto (با LocalDateTime)
     */
    public static CustomUser toDto(UserInfo userInfo) {
        if (userInfo == null) return null;

        CustomUser dto = new CustomUser();
        try {
            dto.setId(userInfo.getId());
            dto.setUsername(userInfo.getUsername());
            dto.setMaxTryCount(userInfo.getMaxTryCount());
            dto.setPasswordExpirationDate(userInfo.getPasswordExpirationDate());
            dto.setCredentialsExpired(userInfo.isCredentialsExpired());
            dto.setEnabled(userInfo.getEnabled());
            dto.setCreatedTimeStamp(userInfo.getCreatedTimeStamp());
            dto.setModifiedTimeStamp(userInfo.getModifiedTimeStamp());
            dto.setFirstName(userInfo.getFirstName());
            dto.setLastName(userInfo.getLastName());
            dto.setEmail(userInfo.getEmail());
            dto.setEmailVerified(userInfo.getEmailVerified());
            dto.setTemporary(userInfo.getTemporary());
            dto.setUuid(userInfo.getUuid());
        }catch (Exception e){
            e.printStackTrace();
        }
        return dto;
    }

    /**
     * تبدیل UserIDto (با LocalDateTime) به UserInfo (با Date)
     */
    public static UserInfo toEntity(CustomUser dto) {
        if (dto == null) return null;
        UserInfo userInfo = new UserInfo();
        try {

            userInfo.setId(dto.getId());
            userInfo.setUsername(dto.getUsername());
            userInfo.setMaxTryCount(dto.getMaxTryCount());
            userInfo.setPasswordExpirationDate(dto.getPasswordExpirationDate());
            userInfo.setCredentialsExpired(dto.isCredentialsExpired());
            userInfo.setEnabled(dto.getEnabled());
            userInfo.setCreatedTimeStamp(dto.getCreatedTimeStamp());
            userInfo.setModifiedTimeStamp(dto.getModifiedTimeStamp());
            userInfo.setFirstName(dto.getFirstName());
            userInfo.setLastName(dto.getLastName());
            userInfo.setEmail(dto.getEmail());
            userInfo.setEmailVerified(dto.getEmailVerified());
            userInfo.setTemporary(dto.getTemporary());
            userInfo.setUuid(dto.getUuid());
        } catch (Exception e){
            e.printStackTrace();
        }
        return userInfo;
    }

    /**
     * تبدیل Date به LocalDateTime
     */
    private static LocalDateTime dateToLocalDateTime(Date date) {
        if (date == null) return null;
        return date.toInstant().atZone(DEFAULT_ZONE).toLocalDateTime();
    }

    /**
     * تبدیل LocalDateTime به Date
     */
    private static Date localDateTimeToDate(LocalDateTime localDateTime) {
        if (localDateTime == null) return null;
        return Date.from(localDateTime.atZone(DEFAULT_ZONE).toInstant());
    }
}