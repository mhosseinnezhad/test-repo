package com.modernisc.security.keycloak.users;

import com.modernisc.security.keycloak.users.util.QuarkusUtil;
import io.agroal.api.configuration.supplier.AgroalDataSourceConfigurationSupplier;
import io.agroal.api.security.SimplePassword;
import org.keycloak.component.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.storage.UserStorageProviderFactory;
import org.wildfly.security.auth.principal.NamePrincipal;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.time.Duration;

import io.agroal.api.AgroalDataSource;


public class CbglUserStorageProviderFactory implements
        UserStorageProviderFactory<CbglUserStorageProvider> {

    public static final String PROVIDER_ID = "user-storage-spi";

    private AgroalDataSource dataSource;


    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        try {
            AgroalDataSourceConfigurationSupplier config = new AgroalDataSourceConfigurationSupplier()
                    .connectionPoolConfiguration(cp -> cp
                            .maxSize(10)                     // حداکثر 10 connection
                            .minSize(5)                      // ✅ حداقل 5 (مهم برای performance)
                            .initialSize(2)                  // 2 connection در startup

                            // ⏱️ زمان انتظار برای گرفتن Connection از Pool
                            .acquisitionTimeout(Duration.ofSeconds(30))  // ✅ 30 ثانیه کافی است

                            // ⏱️ زمان انتظار برای validate یک Connection
                            .validationTimeout(Duration.ofSeconds(5))    // ✅ 5 ثانیه

                            // ⏱️ Max lifetime یک Connection (قبل از بسته شدن)
                            .maxLifetime(Duration.ofMinutes(30))         // ✅ 30 دقیقه

                            // ⏱️ Idle timeout (اگر connection استفاده نشد، بسته شود)
                            .reapTimeout(Duration.ofMinutes(5))          // ✅ 5 دقیقه

                            // ⏱️ گزارش leak اگر connection بیش از X باز بماند
                            .leakTimeout(Duration.ofMinutes(5))          // ✅ 5 دقیقه

                            // 🔌 Oracle Connection Factory
                            .connectionFactoryConfiguration(cf -> cf
                                    .jdbcUrl(QuarkusUtil.getProperty("cbgl.persistence.jdbc.url"))

                                    .principal(new NamePrincipal(
                                            QuarkusUtil.getProperty("cbgl.persistence.jdbc.user")))
                                    .credential(new SimplePassword(
                                            QuarkusUtil.getProperty("cbgl.persistence.jdbc.password")))

                                    // ✅ Oracle-specific settings
                                    .loginTimeout(Duration.ofSeconds(30))       // 30 ثانیه برای login
                                    .autoCommit(false)                          // ✅ مهم: برای تراکنش
                                    .trackJdbcResources(true)                   // Track open statements

                                    // Oracle performance tuning
                                    .jdbcProperty("oracle.jdbc.defaultRowPrefetch", "20")
                                    .jdbcProperty("oracle.jdbc.defaultBatchValue", "10")
                            )
                    );

            dataSource =  AgroalDataSource.from(config);


            try (var conn = dataSource.getConnection()) {
                if (!conn.isValid(5)) {
                    throw new SQLException("Initial connection validation failed");
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }



    @Override
    public CbglUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        return new CbglUserStorageProvider( session, model, dataSource);
    }

    @Override
    public void close() {

    }

}
