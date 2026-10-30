package dev.sovra.tenancy;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Tenant-scoped datasource. Every borrowed connection requires an
 * authenticated context and pins PostgreSQL row-level security to that
 * tenant; the setting is reset before the connection returns to the pool.
 * Global (cross-tenant) reads must use the plain datasource explicitly.
 *
 * <p>The wrapper is transaction-aware: inside a Spring transaction it
 * joins the transaction's connection (so tenant writes commit atomically
 * with the caller's work) and resets the pin when the transaction
 * completes, on commit and on rollback alike. Outside a transaction it
 * borrows directly and resets on close.
 */
public class TenantDataSource extends DelegatingDataSource {

  private static final Object PIN_KEY = new Object();

  public TenantDataSource(DataSource target) {
    super(target);
  }

  @Override
  public Connection getConnection() throws SQLException {
    // Require context before borrowing: a fail-closed check must not consume
    // (and leak) a pooled connection on its way to throwing.
    UUID tenantId = TenantContext.require().tenantId();
    if (TransactionSynchronizationManager.isSynchronizationActive()) {
      return transactionalConnection(tenantId);
    }
    return pin(super.getConnection(), tenantId, true);
  }

  @Override
  public Connection getConnection(String username, String password) throws SQLException {
    UUID tenantId = TenantContext.require().tenantId();
    // Documented non-transactional path: credentials address the pool
    // directly, so this borrow never joins a Spring transaction.
    return pin(super.getConnection(username, password), tenantId, true);
  }

  private Connection transactionalConnection(UUID tenantId) throws SQLException {
    DataSource target = getTargetDataSource();
    Connection delegate = DataSourceUtils.getConnection(target);
    try {
      setTenant(delegate, tenantId);
    } catch (SQLException | RuntimeException e) {
      DataSourceUtils.releaseConnection(delegate, target);
      throw e;
    }
    if (TransactionSynchronizationManager.isActualTransactionActive()
        && TransactionSynchronizationManager.getResource(PIN_KEY) == null) {
      TransactionSynchronizationManager.bindResource(PIN_KEY, Boolean.TRUE);
      TransactionSynchronizationManager.registerSynchronization(new ResetOnCompletion(delegate));
    }
    return proxy(delegate, target, false);
  }

  private Connection pin(Connection delegate, UUID tenantId, boolean resetOnClose)
      throws SQLException {
    try {
      setTenant(delegate, tenantId);
    } catch (SQLException | RuntimeException e) {
      try {
        delegate.close();
      } catch (SQLException closeFailure) {
        e.addSuppressed(closeFailure);
      }
      throw e;
    }
    return proxy(delegate, getTargetDataSource(), resetOnClose);
  }

  private static void setTenant(Connection delegate, UUID tenantId) throws SQLException {
    try (Statement stmt = delegate.createStatement()) {
      // Tenant ID comes from a parsed UUID, so it cannot inject SQL.
      stmt.execute("SET app.tenant = '" + tenantId + "'");
    }
  }

  private static void resetTenant(Connection delegate) throws SQLException {
    try (Statement stmt = delegate.createStatement()) {
      stmt.execute("RESET app.tenant");
    }
  }

  private static Connection proxy(Connection delegate, DataSource target, boolean resetOnClose) {
    return (Connection)
        Proxy.newProxyInstance(
            Connection.class.getClassLoader(),
            new Class<?>[] {Connection.class},
            (proxy, method, args) -> {
              if (method.getName().equals("close")) {
                if (resetOnClose) {
                  try {
                    resetTenant(delegate);
                  } finally {
                    delegate.close();
                  }
                } else {
                  DataSourceUtils.releaseConnection(delegate, target);
                }
                return null;
              }
              return method.invoke(delegate, args);
            });
  }

  /**
   * Resets the tenant pin when the transaction completes. Spring runs
   * synchronizations before the connection returns to the pool, so the
   * next borrower never inherits this transaction's tenant.
   */
  private static final class ResetOnCompletion implements TransactionSynchronization {
    private final Connection delegate;

    ResetOnCompletion(Connection delegate) {
      this.delegate = delegate;
    }

    @Override
    public void suspend() {
      // REQUIRES_NEW must register cleanup for its own connection,
      // rather than inheriting the suspended transaction's marker.
      TransactionSynchronizationManager.unbindResource(PIN_KEY);
    }

    @Override
    public void resume() {
      TransactionSynchronizationManager.bindResource(PIN_KEY, Boolean.TRUE);
    }

    @Override
    public void afterCompletion(int status) {
      TransactionSynchronizationManager.unbindResourceIfPossible(PIN_KEY);
      try {
        if (!delegate.isClosed()) {
          resetTenant(delegate);
        }
      } catch (SQLException e) {
        throw new IllegalStateException("tenant pin was not reset after commit", e);
      }
    }
  }
}
