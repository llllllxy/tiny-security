package org.tinycloud.security.session;

/**
 * {@link CaffeineSessionRepository} 的契约测试（TCK 子类）。
 *
 * @author liuxingyu01
 */
class CaffeineSessionRepositoryContractTest extends SessionRepositoryContractTest {

    @Override
    protected SessionRepository createRepository() {
        return new CaffeineSessionRepository(10000L);
    }

    @Override
    protected void destroyRepository(SessionRepository repository) {
        ((CaffeineSessionRepository) repository).destroy();
    }
}
