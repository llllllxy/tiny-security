package org.tinycloud.security.session;

/**
 * {@link SingleSessionRepository} 的契约测试（TCK 子类）。
 *
 * @author liuxingyu01
 */
class SingleSessionRepositoryContractTest extends SessionRepositoryContractTest {

    @Override
    protected SessionRepository createRepository() {
        return new SingleSessionRepository();
    }

    @Override
    protected void destroyRepository(SessionRepository repository) {
        ((SingleSessionRepository) repository).destroy();
    }
}
