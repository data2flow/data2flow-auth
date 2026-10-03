package net.java21.data2flow.auth;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import net.java21.data2flow.contracts.test.arch.Data2flowArchRules;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * 코드 구조 규칙(design/testing/backend.md §6, IAM-07.02).
 * TC-IAM-187(AT-IAM-21.7): JWT 해석 라이브러리는 auth의 토큰 도메인({@code token.domain})에서만 쓴다. 다른 서비스에 같은 규칙을
 * 두는 것은 각 서비스 몫이고, auth 안에서도 JWT 원문을 해석하는 곳을 한 군데로 묶는다.
 */
@AnalyzeClasses(packages = "net.java21.data2flow.auth", importOptions = ImportOption.DoNotIncludeTests.class)
class ArchitectureTest {

    @ArchTest
    static final ArchRule organizationScoped = Data2flowArchRules.REPOSITORY_QUERIES_ARE_ORGANIZATION_SCOPED;
    @ArchTest
    static final ArchRule noUnscopedCrud = Data2flowArchRules.UNSCOPED_CRUD_LOOKUPS_ARE_NOT_CALLED;
    @ArchTest
    static final ArchRule noSleep = Data2flowArchRules.NO_THREAD_SLEEP;
    @ArchTest
    static final ArchRule noSystemClock = Data2flowArchRules.NO_SYSTEM_CLOCK;

    /** [IAM-07.02][TC-IAM-187][AT-IAM-21.7] JWT 라이브러리는 token.domain 밖에서 쓰지 않는다 */
    @ArchTest
    static final ArchRule jwtParsingIsConfined = noClasses()
            .that().resideOutsideOfPackage("net.java21.data2flow.auth.token.domain..")
            .should().dependOnClassesThat().resideInAnyPackage("com.nimbusds..")
            .because("JWT를 해석하는 곳은 인증 서비스의 토큰 도메인 한 곳뿐이다(BR-IAM-36)");

    /** 도메인은 Spring에 의존하지 않는다 */
    @ArchTest
    static final ArchRule domainIsFrameworkFree = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAnyPackage("org.springframework..");

    /** controller → service → repository 방향만 */
    @ArchTest
    static final ArchRule repositoriesDoNotUseServices = noClasses()
            .that().resideInAPackage("..repository..")
            .should().dependOnClassesThat().resideInAnyPackage("..service..", "..controller..");

    @ArchTest
    static final ArchRule servicesDoNotUseControllers = noClasses()
            .that().resideInAPackage("..service..")
            .should().dependOnClassesThat().resideInAPackage("..controller..");
}
