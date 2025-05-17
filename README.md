# 클라우드 퍼포먼스 최적화 프로젝트

## 프로젝트 기본 정보

* 기간: 2025.04.18 \~ 2025.05.16
* 인원: 4명 (BE 2, FE 2)
* 주제: 자동 오류 감지 및 트랜잭션 무결성 확보

## 목표

* 클라우드 네이티브 기반 오류 감지 및 트랜잭션 무결성 시스템 구현
* 자동화된 CI/CD 파이프라인과 보안 강화 모델 적용
* 실시간 모니터링, 장애 대응 및 비용 최적화 구조 수립

## 기술 스택 및 협업 전략

### ▶ 프론트엔드 (Client)

* 언어: React(TypeScript), Axios
* 인프라: AWS S3, CloudFront
* 정적 분석: ESLint, Husky

### ▶ 백엔드 (API 서버)

* 언어: Spring Boot, Docker
* 인프라: ECS Fargate, ALB, Multi-AZ 기반 Private Subnet
* 데이터베이스: Aurora Serverless, Redis

### ▶ CI/CD 및 보안

* GitHub + Jenkins 연동 (Webhook 기반)
* 정적 분석: ESLint, SonarLint + Pre-commit Hook
* 동적 분석: OWASP ZAP 자동 스캔 포함
* 배포: ECS Fargate 자동 배포, 실패 시 롤백 처리
* 보안: WAF, MFA, Redis 토큰 관리, VPC Endpoint 구성

## 구현 내용 요약

### ▶ 트랜잭션 무결성

* Aurora 기반 고가용성 구성
* Redis 기반 Refresh Token 처리
* MFA + SameSite Cookie + CSRF 방지 적용
* 예외 발생 시 트랜잭션 롤백 + Slack 알림
* 계층별 UUID 기반 traceId 로그 처리

### ▶ 자동 오류 감지

* SonarLint + ESLint 기반 사전 정적 분석
* ZAP 보안 스캔 자동화 (고위험 0건, 저위험 3건)
* WAF 차단 비율: 3,080건 중 1,280건 차단 (82.84%)

### ▶ 비용 최적화 전략

* AWS Compute Optimizer / Trusted Advisor 분석
* AWS Budgets 설정 (\$60 예산 기준, 80% 초과 시 알림)
* ECR 미사용 이미지 30일 후 자동 삭제
* CloudWatch Logs + Firehose + S3 + Glacier 구조로 로그 통합

## 현황 및 결과

* GitHub Actions 미사용 환경에서 Jenkins + Pre-commit Hook으로 DevSecOps 구축
* 중복 코드 제거 및 예외처리 일관성 확보
* WAF를 통한 실시간 공격 차단 및 로그 기반 분석 완료
* 정적 + 동적 분석 기반으로 코드 품질 및 보안 선제 대응

## 효과 및 보안 가치

* S3에 주기적 보존 + Glacier 전환으로 로그 장기 관리
* 유휴 EC2 및 EBS, 과소 할당 Lambda에 대한 사용 분석 수행
* MFA + Redis + WAF 조합으로 애플리케이션 레벨까지 방어 계층 구성
* Dev 단계 → 운영 단계까지 보안 흐름 일관성 유지

## 향후 계획

* AWS CUR + Athena 통한 세부 비용 분석 도입 검토
* 다운사이징 ROI가 낮은 인스턴스는 현 상태 유지
* Glacier 보존 정책 정착 및 자동화 운영 강화

## 📊 주요 성과 요약

| 항목                         | 결과                                            |
| -------------------------- | --------------------------------------------- |
| 🔐 **보안 차단률**              | 전체 요청 3,080건 중 1,280건 차단 (**82.84%**)         |
| 🧪 **OWASP ZAP 동적 보안 테스트** | 총 41개 URL 대상<br>고위험/중위험 취약점 **0건**, 저위험 3건    |
| 🔍 **SonarLint 정적 분석 결과**  | 총 이슈 51건 자동 탐지<br>17개 파일 분석                   |
| 🧹 **불필요 리소스 최적화**         | 유휴 EBS 1개 탐지 → 월 약 **\$0.73** 절감 가능           |
| 💸 **비용 경보 시스템**           | AWS Budgets 기준 **\$60 중 80% 초과 시 알림 설정 완료**   |
| 🗑️ **이미지 정리 정책**          | ECR에 대해 **30일 이상 미사용 이미지 자동 삭제 정책** 적용        |
| 🔄 **배포 자동화**              | Jenkins 기반 CI/CD 구축 + **배포 실패 시 자동 롤백** 전략 구현 |


## 시스템 아키텍처
<img width="1016" alt="image" src="https://github.com/user-attachments/assets/aa4459bb-c48a-4a27-b1ab-83ede24a2f6e" />

