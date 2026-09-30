export { ChromeStorageVaultRepository } from "./ChromeStorageVaultRepository";
export { InMemoryVulnerabilityRepository } from "./InMemoryVulnerabilityRepository";
export { InMemoryReleaseShareStore } from "./InMemoryReleaseShareStore";
export { PostgresVaultRepository } from "./PostgresVaultRepository";
export { PostgresCredentialRepository } from "./PostgresCredentialRepository";
export { PostgresReleaseShareStore } from "./PostgresReleaseShareStore";
export {
  createReleaseShareStore,
  type ReleaseShareStoreEnv,
} from "./release-share-store-factory";
export {
  createStepUpProofStores,
  type StepUpProofStoreEnv,
  type StepUpProofStores,
} from "./step-up-proof-store-factory";

// Tipos de repositorios para facilitar la inyección de dependencias
export type {
  IVaultRepository,
  ICredentialRepository,
  IVulnerabilityRepository,
  IReleaseShareStore,
  WrappedReleaseShare,
  IStepUpApprovalChallengeStore,
  IStepUpAuthenticatorStore,
  StepUpApprovalChallenge,
  StepUpAuthenticator,
} from "../../domain/repositories";
