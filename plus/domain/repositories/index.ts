/**
 * Plus Domain Repository Interfaces
 *
 * Ports for Plus domain entities persistence.
 * Implementations live in plus/infrastructure/repositories/
 */

import type { Resource } from "../entities/resource";
import type { Entitlement } from "../entities/entitlement";
import type { PlusUser } from "../entities/user";
import type { ResourceType, ResourceEnvironment, ResourceCriticality } from "../entities/resource";
import type { PestilloState } from "../entities/entitlement";

export interface IResourceRepository {
  save(resource: Resource): Promise<Resource>;
  findById(id: string): Promise<Resource | null>;
  findByType(type: ResourceType): Promise<Resource[]>;
  findByEnvironment(env: ResourceEnvironment): Promise<Resource[]>;
  findByCriticality(criticality: ResourceCriticality): Promise<Resource[]>;
  findActive(): Promise<Resource[]>;
  search(criteria: {
    name?: string;
    type?: ResourceType;
    environment?: ResourceEnvironment;
    criticality?: ResourceCriticality;
    tags?: string[];
    active?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<{ resources: Resource[]; total: number }>;
  delete(id: string): Promise<boolean>;
  list(): Promise<Resource[]>;
  isHealthy(): Promise<boolean>;
  close(): Promise<void>;
}

export interface IEntitlementRepository {
  save(entitlement: Entitlement): Promise<Entitlement>;
  findById(id: string): Promise<Entitlement | null>;
  findByUserId(userId: string): Promise<Entitlement[]>;
  findByResourceId(resourceId: string): Promise<Entitlement[]>;
  findByUserAndResource(userId: string, resourceId: string): Promise<Entitlement | null>;
  findByPestilloState(state: PestilloState): Promise<Entitlement[]>;
  findExpiringSoon(withinMs: number): Promise<Entitlement[]>;
  search(criteria: {
    userId?: string;
    resourceId?: string;
    pestilloState?: PestilloState;
    activeOnly?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<{ entitlements: Entitlement[]; total: number }>;
  delete(id: string): Promise<boolean>;
  list(): Promise<Entitlement[]>;
  isHealthy(): Promise<boolean>;
  close(): Promise<void>;
}

export interface IPlusUserRepository {
  save(user: PlusUser): Promise<PlusUser>;
  findById(id: string): Promise<PlusUser | null>;
  findByEmail(email: string): Promise<PlusUser | null>;
  findByRole(role: string): Promise<PlusUser[]>;
  findActive(): Promise<PlusUser[]>;
  search(criteria: {
    name?: string;
    email?: string;
    role?: string;
    active?: boolean;
    habitualCountry?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ users: PlusUser[]; total: number }>;
  delete(id: string): Promise<boolean>;
  list(): Promise<PlusUser[]>;
  isHealthy(): Promise<boolean>;
  close(): Promise<void>;
}

export interface IChallengeRepository {
  save(challenge: any): Promise<any>;
  findById(id: string): Promise<any | null>;
  findByUserId(userId: string): Promise<any[]>;
  findPendingByUserId(userId: string): Promise<any[]>;
  update(challenge: any): Promise<any>;
  delete(id: string): Promise<boolean>;
  cleanupExpired(): Promise<number>;
}