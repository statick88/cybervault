/**
 * Resource Use Cases — Plus Domain
 *
 * CRUD operations for Resources (stable infrastructure identifiers)
 */

import type { IResourceRepository } from "../../domain/repositories";
import { Resource } from "../../domain/entities/resource";
import type { ResourceType, ResourceEnvironment, ResourceCriticality } from "../../domain/entities/resource";

export interface ResourceCreateInput {
  id: string;
  name: string;
  type: ResourceType;
  endpoint: string;
  environment: ResourceEnvironment;
  criticality: ResourceCriticality;
  description?: string;
  tags?: string[];
  ownerTeam?: string;
  metadata?: Record<string, unknown>;
}

export interface ResourceUpdateInput {
  name?: string;
  endpoint?: string;
  environment?: ResourceEnvironment;
  criticality?: ResourceCriticality;
  description?: string;
  tags?: string[];
  ownerTeam?: string;
  metadata?: Record<string, unknown>;
  active?: boolean;
}

export interface ResourceSearchCriteria {
  name?: string;
  type?: ResourceType;
  environment?: ResourceEnvironment;
  criticality?: ResourceCriticality;
  tags?: string[];
  active?: boolean;
  limit?: number;
  offset?: number;
}

export class ResourceUseCase {
  constructor(private resourceRepository: IResourceRepository) {}

  async create(input: ResourceCreateInput): Promise<Resource> {
    // Validate criticality
    const validCriticalities: ResourceCriticality[] = ["low", "medium", "high", "critical"];
    if (!validCriticalities.includes(input.criticality)) {
      throw new Error(`Invalid criticality: ${input.criticality}`);
    }

    // Validate environment
    const validEnvironments: ResourceEnvironment[] = ["production", "staging", "development", "testing", "dr"];
    if (!validEnvironments.includes(input.environment)) {
      throw new Error(`Invalid environment: ${input.environment}`);
    }

    // Validate type
    const validTypes: ResourceType[] = [
      "web", "ssh", "rdp", "vpn", "database", "kubernetes",
      "microservice", "firewall", "backup", "drp", "other"
    ];
    if (!validTypes.includes(input.type)) {
      throw new Error(`Invalid resource type: ${input.type}`);
    }

    const resource = Resource.create({
      id: input.id,
      name: input.name,
      type: input.type,
      endpoint: input.endpoint,
      environment: input.environment,
      criticality: input.criticality,
      description: input.description,
      tags: input.tags,
      ownerTeam: input.ownerTeam,
      metadata: input.metadata,
    });

    return await this.resourceRepository.save(resource);
  }

  async getById(id: string): Promise<Resource | null> {
    return await this.resourceRepository.findById(id);
  }

  async update(id: string, input: ResourceUpdateInput): Promise<Resource | null> {
    const resource = await this.resourceRepository.findById(id);
    if (!resource) return null;

    if (input.name !== undefined) {
      // Update name via props directly (Resource doesn't have updateTitle)
      (resource as any).props.name = input.name;
      (resource as any).props.updatedAt = new Date();
    }
    if (input.endpoint !== undefined) resource.updateEndpoint(input.endpoint);
    if (input.environment !== undefined) resource.updateEnvironment(input.environment);
    if (input.criticality !== undefined) resource.updateCriticality(input.criticality);
    if (input.description !== undefined) {
      (resource as any).props.description = input.description;
      (resource as any).props.updatedAt = new Date();
    }
    if (input.tags !== undefined) {
      (resource as any).props.tags = [...input.tags];
      (resource as any).props.updatedAt = new Date();
    }
    if (input.ownerTeam !== undefined) {
      (resource as any).props.ownerTeam = input.ownerTeam;
      (resource as any).props.updatedAt = new Date();
    }
    if (input.metadata !== undefined) resource.updateMetadata(input.metadata);
    if (input.active !== undefined) resource.setActive(input.active);

    return await this.resourceRepository.save(resource);
  }

  async delete(id: string): Promise<boolean> {
    return await this.resourceRepository.delete(id);
  }

  async list(criteria: ResourceSearchCriteria = {}): Promise<{ resources: Resource[]; total: number }> {
    return await this.resourceRepository.search(criteria);
  }

  async findByType(type: ResourceType): Promise<Resource[]> {
    return await this.resourceRepository.findByType(type);
  }

  async findByEnvironment(env: ResourceEnvironment): Promise<Resource[]> {
    return await this.resourceRepository.findByEnvironment(env);
  }

  async findByCriticality(criticality: ResourceCriticality): Promise<Resource[]> {
    return await this.resourceRepository.findByCriticality(criticality);
  }

  async findActive(): Promise<Resource[]> {
    return await this.resourceRepository.findActive();
  }
}

// Add missing methods to Resource entity (for use case compatibility)
// These would be added to the Resource entity class