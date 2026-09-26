/**
 * Resource Entity — Stable Resource Identification for CyberVault Plus
 *
 * Resources are logical entities (not IPs) that represent technical assets.
 * Resource ID is stable and does not change when endpoint/IP changes.
 *
 * Example:
 *   resourceId: "db-prod-001"
 *   current endpoint: "db01.internal.example:5432"
 *   If IP changes tomorrow, resourceId stays "db-prod-001"
 */

export type ResourceType =
  | "web"
  | "ssh"
  | "rdp"
  | "vpn"
  | "database"
  | "kubernetes"
  | "microservice"
  | "firewall"
  | "backup"
  | "drp"
  | "other";

export type ResourceEnvironment =
  | "production"
  | "staging"
  | "development"
  | "testing"
  | "dr";

export type ResourceCriticality =
  | "low"
  | "medium"
  | "high"
  | "critical";

export interface ResourceProps {
  id: string; // Stable resource ID (e.g., "db-prod-001")
  name: string; // Human-readable name
  type: ResourceType;
  endpoint: string; // Current endpoint (host:port, URL, etc.)
  environment: ResourceEnvironment;
  criticality: ResourceCriticality;
  description?: string;
  tags: string[]; // For grouping/filtering
  ownerTeam?: string; // Team responsible
  metadata?: Record<string, unknown>; // Extensible metadata
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export class Resource {
  private readonly props: ResourceProps;

  constructor(props: ResourceProps) {
    this.props = { ...props };
  }

  // Getters
  get id(): string {
    return this.props.id;
  }

  get name(): string {
    return this.props.name;
  }

  get type(): ResourceType {
    return this.props.type;
  }

  get endpoint(): string {
    return this.props.endpoint;
  }

  get environment(): ResourceEnvironment {
    return this.props.environment;
  }

  get criticality(): ResourceCriticality {
    return this.props.criticality;
  }

  get description(): string | undefined {
    return this.props.description;
  }

  get tags(): string[] {
    return [...this.props.tags];
  }

  get ownerTeam(): string | undefined {
    return this.props.ownerTeam;
  }

  get metadata(): Record<string, unknown> | undefined {
    return this.props.metadata ? JSON.parse(JSON.stringify(this.props.metadata)) : undefined;
  }

  get active(): boolean {
    return this.props.active;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get updatedAt(): Date {
    return this.props.updatedAt;
  }

  // Business methods
  updateEndpoint(newEndpoint: string): void {
    this.props.endpoint = newEndpoint;
    this.props.updatedAt = new Date();
  }

  updateCriticality(newCriticality: ResourceCriticality): void {
    this.props.criticality = newCriticality;
    this.props.updatedAt = new Date();
  }

  updateEnvironment(newEnvironment: ResourceEnvironment): void {
    this.props.environment = newEnvironment;
    this.props.updatedAt = new Date();
  }

  setActive(active: boolean): void {
    this.props.active = active;
    this.props.updatedAt = new Date();
  }

  addTag(tag: string): void {
    if (!this.props.tags.includes(tag)) {
      this.props.tags.push(tag);
      this.props.updatedAt = new Date();
    }
  }

  removeTag(tag: string): void {
    const index = this.props.tags.indexOf(tag);
    if (index > -1) {
      this.props.tags.splice(index, 1);
      this.props.updatedAt = new Date();
    }
  }

  updateMetadata(metadata: Record<string, unknown>): void {
    this.props.metadata = { ...this.props.metadata, ...metadata };
    this.props.updatedAt = new Date();
  }

  // Factory methods
  static create(props: {
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
  }): Resource {
    const now = new Date();
    return new Resource({
      id: props.id,
      name: props.name,
      type: props.type,
      endpoint: props.endpoint,
      environment: props.environment,
      criticality: props.criticality,
      description: props.description,
      tags: props.tags || [],
      ownerTeam: props.ownerTeam,
      metadata: props.metadata,
      active: true,
      createdAt: now,
      updatedAt: now,
    });
  }

  static fromPlainObject(obj: {
    id: string;
    name: string;
    type: ResourceType;
    endpoint: string;
    environment: ResourceEnvironment;
    criticality: ResourceCriticality;
    description?: string;
    tags: string[];
    ownerTeam?: string;
    metadata?: Record<string, unknown>;
    active: boolean;
    createdAt: string;
    updatedAt: string;
  }): Resource {
    return new Resource({
      id: obj.id,
      name: obj.name,
      type: obj.type,
      endpoint: obj.endpoint,
      environment: obj.environment,
      criticality: obj.criticality,
      description: obj.description,
      tags: obj.tags,
      ownerTeam: obj.ownerTeam,
      metadata: obj.metadata,
      active: obj.active,
      createdAt: new Date(obj.createdAt),
      updatedAt: new Date(obj.updatedAt),
    });
  }

  toPlainObject(): {
    id: string;
    name: string;
    type: ResourceType;
    endpoint: string;
    environment: ResourceEnvironment;
    criticality: ResourceCriticality;
    description?: string;
    tags: string[];
    ownerTeam?: string;
    metadata?: Record<string, unknown>;
    active: boolean;
    createdAt: string;
    updatedAt: string;
  } {
    return {
      id: this.props.id,
      name: this.props.name,
      type: this.props.type,
      endpoint: this.props.endpoint,
      environment: this.props.environment,
      criticality: this.props.criticality,
      description: this.props.description,
      tags: [...this.props.tags],
      ownerTeam: this.props.ownerTeam,
      metadata: this.props.metadata ? JSON.parse(JSON.stringify(this.props.metadata)) : undefined,
      active: this.props.active,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
    };
  }

  toSafeObject(): {
    id: string;
    name: string;
    type: ResourceType;
    environment: ResourceEnvironment;
    criticality: ResourceCriticality;
    description?: string;
    tags: string[];
    active: boolean;
    createdAt: string;
    updatedAt: string;
  } {
    return {
      id: this.props.id,
      name: this.props.name,
      type: this.props.type,
      environment: this.props.environment,
      criticality: this.props.criticality,
      description: this.props.description,
      tags: [...this.props.tags],
      active: this.props.active,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
    };
  }
}