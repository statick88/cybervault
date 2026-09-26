/**
 * Plus User Entity — Technical/Infrastructure User for CyberVault Plus
 *
 * Distinct from Core account user. Plus users are technical operators
 * (DevOps, SRE, DBAs, admins) who need access to infrastructure credentials.
 */

export type UserRole =
  | "admin"
  | "operator"
  | "viewer"
  | "auditor";

export interface PlusUserProps {
  id: string;
  email: string; // Corporate email
  name: string; // Full name
  role: UserRole;
  habitualCountries: string[]; // ISO 3166-1 alpha-2 codes (e.g., ["EC", "US"])
  timezone: string; // IANA timezone (e.g., "America/Guayaquil")
  active: boolean;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date;
}

export class PlusUser {
  private readonly props: PlusUserProps;

  constructor(props: PlusUserProps) {
    this.props = { ...props };
  }

  // Getters
  get id(): string {
    return this.props.id;
  }

  get email(): string {
    return this.props.email;
  }

  get name(): string {
    return this.props.name;
  }

  get role(): UserRole {
    return this.props.role;
  }

  get habitualCountries(): string[] {
    return [...this.props.habitualCountries];
  }

  get timezone(): string {
    return this.props.timezone;
  }

  get active(): boolean {
    return this.props.active;
  }

  get metadata(): Record<string, unknown> | undefined {
    return this.props.metadata ? JSON.parse(JSON.stringify(this.props.metadata)) : undefined;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get updatedAt(): Date {
    return this.props.updatedAt;
  }

  get lastLoginAt(): Date | undefined {
    return this.props.lastLoginAt;
  }

  // Business methods
  updateProfile(data: { name?: string; role?: UserRole; timezone?: string }): void {
    if (data.name !== undefined) this.props.name = data.name;
    if (data.role !== undefined) this.props.role = data.role;
    if (data.timezone !== undefined) this.props.timezone = data.timezone;
    this.props.updatedAt = new Date();
  }

  addHabitualCountry(countryCode: string): void {
    const upper = countryCode.toUpperCase();
    if (!this.props.habitualCountries.includes(upper)) {
      this.props.habitualCountries.push(upper);
      this.props.updatedAt = new Date();
    }
  }

  removeHabitualCountry(countryCode: string): void {
    const upper = countryCode.toUpperCase();
    const index = this.props.habitualCountries.indexOf(upper);
    if (index > -1) {
      this.props.habitualCountries.splice(index, 1);
      this.props.updatedAt = new Date();
    }
  }

  setActive(active: boolean): void {
    this.props.active = active;
    this.props.updatedAt = new Date();
  }

  recordLogin(): void {
    this.props.lastLoginAt = new Date();
  }

  updateMetadata(metadata: Record<string, unknown>): void {
    this.props.metadata = { ...this.props.metadata, ...metadata };
    this.props.updatedAt = new Date();
  }

  // Risk context helpers
  isCountryHabitual(countryCode: string): boolean {
    return this.props.habitualCountries.includes(countryCode.toUpperCase());
  }

  isActive(): boolean {
    return this.props.active;
  }

  hasRole(roles: UserRole | UserRole[]): boolean {
    const roleArray = Array.isArray(roles) ? roles : [roles];
    return roleArray.includes(this.props.role);
  }

  // Factory methods
  static create(props: {
    id: string;
    email: string;
    name: string;
    role: UserRole;
    habitualCountries?: string[];
    timezone?: string;
    metadata?: Record<string, unknown>;
  }): PlusUser {
    const now = new Date();
    return new PlusUser({
      id: props.id,
      email: props.email.toLowerCase(),
      name: props.name,
      role: props.role,
      habitualCountries: props.habitualCountries?.map((c) => c.toUpperCase()) || [],
      timezone: props.timezone || "UTC",
      active: true,
      metadata: props.metadata,
      createdAt: now,
      updatedAt: now,
    });
  }

  static fromPlainObject(obj: {
    id: string;
    email: string;
    name: string;
    role: UserRole;
    habitualCountries: string[];
    timezone: string;
    active: boolean;
    metadata?: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
    lastLoginAt?: string;
  }): PlusUser {
    return new PlusUser({
      id: obj.id,
      email: obj.email,
      name: obj.name,
      role: obj.role,
      habitualCountries: obj.habitualCountries,
      timezone: obj.timezone,
      active: obj.active,
      metadata: obj.metadata,
      createdAt: new Date(obj.createdAt),
      updatedAt: new Date(obj.updatedAt),
      lastLoginAt: obj.lastLoginAt ? new Date(obj.lastLoginAt) : undefined,
    });
  }

  toPlainObject(): {
    id: string;
    email: string;
    name: string;
    role: UserRole;
    habitualCountries: string[];
    timezone: string;
    active: boolean;
    metadata?: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
    lastLoginAt?: string;
  } {
    return {
      id: this.props.id,
      email: this.props.email,
      name: this.props.name,
      role: this.props.role,
      habitualCountries: [...this.props.habitualCountries],
      timezone: this.props.timezone,
      active: this.props.active,
      metadata: this.props.metadata ? JSON.parse(JSON.stringify(this.props.metadata)) : undefined,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
      lastLoginAt: this.props.lastLoginAt?.toISOString(),
    };
  }

  toSafeObject(): {
    id: string;
    email: string;
    name: string;
    role: UserRole;
    habitualCountries: string[];
    timezone: string;
    active: boolean;
    createdAt: string;
    updatedAt: string;
    lastLoginAt?: string;
  } {
    return {
      id: this.props.id,
      email: this.props.email,
      name: this.props.name,
      role: this.props.role,
      habitualCountries: [...this.props.habitualCountries],
      timezone: this.props.timezone,
      active: this.props.active,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
      lastLoginAt: this.props.lastLoginAt?.toISOString(),
    };
  }
}