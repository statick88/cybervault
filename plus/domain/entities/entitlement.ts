/**
 * Entitlement Entity — User × Resource Authorization Matrix
 *
 * Represents the authorization state for a specific user on a specific resource.
 * Includes pestillo state, allowed operations, and time-bounded validity.
 *
 * Pestillo States (as per security invariants):
 * - CLOSED: No capability, no Release Share, no secret access
 * - ENABLED: Can request allowed operations, adaptive risk applies
 * - STEP_UP: Third factor mandatory even with low risk
 * - TEMPORARY: Time-bounded authorization, auto-expires to CLOSED
 */

export type PestilloState = "closed" | "enabled" | "step_up" | "temporary";

export type CapabilityOperation =
  | "AUTOFILL"
  | "VIEW"
  | "TOTP"
  | "CONNECT"
  | "READ"
  | "ADMIN"
  | "BACKUP"
  | "RESTORE"
  | "ROTATE_SECRET"
  | "EDIT_SECRET"
  | "DELETE_SECRET"
  | "EXPORT_SECRET";

export interface EntitlementProps {
  id: string;
  userId: string;
  resourceId: string;
  pestilloState: PestilloState;
  allowedOperations: CapabilityOperation[];
  validFrom?: Date; // Optional start time
  validUntil?: Date; // Optional expiry (for TEMPORARY)
  metadata?: Record<string, unknown>; // Extensible (e.g., maxAssurance, custom conditions)
  createdAt: Date;
  updatedAt: Date;
  createdBy: string; // Admin user who created/modified
}

export class Entitlement {
  private readonly props: EntitlementProps;

  constructor(props: EntitlementProps) {
    this.props = { ...props };
  }

  // Getters
  get id(): string {
    return this.props.id;
  }

  get userId(): string {
    return this.props.userId;
  }

  get resourceId(): string {
    return this.props.resourceId;
  }

  get pestilloState(): PestilloState {
    return this.props.pestilloState;
  }

  get allowedOperations(): CapabilityOperation[] {
    return [...this.props.allowedOperations];
  }

  get validFrom(): Date | undefined {
    return this.props.validFrom;
  }

  get validUntil(): Date | undefined {
    return this.props.validUntil;
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

  get createdBy(): string {
    return this.props.createdBy;
  }

  // State evaluation
  isCurrentlyValid(now: Date = new Date()): boolean {
    // Check pestillo state
    if (this.props.pestilloState === "closed") return false;

    // Check time bounds
    if (this.props.validFrom && now < this.props.validFrom) return false;
    if (this.props.validUntil && now >= this.props.validUntil) return false;

    return true;
  }

  getEffectiveState(now: Date = new Date()): PestilloState {
    if (!this.isCurrentlyValid(now)) {
      return "closed"; // Expired temporary = effectively closed
    }
    return this.props.pestilloState;
  }

  // Operation checks
  isOperationAllowed(operation: CapabilityOperation): boolean {
    return this.props.allowedOperations.includes(operation);
  }

  requiresStepUp(): boolean {
    return this.props.pestilloState === "step_up";
  }

  isTemporary(): boolean {
    return this.props.pestilloState === "temporary";
  }

  // Business methods
  setPestilloState(state: PestilloState, validUntil?: Date): void {
    this.props.pestilloState = state;
    if (state === "temporary" && validUntil) {
      this.props.validUntil = validUntil;
    } else if (state !== "temporary") {
      this.props.validUntil = undefined;
    }
    this.props.updatedAt = new Date();
  }

  addOperation(operation: CapabilityOperation): void {
    if (!this.props.allowedOperations.includes(operation)) {
      this.props.allowedOperations.push(operation);
      this.props.updatedAt = new Date();
    }
  }

  removeOperation(operation: CapabilityOperation): void {
    const index = this.props.allowedOperations.indexOf(operation);
    if (index > -1) {
      this.props.allowedOperations.splice(index, 1);
      this.props.updatedAt = new Date();
    }
  }

  setOperations(operations: CapabilityOperation[]): void {
    this.props.allowedOperations = [...operations];
    this.props.updatedAt = new Date();
  }

  setValidity(validFrom?: Date, validUntil?: Date): void {
    this.props.validFrom = validFrom;
    this.props.validUntil = validUntil;
    this.props.updatedAt = new Date();
  }

  updateMetadata(metadata: Record<string, unknown>): void {
    this.props.metadata = { ...this.props.metadata, ...metadata };
    this.props.updatedAt = new Date();
  }

  // Factory methods
  static create(props: {
    userId: string;
    resourceId: string;
    pestilloState: PestilloState;
    allowedOperations: CapabilityOperation[];
    validFrom?: Date;
    validUntil?: Date;
    metadata?: Record<string, unknown>;
    createdBy: string;
  }): Entitlement {
    const now = new Date();
    return new Entitlement({
      id: `${props.userId}:${props.resourceId}`,
      userId: props.userId,
      resourceId: props.resourceId,
      pestilloState: props.pestilloState,
      allowedOperations: props.allowedOperations,
      validFrom: props.validFrom,
      validUntil: props.validUntil,
      metadata: props.metadata,
      createdAt: now,
      updatedAt: now,
      createdBy: props.createdBy,
    });
  }

  static fromPlainObject(obj: {
    id: string;
    userId: string;
    resourceId: string;
    pestilloState: PestilloState;
    allowedOperations: CapabilityOperation[];
    validFrom?: string;
    validUntil?: string;
    metadata?: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
    createdBy: string;
  }): Entitlement {
    return new Entitlement({
      id: obj.id,
      userId: obj.userId,
      resourceId: obj.resourceId,
      pestilloState: obj.pestilloState,
      allowedOperations: obj.allowedOperations,
      validFrom: obj.validFrom ? new Date(obj.validFrom) : undefined,
      validUntil: obj.validUntil ? new Date(obj.validUntil) : undefined,
      metadata: obj.metadata,
      createdAt: new Date(obj.createdAt),
      updatedAt: new Date(obj.updatedAt),
      createdBy: obj.createdBy,
    });
  }

  toPlainObject(): {
    id: string;
    userId: string;
    resourceId: string;
    pestilloState: PestilloState;
    allowedOperations: CapabilityOperation[];
    validFrom?: string;
    validUntil?: string;
    metadata?: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
    createdBy: string;
  } {
    return {
      id: this.props.id,
      userId: this.props.userId,
      resourceId: this.props.resourceId,
      pestilloState: this.props.pestilloState,
      allowedOperations: [...this.props.allowedOperations],
      validFrom: this.props.validFrom?.toISOString(),
      validUntil: this.props.validUntil?.toISOString(),
      metadata: this.props.metadata ? JSON.parse(JSON.stringify(this.props.metadata)) : undefined,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
      createdBy: this.props.createdBy,
    };
  }

  toSafeObject(): {
    id: string;
    userId: string;
    resourceId: string;
    pestilloState: PestilloState;
    allowedOperations: CapabilityOperation[];
    validFrom?: string;
    validUntil?: string;
    isCurrentlyValid: boolean;
    effectiveState: PestilloState;
  } {
    const now = new Date();
    return {
      id: this.props.id,
      userId: this.props.userId,
      resourceId: this.props.resourceId,
      pestilloState: this.props.pestilloState,
      allowedOperations: [...this.props.allowedOperations],
      validFrom: this.props.validFrom?.toISOString(),
      validUntil: this.props.validUntil?.toISOString(),
      isCurrentlyValid: this.isCurrentlyValid(now),
      effectiveState: this.getEffectiveState(now),
    };
  }
}