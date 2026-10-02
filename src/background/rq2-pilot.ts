// RQ2 Pilot — Intention vs Attention in WebAuthn Step-Up
// Feature flag: RQ2_PILOT=true at build time

export type RQ2Condition = 'baseline' | 'contextual';

export interface RQ2PilotState {
  enabled: boolean;
  condition: 'baseline' | 'contextual';
  trial: number;
  sequence: ('baseline' | 'contextual')[];
  participantId: string;
  trialData: RQ2TrialData[];
}

export interface RQ2TrialData {
  trial: number;
  condition: 'baseline' | 'contextual';
  operation: string;
  resource: string;
  userId: string;
  challengeId: string;
  promptVisibleTs: number;
  gestureStartTs?: number;
  approveSentTs?: number;
  errorTs?: number;
  errorDetail?: string;
  selfReportConsciousness?: 1 | 2 | 3 | 4 | 5;
  isDistractor: boolean;
  injectedOperation?: string;
  injectedResource?: string;
}

const STORAGE_KEY = 'rq2_pilot_state';

/**
 * Initialize RQ2 pilot state in session storage.
 * Called once per browser session when the extension loads.
 */
export async function initRQ2Pilot(): Promise<void> {
  if (!isRQ2PilotEnabled()) {
    return;
  }

  const existing = await getRQ2State();
  if (existing) {
    return; // Already initialized
  }

  const participantId = generateParticipantId();
  const sequence = generateCounterbalancedSequence();
  const condition = sequence[0];

  const state: RQ2PilotState = {
    enabled: true,
    condition,
    trial: 0,
    sequence,
    participantId,
    trialData: [],
  };

  await saveRQ2State(state);
  console.log('[RQ2 Pilot] Initialized:', { participantId, sequence });
}

/**
 * Get current pilot state from session storage.
 */
export async function getRQ2State(): Promise<RQ2PilotState | null> {
  try {
    const result = await chrome.storage.session.get(STORAGE_KEY);
    const state = result[STORAGE_KEY];
    return (state as RQ2PilotState) || null;
  } catch {
    return null;
  }
}

/**
 * Save pilot state to session storage.
 */
async function saveRQ2State(state: RQ2PilotState): Promise<void> {
  await chrome.storage.session.set({ [STORAGE_KEY]: state });
}

/**
 * Check if RQ2 pilot is enabled via build-time flag.
 */
function isRQ2PilotEnabled(): boolean {
  // At build time, this is replaced by the build script
  // For development, we can also check a localStorage flag
  if (typeof process !== 'undefined' && process.env?.RQ2_PILOT === 'true') {
    return true;
  }
  // Fallback for manual testing
  try {
    return localStorage.getItem('RQ2_PILOT') === 'true';
  } catch {
    return false;
  }
}

/**
 * Generate a random participant ID (P01, P02, etc.)
 */
function generateParticipantId(): string {
  const existing = getLocalParticipantCount();
  const next = existing + 1;
  setLocalParticipantCount(next);
  return `P${next.toString().padStart(2, '0')}`;
}

function getLocalParticipantCount(): number {
  try {
    return parseInt(localStorage.getItem('rq2_participant_count') || '0', 10);
  } catch {
    return 0;
  }
}

function setLocalParticipantCount(count: number): void {
  try {
    localStorage.setItem('rq2_participant_count', count.toString());
  } catch {
    // Ignore
  }
}

/**
 * Generate a counterbalanced sequence: ABBA or BAAB
 */
function generateCounterbalancedSequence(): ('baseline' | 'contextual')[] {
  const isABBA = Math.random() < 0.5;
  return isABBA
    ? ['baseline', 'baseline', 'contextual', 'contextual']
    : ['contextual', 'contextual', 'baseline', 'baseline'];
}

/**
 * Advance to the next trial condition.
 * Returns the new condition, or null if pilot is complete.
 */
export async function advanceRQ2Trial(): Promise<'baseline' | 'contextual' | null> {
  const state = await getRQ2State();
  if (!state || !state.enabled) {
    return null;
  }

  state.trial += 1;

  if (state.trial >= state.sequence.length) {
    // Pilot complete
    state.enabled = false;
    await saveRQ2State(state);
    return null;
  }

  state.condition = state.sequence[state.trial];
  await saveRQ2State(state);
  return state.condition;
}

/**
 * Record the start of a trial (prompt shown to user).
 */
export async function recordPromptVisible(
  challengeId: string,
  operation: string,
  resource: string,
  userId: string,
  isDistractor: boolean = false,
  injectedOperation?: string,
  injectedResource?: string
): Promise<void> {
  const state = await getRQ2State();
  if (!state || !state.enabled) return;

  const trialData: RQ2TrialData = {
    trial: state.trial,
    condition: state.condition,
    operation,
    resource,
    userId,
    challengeId,
    promptVisibleTs: performance.now(),
    isDistractor,
    injectedOperation,
    injectedResource,
  };

  state.trialData.push(trialData);
  await saveRQ2State(state);
}

/**
 * Record when user starts the gesture (touch/click on authenticator).
 */
export async function recordGestureStart(): Promise<void> {
  const state = await getRQ2State();
  if (!state || !state.enabled) return;

  const currentTrial = state.trialData[state.trialData.length - 1];
  if (currentTrial && !currentTrial.gestureStartTs) {
    currentTrial.gestureStartTs = performance.now();
    await saveRQ2State(state);
  }
}

/**
 * Record when the approval is sent to Plus.
 */
export async function recordApproveSent(): Promise<void> {
  const state = await getRQ2State();
  if (!state || !state.enabled) return;

  const currentTrial = state.trialData[state.trialData.length - 1];
  if (currentTrial && !currentTrial.approveSentTs) {
    currentTrial.approveSentTs = performance.now();
    await saveRQ2State(state);
  }
}

/**
 * Record an error during the trial.
 */
export async function recordError(errorDetail: string): Promise<void> {
  const state = await getRQ2State();
  if (!state || !state.enabled) return;

  const currentTrial = state.trialData[state.trialData.length - 1];
  if (currentTrial && !currentTrial.errorTs) {
    currentTrial.errorTs = performance.now();
    currentTrial.errorDetail = errorDetail;
    await saveRQ2State(state);
  }
}

/**
 * Record the self-report consciousness rating (1-5).
 */
export async function recordSelfReport(rating: 1 | 2 | 3 | 4 | 5): Promise<void> {
  const state = await getRQ2State();
  if (!state || !state.enabled) return;

  const currentTrial = state.trialData[state.trialData.length - 1];
  if (currentTrial) {
    currentTrial.selfReportConsciousness = rating;
    await saveRQ2State(state);
  }
}

/**
 * Export all collected trial data for analysis.
 * Returns JSON-serializable data.
 */
export async function exportRQ2Data(): Promise<RQ2PilotState | null> {
  return getRQ2State();
}

/**
 * Clear all pilot data (for testing/reset).
 */
export async function clearRQ2Data(): Promise<void> {
  await chrome.storage.session.remove(STORAGE_KEY);
  try {
    localStorage.removeItem('rq2_participant_count');
  } catch {
    // Ignore
  }
}

/**
 * Get current condition without advancing trial.
 */
export async function getCurrentCondition(): Promise<'baseline' | 'contextual' | null> {
  const state = await getRQ2State();
  if (!state || !state.enabled) return null;
  return state.condition;
}

/**
 * Check if pilot is currently running.
 */
export async function isPilotRunning(): Promise<boolean> {
  const state = await getRQ2State();
  return state?.enabled === true;
}

/**
 * Get trial number (1-indexed) or 0 if not running.
 */
export async function getCurrentTrialNumber(): Promise<number> {
  const state = await getRQ2State();
  if (!state || !state.enabled) return 0;
  return state.trial + 1; // 1-indexed for display
}