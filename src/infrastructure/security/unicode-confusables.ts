/**
 * Infrastructure layer re-export of confusable data.
 *
 * The canonical source now lives in `domain/utils/confusables-data.ts`
 * (DIP fix — domain owns the data). This file re-exports for any
 * infrastructure consumers that haven't migrated yet.
 */

export {
  type ConfusableMapping,
  UNICODE_CONFUSABLES_MAP,
  CONFUSABLE_LOOKUP,
  SCRIPT_RANGES,
} from "../../domain/utils/confusables-data";
