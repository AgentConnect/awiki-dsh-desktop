/** Durable sent-Bearer records and retention limits. */

/** Maximum validated expires_in, in milliseconds. */
export const MACHINE_TOKEN_MAX_LIFETIME = 86400000
/** Conservative network allowance after the advertised lifetime. */
export const MACHINE_HISTORY_ALLOWANCE = 30000
/** Maximum retained bearer count. */
export const MACHINE_HISTORY_COUNT = 256
/** Maximum serialized private history size. */
export const MACHINE_HISTORY_BYTES = 1048576

/** Secret history record; never part of Remote or public status. */
export interface MachineSentBearer { value: string; receipt: string; source: string; lifetime: number }
