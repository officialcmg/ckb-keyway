export type SettlementState = Record<string, unknown> & {
  address?: string;
  channelId?: string;
  commitment?: string;
  finished?: boolean;
};
export function loadSettlementState(text: string | undefined): SettlementState;
export function resumableRun(state: SettlementState): boolean;
export function forAccount(state: SettlementState, address: string): SettlementState;
export function forChannel(state: SettlementState, channelId: string): SettlementState;
