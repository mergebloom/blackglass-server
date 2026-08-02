export const CONTROL_ROUTES = {
  powChallenge: "/user/pow-challenge",
  signin: "/user/signin",
  signout: "/user/signout",
  userInfo: "/user/info",
  subscriptionList: "/subscription/list",
  vaultRegions: "/vault/regions",
  vaultList: "/vault/list",
  vaultCreate: "/vault/create",
  vaultAccess: "/vault/access",
  vaultRename: "/vault/rename",
  vaultDelete: "/vault/delete",
  vaultShareList: "/vault/share/list",
  vaultShareInvite: "/vault/share/invite",
  vaultShareRemove: "/vault/share/remove",
} as const;

export interface SigninRequest {
  email: string;
  password: string;
  mfa?: string;
}

export interface TokenRequest {
  token: string;
}

export interface VaultListRequest extends TokenRequest {
  supported_encryption_version: number;
}

export interface VaultCreateRequest extends TokenRequest {
  name: string;
  keyhash: string | null;
  salt?: string | null;
  region: string;
  encryption_version: number;
}

export interface VaultAccessRequest extends TokenRequest {
  vault_uid: string;
  keyhash: string | null;
  host: string;
  encryption_version: number;
}

export interface RemoteVault {
  id: string;
  name: string;
  keyhash: string | null;
  salt: string | null;
  host: string;
  region: string;
  encryption_version: number;
  size: number;
  created: number;
  password?: string;
}

export interface SharedRemoteVault extends RemoteVault {
  share_uid: number;
}

export interface VaultListResponse {
  vaults: RemoteVault[];
  shared: SharedRemoteVault[];
  limit: number;
}

export interface VaultShareListRequest extends TokenRequest {
  vault_uid: string;
}

export interface VaultShareInviteRequest extends VaultShareListRequest {
  email: string;
}

export interface VaultShareRemoveRequest extends VaultShareListRequest {
  share_uid: number;
}

export interface VaultShareItem {
  uid: number;
  email: string;
  name: string;
  accepted: boolean;
}

export interface VaultShareListResponse {
  shares: VaultShareItem[];
}

export interface VaultRenameRequest extends TokenRequest {
  vault_uid: string;
  name: string;
}

export interface VaultDeleteRequest extends TokenRequest {
  vault_uid: string;
}

export interface ApiError {
  error: string;
}
