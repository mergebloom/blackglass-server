export interface InitMessage {
  op: "init";
  token: string;
  id: string;
  keyhash: string | null;
  version: number;
  initial: boolean;
  device: string;
  encryption_version: number;
}

export interface PingMessage {
  op: "ping";
}

export interface SizeMessage {
  op: "size";
}

export interface UsernamesMessage {
  op: "usernames";
}

export interface PushMessage {
  op: "push";
  path: string;
  relatedpath: string | null;
  extension: string;
  hash: string;
  ctime: number;
  mtime: number;
  folder: boolean;
  deleted: boolean;
  size?: number;
  pieces?: number;
}

export interface PullMessage {
  op: "pull";
  uid: number;
}

export interface DeletedMessage {
  op: "deleted";
  suppressrenames?: boolean;
}

export interface HistoryMessage {
  op: "history";
  path: string;
  last?: number | null;
}

export interface RestoreMessage {
  op: "restore";
  uid: number;
}

export interface PurgeMessage {
  op: "purge";
}

export type ClientTextMessage =
  | InitMessage
  | PingMessage
  | SizeMessage
  | UsernamesMessage
  | PushMessage
  | PullMessage
  | DeletedMessage
  | HistoryMessage
  | RestoreMessage
  | PurgeMessage
  | { op: string; [key: string]: unknown };

export interface PushNotification {
  op: "push";
  path: string;
  relatedpath: string | null;
  extension: string;
  hash: string;
  ctime: number;
  mtime: number;
  folder: boolean;
  deleted: boolean;
  size: number;
  uid: number;
  device: string;
  user: number;
  ts: number;
}

export interface RevisionItem {
  uid: number;
  ts: number;
  path: string;
  relatedpath: string | null;
  extension: string;
  hash: string;
  ctime: number;
  mtime: number;
  folder: boolean;
  deleted: boolean;
  size: number;
  device: string;
  user: number;
}

export type ServerTextMessage =
  | { res: "ok"; userId: number; perFileMax: number }
  | { res: "err"; msg: string }
  | { op: "pong" }
  | { op: "ready"; version: number }
  | PushNotification
  | { res: "next" }
  | { res: "ok" }
  | {
      res: "ok";
      size: number;
      pieces: number;
      deleted: boolean;
      hash: string;
    }
  | { res: "ok"; size: number; limit: number; vault_size: number }
  | { items: RevisionItem[]; more?: boolean }
  | Record<string, string>
  | { err: string }
  | { res: "err"; msg: string; op?: string };
