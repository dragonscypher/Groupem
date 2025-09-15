const dataKeys = new Map<string, Buffer>();

export function setDataKey(userId: string, key: Buffer) {
    dataKeys.set(userId, key);
}

export function getDataKey(userId: string): Buffer | undefined {
    return dataKeys.get(userId);
}

export function clearDataKey(userId: string) {
    dataKeys.delete(userId);
}

export function clearAll() { dataKeys.clear(); }
