import { Tab } from './models';

export interface GroupedTab extends Tab { group: string; }
export interface GroupResult { label: string; tabIds: string[]; }

export function domainGroup(tabs: Tab[]): GroupResult[] {
    const buckets: Record<string, string[]> = {};
    for (const t of tabs) {
        try {
            const u = new URL(t.url);
            const host = u.hostname.split('.').slice(-2).join('.');
            (buckets[host] ||= []).push(t.id);
        } catch {
            (buckets['other'] ||= []).push(t.id);
        }
    }
    return Object.entries(buckets).map(([label, tabIds]) => ({ label, tabIds }));
}

export function purity(expected: Record<string, string[]>, predicted: GroupResult[]): number {
    // Simple purity: sum(max overlap per expected cluster)/total
    const predictedMap: Record<string, Set<string>> = {};
    for (const g of predicted) predictedMap[g.label] = new Set(g.tabIds);
    let total = 0; let correct = 0;
    for (const [_, tabs] of Object.entries(expected)) {
        total += tabs.length;
        let maxOverlap = 0;
        for (const p of Object.values(predictedMap)) {
            let overlap = 0;
            for (const id of tabs) if (p.has(id)) overlap++;
            if (overlap > maxOverlap) maxOverlap = overlap;
        }
        correct += maxOverlap;
    }
    return total ? correct / total : 1;
}
